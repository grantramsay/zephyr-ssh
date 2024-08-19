/*
* Copyright (c) 2024 Grant Ramsay <grant.ramsay@hotmail.com>
*
* SPDX-License-Identifier: Apache-2.0
*/
#include "ssh_kex.h"

#include "ssh_host_key.h"

#include CONFIG_MBEDTLS_CFG_FILE
#include "mbedtls/platform.h"

#include <mbedtls/ecdsa.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/error.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(ssh, CONFIG_NET_SSH_LOG_LEVEL);

#ifdef CONFIG_SSH_SERVER
static int send_kex_ecdh_reply(struct ssh_transport *transport);
#endif
static int gen_shared_secret(struct ssh_transport *transport, const struct ssh_string *remote_ephemeral_key);

#ifdef CONFIG_SSH_CLIENT
int ssh_kex_ecdh_send_kex_ecdh_init(struct ssh_transport *transport)
{
	int res;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);

	// Header / Message ID
	if (!ssh_payload_skip_bytes(&payload, SSH_PKT_MSG_ID_OFFSET) ||
	    !ssh_payload_write_byte(&payload, SSH_MSG_KEX_ECDH_INIT)) {
		return -ENOBUFS;
	}

	// Ephemeral key
	uint8_t pubkey_buff[32];
	size_t pubkey_len;
	res = mbedtls_ecp_write_public_key(
		&transport->ecdsa_ephemeral_key, MBEDTLS_ECP_PF_UNCOMPRESSED, &pubkey_len,
		pubkey_buff, sizeof(pubkey_buff));
	if (res != 0) {
		LOG_ERR("Failed to write pubkey: %d", res);
		return -EIO;
	}
	struct ssh_string pubkey_str = {
		.len = pubkey_len,
		.data = pubkey_buff
	};
	if (!ssh_payload_write_string(&payload, &pubkey_str)) {
		return -ENOBUFS;
	}

	res = ssh_transport_send_packet(transport, &payload);
	if (res < 0) {
		LOG_WRN("Failed to send KEX_ECDH_REPLY %d", res);
	}
	return res;
}
#endif

int ssh_kex_ecdh_process_msg(struct ssh_transport *transport, uint8_t msg_id, struct ssh_payload *rx_pkt)
{
	int res = -1;

	switch (msg_id) {
#ifdef CONFIG_SSH_SERVER
	case SSH_MSG_KEX_ECDH_INIT: {
		LOG_INF("KEX_ECDH_INIT");
		// Server only
		if (!transport->server || !transport->kexinit_received || transport->newkeys_sent) {
			return -1;
		}
		struct ssh_string client_ephemeral_key;
		if (!ssh_payload_read_string(rx_pkt, &client_ephemeral_key) ||
		    !ssh_payload_read_complete(rx_pkt)) {
			LOG_ERR("Length error");
			return -1;
		}

		// Generate ephemeral key
		mbedtls_ecdsa_init(&transport->ecdsa_ephemeral_key);
		res = mbedtls_ecdsa_genkey(
			&transport->ecdsa_ephemeral_key, MBEDTLS_ECP_DP_CURVE25519,
			ssh_mbedtls_rand, NULL);
		if (res != 0) {
			LOG_ERR("genkey ed25519 failed: %d", res);
			return -EIO;
		}

		res = gen_shared_secret(transport, &client_ephemeral_key);
		if (res != 0) {
			LOG_ERR("gen shared secret failed: %d", res);
			return res;
		}

		// Generate exchange hash
		res = ssh_kex_gen_exchange_hash(transport, &client_ephemeral_key, NULL);
		if (res != 0) {
			LOG_ERR("gen exchange hash failed: %d", res);
			return res;
		}

		// Only set session ID on first kex
		if (transport->session_id == NULL) {
			transport->session_id = ssh_payload_string_alloc(
				&transport->kex_heap, transport->exchange_hash->data, transport->exchange_hash->len);
			if (transport->session_id == NULL) {
				return -ENOMEM;
			}
		}

		res = send_kex_ecdh_reply(transport);
		if (res < 0) {
			return res;
		}

		res = ssh_kex_send_newkeys(transport);
		if (res < 0) {
			return res;
		}

		transport->newkeys_sent = true;
		break;
	}
#endif
#ifdef CONFIG_SSH_CLIENT
	case SSH_MSG_KEX_ECDH_REPLY: {
		LOG_INF("KEX_ECDH_REPLY");
		//      byte     SSH_MSG_KEX_ECDH_REPLY
		//      string   K_S, server's public host key
		//      string   Q_S, server's ephemeral public key octet string
		//      string   the signature on the exchange hash
		// Client only
		if (transport->server || !transport->kexinit_received || transport->newkeys_sent) {
			return -1;
		}
		struct ssh_string server_host_key, server_ephemeral_key, exchange_hash_signature;
		if (!ssh_payload_read_string(rx_pkt, &server_host_key) ||
		    !ssh_payload_read_string(rx_pkt, &server_ephemeral_key) ||
		    !ssh_payload_read_string(rx_pkt, &exchange_hash_signature) ||
		    !ssh_payload_read_complete(rx_pkt)) {
			LOG_ERR("Length error");
			return -1;
		}

		res = gen_shared_secret(transport, &server_ephemeral_key);
		if (res != 0) {
			LOG_ERR("gen shared secret failed: %d", res);
			return res;
		}

		// Generate exchange hash
		res = ssh_kex_gen_exchange_hash(transport, &server_ephemeral_key, &server_host_key);
		if (res != 0) {
			LOG_ERR("gen exchange hash failed: %d", res);
			return res;
		}

		// TODO: Validate the servers host key (known hosts)

		// Verify the servers signature on the exchange hash
		res = ssh_host_key_verify_signature(
			&transport->algs.server_host_key, &server_host_key, &exchange_hash_signature,
			transport->exchange_hash->data, transport->exchange_hash->len);
		if (res < 0) {
			LOG_WRN("Failed to verify signature", res);
			return res;
		}

		// Only set session ID on first kex
		if (transport->session_id == NULL) {
			transport->session_id = ssh_payload_string_alloc(
				&transport->kex_heap, transport->exchange_hash->data, transport->exchange_hash->len);
			if (transport->session_id == NULL) {
				return -ENOMEM;
			}
		}

		res = ssh_kex_send_newkeys(transport);
		if (res < 0) {
			return res;
		}

		transport->newkeys_sent = true;
		break;
	}
#endif
	default:
		break;
	}

	return res;
}

#ifdef CONFIG_SSH_SERVER
static int send_kex_ecdh_reply(struct ssh_transport *transport)
{
	int res;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);

	// Header / Message ID
	if (!ssh_payload_skip_bytes(&payload, SSH_PKT_MSG_ID_OFFSET) ||
	    !ssh_payload_write_byte(&payload, SSH_MSG_KEX_ECDH_REPLY)) {
		res = -ENOBUFS;
		goto exit;
	}

	// Host key
	res = ssh_host_key_write_pub_key(&payload, transport->host_key_index);
	if (res != 0) {
		goto exit;
	}

	// Ephemeral key
	uint8_t pubkey_buff[32];
	size_t pubkey_len;
	res = mbedtls_ecp_write_public_key(
		&transport->ecdsa_ephemeral_key, MBEDTLS_ECP_PF_UNCOMPRESSED, &pubkey_len,
		pubkey_buff, sizeof(pubkey_buff));
	if (res != 0) {
		LOG_ERR("Failed to write pubkey: %d", res);
		res = -EIO;
		goto exit;
	}
	struct ssh_string pubkey_str = {
		.len = pubkey_len,
		.data = pubkey_buff
	};
	if (!ssh_payload_write_string(&payload, &pubkey_str)) {
		res = -ENOBUFS;
		goto exit;
	}

	// Signature on the exchange hash
	res = ssh_host_key_write_signature(
		&payload, transport->host_key_index, transport->algs.server_host_key,
		transport->exchange_hash->data, transport->exchange_hash->len);
	if (res < 0) {
		LOG_WRN("Failed to write signature", res);
		goto exit;
	}

	res = ssh_transport_send_packet(transport, &payload);
	if (res < 0) {
		LOG_WRN("Failed to send KEX_ECDH_REPLY %d", res);
	}

exit:
	return res;
}
#endif

static int gen_shared_secret(struct ssh_transport *transport, const struct ssh_string *remote_ephemeral_key)
{
	int res;
	mbedtls_mpi priv_key;
	mbedtls_ecp_group grp;
	mbedtls_ecp_point remote_pub;
	mbedtls_mpi shared_secret;

	mbedtls_mpi_init(&priv_key);
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&remote_pub);
	mbedtls_mpi_init(&shared_secret);

	// Get the private key
	// TODO: ecdsa_ephemeral_key is not correct type...
	res = mbedtls_ecp_export(&transport->ecdsa_ephemeral_key, NULL, &priv_key, NULL);
	if (res != 0) {
		res = -EIO;
		goto exit;
	}

	res = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
	if (res != 0) {
		res = -EIO;
		goto exit;
	}

	// Get the remote pub key
	LOG_HEXDUMP_DBG(remote_ephemeral_key->data, remote_ephemeral_key->len, "remote_pub");
	res = mbedtls_ecp_point_read_binary(&grp, &remote_pub, remote_ephemeral_key->data, remote_ephemeral_key->len);
	if (res != 0) {
		res = -EIO;
		goto exit;
	}

	res = mbedtls_ecdh_compute_shared(
		&grp, &shared_secret, &remote_pub,
		&priv_key, ssh_mbedtls_rand, NULL);
	if (res != 0) {
		LOG_ERR("ecdh compute shared failed: %d", res);
		res = -EIO;
		goto exit;
	}
	size_t shared_secret_size = mbedtls_mpi_size(&shared_secret);
	transport->shared_secret = ssh_payload_string_alloc(&transport->kex_heap, NULL, shared_secret_size);
	if (transport->shared_secret == NULL) {
		res = -ENOMEM;
		goto exit;
	}
	res = mbedtls_mpi_write_binary_le(&shared_secret, (void *)transport->shared_secret->data, transport->shared_secret->len);
	if (res != 0) {
		res = -EIO;
		goto exit;
	}
	LOG_DBG("shared_secret %zu %d", transport->shared_secret->len, res);
	LOG_HEXDUMP_DBG(transport->shared_secret->data, transport->shared_secret->len, "shared_secret");

exit:
	mbedtls_mpi_free(&shared_secret);
	mbedtls_ecp_point_free(&remote_pub);
	mbedtls_ecp_group_free(&grp);
	mbedtls_mpi_free(&priv_key);

	return res;
}
