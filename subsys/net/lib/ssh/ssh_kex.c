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

#define KEXINIT_COOKIE_SIZE 16

static int gen_all_keys(struct ssh_transport *transport);
static int gen_key(struct ssh_transport *transport, char c, uint8_t *buf, size_t len);

///* Can be used as a simple lookup table (LUT) for converting strings <-> enums */
//struct ssh_string_lut {
//	int type;
//	struct ssh_string string;
//};
//static const struct ssh_string_lut supported_kex_algs[] = {
//	{ SSH_KEX_ALG_CURVE25519_SHA256, SSH_STRING_LITERAL("curve25519-sha256") },
//};

// Note: The order of the strings is important
static const struct ssh_string supported_kex_algs[] = {
	[SSH_KEX_ALG_CURVE25519_SHA256] = SSH_STRING_LITERAL("curve25519-sha256"),
	// SSH_STRING_LITERAL("curve25519-sha256@libssh.org"),
};
static const struct ssh_string supported_server_host_key_algs[] = {
	// SSH_STRING_LITERAL("ssh-ed25519"),
#ifdef CONFIG_SSH_HOST_KEY_ALG_RSA_SHA2_256
	[SSH_HOST_KEY_ALG_RSA_SHA2_256] = SSH_STRING_LITERAL("rsa-sha2-256"),
#endif
#ifdef CONFIG_SSH_HOST_KEY_ALG_RSA_SHA2_512
	[SSH_HOST_KEY_ALG_RSA_SHA2_512] = SSH_STRING_LITERAL("rsa-sha2-512"),
#endif
};
static const struct ssh_string supported_encryption_algs[] = {
	// SSH_STRING_LITERAL("chacha20-poly1305@openssh.com"),
	[SSH_ENCRYPTION_ALG_AES128_CTR] = SSH_STRING_LITERAL("aes128-ctr"),
};
static const struct ssh_string supported_mac_algs[] = {
	[SSH_MAC_ALG_HMAC_SHA2_256] = SSH_STRING_LITERAL("hmac-sha2-256"),
};
static const struct ssh_string supported_compression_algs[] = {
	[SSH_COMPRESSION_ALG_NONE] = SSH_STRING_LITERAL("none"),
};
static const struct ssh_string supported_languages[] = {
	SSH_STRING_LITERAL(""),
};
BUILD_ASSERT(ARRAY_SIZE(supported_kex_algs) > 0);
BUILD_ASSERT(ARRAY_SIZE(supported_server_host_key_algs) > 0);
BUILD_ASSERT(ARRAY_SIZE(supported_encryption_algs) > 0);
BUILD_ASSERT(ARRAY_SIZE(supported_mac_algs) > 0);
BUILD_ASSERT(ARRAY_SIZE(supported_compression_algs) > 0);
BUILD_ASSERT(ARRAY_SIZE(supported_languages) > 0);

int ssh_kex_send_kexinit(struct ssh_transport *transport)
{
	int res;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);
	const bool first_kex_pkt_follows = false;
	const uint32_t reserved = 0;

	// Add "ext-info-c" to client kex algs to enable RFC8308 extensions
	// (server "ext-info-s" does not appear to be needed).
	struct ssh_string kex_algs[ARRAY_SIZE(supported_kex_algs) + 1];
	uint32_t num_kex_algs = 0;
	for (; num_kex_algs < ARRAY_SIZE(supported_kex_algs); num_kex_algs++) {
		kex_algs[num_kex_algs] = supported_kex_algs[num_kex_algs];
	}
	if (IS_ENABLED(CONFIG_SSH_CLIENT) && !transport->server) {
		kex_algs[num_kex_algs++] = (struct ssh_string)SSH_STRING_LITERAL("ext-info-c");
	}

	// Header / Message ID / Cookie / Kex algorithms / Server host key algorithms
	// Encryption algorithms client to server / Encryption algorithms server to client
	// MAC algorithms client to server / MAC algorithms server to client
	// Compression algorithms client to server / Compression algorithms server to client
	// Languages client to server / Languages server to client
	// First kex packet follows / Reserved for future extension
	if (!ssh_payload_skip_bytes(&payload, SSH_PKT_MSG_ID_OFFSET) ||
	    !ssh_payload_write_byte(&payload, SSH_MSG_KEXINIT) ||
	    !ssh_payload_write_csrand(&payload, KEXINIT_COOKIE_SIZE) ||
	    !ssh_payload_write_name_list(&payload, kex_algs, num_kex_algs) ||
	    !ssh_payload_write_name_list(&payload, supported_server_host_key_algs, ARRAY_SIZE(supported_server_host_key_algs)) ||
	    !ssh_payload_write_name_list(&payload, supported_encryption_algs, ARRAY_SIZE(supported_encryption_algs)) ||
	    !ssh_payload_write_name_list(&payload, supported_encryption_algs, ARRAY_SIZE(supported_encryption_algs)) ||
	    !ssh_payload_write_name_list(&payload, supported_mac_algs, ARRAY_SIZE(supported_mac_algs)) ||
	    !ssh_payload_write_name_list(&payload, supported_mac_algs, ARRAY_SIZE(supported_mac_algs)) ||
	    !ssh_payload_write_name_list(&payload, supported_compression_algs, ARRAY_SIZE(supported_compression_algs)) ||
	    !ssh_payload_write_name_list(&payload, supported_compression_algs, ARRAY_SIZE(supported_compression_algs)) ||
	    !ssh_payload_write_name_list(&payload, supported_languages, ARRAY_SIZE(supported_languages)) ||
	    !ssh_payload_write_name_list(&payload, supported_languages, ARRAY_SIZE(supported_languages)) ||
	    !ssh_payload_write_bool(&payload, first_kex_pkt_follows) ||
	    !ssh_payload_write_u32(&payload, reserved)) {
		return -ENOBUFS;
	}

	// Save local kexinit payload for KEX hash
	// ssh_transport_send_packet encrypts in-place, so we need to make a copy here.
	struct ssh_string **local_kexinit = transport->server ? &transport->server_kexinit : &transport->client_kexinit;
	*local_kexinit = ssh_payload_string_alloc(
		&transport->kex_heap, &payload.data[SSH_PKT_MSG_ID_OFFSET],
		payload.len - SSH_PKT_MSG_ID_OFFSET);
	if (*local_kexinit == NULL) {
		return -ENOMEM;
	}

	res = ssh_transport_send_packet(transport, &payload);
	if (res < 0) {
		LOG_WRN("Failed to send KEXINIT %d", res);
		return res;
	}

	transport->kexinit_sent = true;

	return res;
}

int ssh_kex_send_newkeys(struct ssh_transport *transport)
{
	int res;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);

	if (!ssh_payload_skip_bytes(&payload, SSH_PKT_MSG_ID_OFFSET) ||
	    !ssh_payload_write_byte(&payload, SSH_MSG_NEWKEYS)) {
		return -ENOBUFS;
	}

	res = ssh_transport_send_packet(transport, &payload);
	if (res < 0) {
		LOG_WRN("Failed to send NEWKEYS %d", res);
	}
	return res;
}

static int kex_name_list_find_first(bool server, const struct ssh_string *lut, int lut_len,
				    struct ssh_payload *name_list, struct ssh_string *name_out)
{
	/* We want the fist item in the clients name list that matches a name
	 * in the servers name list. This changes the order of how we iterate
	 * the name list vs look up table depending on if we are a server or client.
	 */
	if (IS_ENABLED(CONFIG_SSH_SERVER) && server) {
		while (ssh_payload_name_list_iter(name_list, name_out)) {
			for (int i = 0; i < lut_len; i++) {
				if (ssh_strings_equal(&lut[i], name_out)) {
					return i;
				}
			}
		}
	} else if (IS_ENABLED(CONFIG_SSH_CLIENT)) {
		for (int i = 0; i < lut_len; i++) {
			struct ssh_payload name_list_copy = *name_list;
			while (ssh_payload_name_list_iter(&name_list_copy, name_out)) {
				if (ssh_strings_equal(&lut[i], name_out)) {
					*name_list = name_list_copy;
					return i;
				}
			}
		}
	}

	return -ENOTSUP;
}

int ssh_kex_process_kexinit(struct ssh_transport *transport, struct ssh_payload *rx_pkt)
{
	int res;
	struct ssh_payload name_list;
	struct ssh_string name;

	LOG_INF("KEXINIT");
	if (transport->kexinit_received) {
		return -1;
	}

	// Skip cookie
	if (!ssh_payload_skip_bytes(rx_pkt, KEXINIT_COOKIE_SIZE)) {
		LOG_ERR("Length error");
		return -1;
	}

	// Kex algorithm
	if (!ssh_payload_read_name_list(rx_pkt, &name_list)) {
		LOG_ERR("Length error");
		return -1;
	}
	LOG_DBG("Remote %s algs: %.*s", "kex", name_list.size, name_list.data);
	if (IS_ENABLED(CONFIG_SSH_SERVER) && transport->server &&
	    transport->auths_allowed_mask & BIT(SSH_AUTH_PUBKEY)) {
		// Check if the client supports RFC8308 extensions.
		// Required for the "server-sig-algs" extension to
		// avoid using SHA-1 signatures in pubkey auth.
		struct ssh_payload name_list_copy = name_list;
		static const struct ssh_string ext_info_c = SSH_STRING_LITERAL("ext-info-c");
		res = kex_name_list_find_first(
			transport->server, &ext_info_c, 1,
			&name_list_copy, &name);
		if (res < 0) {
			LOG_WRN("Client does not support RFC8308 extensions, disabling pubkey auth");
			transport->auths_allowed_mask &= ~BIT(SSH_AUTH_PUBKEY);
		}
	}
	res = kex_name_list_find_first(
		transport->server, supported_kex_algs,
		ARRAY_SIZE(supported_kex_algs), &name_list, &name);
	if (res < 0) {
		LOG_WRN("No suitable %s alg", "kex");
		return res;
	}
	transport->algs.kex = res;
	LOG_DBG("Using %s alg %.*s", "kex", name.len, name.data);

	// Server host key algorithm
	if (!ssh_payload_read_name_list(rx_pkt, &name_list)) {
		LOG_ERR("Length error");
		return -1;
	}
	LOG_DBG("Remote %s algs: %.*s", "host key", name_list.size, name_list.data);
	res = kex_name_list_find_first(
		transport->server, supported_server_host_key_algs,
		ARRAY_SIZE(supported_server_host_key_algs), &name_list, &name);
	if (res < 0) {
		LOG_WRN("No suitable %s alg", "host key");
		return res;
	}
	transport->algs.server_host_key = res;
	LOG_DBG("Using %s alg %.*s", "host key", name.len, name.data);

	// Encryption algorithm (client to server)
	if (!ssh_payload_read_name_list(rx_pkt, &name_list)) {
		LOG_ERR("Length error");
		return -1;
	}
	LOG_DBG("Remote %s algs: %.*s", "encryption (C2S)", name_list.size, name_list.data);
	res = kex_name_list_find_first(
		transport->server, supported_encryption_algs,
		ARRAY_SIZE(supported_encryption_algs), &name_list, &name);
	if (res < 0) {
		LOG_WRN("No suitable %s alg", "encryption (C2S)");
		return res;
	}
	transport->algs.encryption_c2s = res;
	LOG_DBG("Using %s alg %.*s", "encryption (C2S)", name.len, name.data);

	// Encryption algorithm (server to client)
	if (!ssh_payload_read_name_list(rx_pkt, &name_list)) {
		LOG_ERR("Length error");
		return -1;
	}
	LOG_DBG("Remote %s algs: %.*s", "encryption (S2C)", name_list.size, name_list.data);
	res = kex_name_list_find_first(
		transport->server, supported_encryption_algs,
		ARRAY_SIZE(supported_encryption_algs), &name_list, &name);
	if (res < 0) {
		LOG_WRN("No suitable %s alg", "encryption (S2C)");
		return res;
	}
	transport->algs.encryption_s2c = res;
	LOG_DBG("Using %s alg %.*s", "encryption (S2C)", name.len, name.data);

	// MAC algorithm (client to server)
	if (!ssh_payload_read_name_list(rx_pkt, &name_list)) {
		LOG_ERR("Length error");
		return -1;
	}
	LOG_DBG("Remote %s algs: %.*s", "MAC (C2S)", name_list.size, name_list.data);
	res = kex_name_list_find_first(
		transport->server, supported_mac_algs,
		ARRAY_SIZE(supported_mac_algs), &name_list, &name);
	if (res < 0) {
		LOG_WRN("No suitable %s alg", "MAC (C2S)");
		return res;
	}
	transport->algs.mac_c2s = res;
	LOG_DBG("Using %s alg %.*s", "MAC (C2S)", name.len, name.data);

	// MAC algorithm (server to client)
	if (!ssh_payload_read_name_list(rx_pkt, &name_list)) {
		LOG_ERR("Length error");
		return -1;
	}
	LOG_DBG("Remote %s algs: %.*s", "MAC (S2C)", name_list.size, name_list.data);
	res = kex_name_list_find_first(
		transport->server, supported_mac_algs,
		ARRAY_SIZE(supported_mac_algs), &name_list, &name);
	if (res < 0) {
		LOG_WRN("No suitable %s alg", "MAC (S2C)");
		return res;
	}
	transport->algs.mac_s2c = res;
	LOG_DBG("Using %s alg %.*s", "MAC (S2C)", name.len, name.data);

	// Compression algorithm (client to server)
	if (!ssh_payload_read_name_list(rx_pkt, &name_list)) {
		LOG_ERR("Length error");
		return -1;
	}
	LOG_DBG("Remote %s algs: %.*s", "compression (C2S)", name_list.size, name_list.data);
	res = kex_name_list_find_first(
		transport->server, supported_compression_algs,
		ARRAY_SIZE(supported_compression_algs), &name_list, &name);
	if (res < 0) {
		LOG_WRN("No suitable %s alg", "compression (C2S)");
		return res;
	}
	transport->algs.compression_c2s = res;
	LOG_DBG("Using %s alg %.*s", "compression (C2S)", name.len, name.data);

	// Compression algorithm (server to client)
	if (!ssh_payload_read_name_list(rx_pkt, &name_list)) {
		LOG_ERR("Length error");
		return -1;
	}
	LOG_DBG("Remote %s algs: %.*s", "compression (S2C)", name_list.size, name_list.data);
	res = kex_name_list_find_first(
		transport->server, supported_compression_algs,
		ARRAY_SIZE(supported_compression_algs), &name_list, &name);
	if (res < 0) {
		LOG_WRN("No suitable %s alg", "compression (S2C)");
		return res;
	}
	transport->algs.compression_s2c = res;
	LOG_DBG("Using %s alg %.*s", "compression (S2C)", name.len, name.data);

	// Languages (server to client) - Not supported
	if (!ssh_payload_read_name_list(rx_pkt, &name_list)) {
		LOG_ERR("Length error");
		return -1;
	}
	LOG_DBG("Remote %s algs: %.*s", "languages (C2S)", name_list.size, name_list.data);
	// Languages (server to client) - Not supported
	if (!ssh_payload_read_name_list(rx_pkt, &name_list)) {
		LOG_ERR("Length error");
		return -1;
	}
	LOG_DBG("Remote %s algs: %.*s", "languages (S2C)", name_list.size, name_list.data);

	// First kex packet follows (TODO: add support for "first_kex_pkt_follows")
	bool first_kex_pkt_follows;
	if (!ssh_payload_read_bool(rx_pkt, &first_kex_pkt_follows)) {
		LOG_ERR("Length error");
		return -1;
	}
	// Reserved for future extension
	if (!ssh_payload_read_u32(rx_pkt, NULL)) {
		LOG_ERR("Length error");
		return -1;
	}
	if (!ssh_payload_read_complete(rx_pkt)) {
		LOG_ERR("Unexpected extra data");
		return -1;
	}

	// Save remote kexinit payload for KEX hash
	struct ssh_string **remote_kexinit = transport->server ? &transport->client_kexinit : &transport->server_kexinit;
	*remote_kexinit = ssh_payload_string_alloc(
		&transport->kex_heap, &rx_pkt->data[SSH_PKT_MSG_ID_OFFSET],
		rx_pkt->len - SSH_PKT_MSG_ID_OFFSET);
	if (*remote_kexinit == NULL) {
		return -ENOMEM;
	}

	transport->kexinit_received = true;

	if (!transport->kexinit_sent) {
		res = ssh_kex_send_kexinit(transport);
		if (res != 0) {
			return res;
		}
	}

#ifdef CONFIG_SSH_CLIENT
	if (!transport->server) {
		// Generate ephemeral key
		mbedtls_ecdsa_init(&transport->ecdsa_ephemeral_key);
		res = mbedtls_ecdsa_genkey(
			&transport->ecdsa_ephemeral_key, MBEDTLS_ECP_DP_CURVE25519,
			ssh_mbedtls_rand, NULL);
		if (res != 0) {
			LOG_ERR("genkey ed25519 failed: %d", res);
			return -EIO;
		}

		res = ssh_kex_ecdh_send_kex_ecdh_init(transport);
		if (res < 0) {
			return res;
		}
	}
#endif

	return 0;
}

int ssh_kex_process_newkeys(struct ssh_transport *transport, struct ssh_payload *rx_pkt)
{
	int res;

	LOG_INF("NEWKEYS");
	// TODO: if transport->awaiting_newkeys
	if (!transport->kexinit_received || !transport->kexinit_sent || !transport->newkeys_sent) {
		return -1;
	}
	if (!ssh_payload_read_complete(rx_pkt)) {
		LOG_ERR("Unexpected extra data");
		return -1;
	}

	res = gen_all_keys(transport);
	if (res < 0) {
		return res;
	}

	struct ssh_cipher_aes128_ctr *cipher = transport->server ? &transport->tx_cipher : &transport->rx_cipher;
	mbedtls_aes_init(&cipher->aes_crypt);
	res = mbedtls_aes_setkey_enc(&cipher->aes_crypt, transport->encrypt_key_server, sizeof(transport->encrypt_key_server) * 8);
	if (res != 0) {
		LOG_ERR("Cipher error");
		return -1;
	}
	cipher = transport->server ? &transport->rx_cipher : &transport->tx_cipher;
	mbedtls_aes_init(&cipher->aes_crypt);
	res = mbedtls_aes_setkey_enc(&cipher->aes_crypt, transport->encrypt_key_client, sizeof(transport->encrypt_key_client) * 8);
	if (res != 0) {
		LOG_ERR("Cipher error");
		return -1;
	}

	transport->encrypted = true;
	transport->kexinit_sent = false;
	transport->kexinit_received = false;
	transport->newkeys_sent = false;
	transport->kex_expiry = sys_timepoint_calc(K_HOURS(1));
	transport->tx_bytes_since_kex = 0;
	transport->rx_bytes_since_kex = 0;
	// Free/clear everything we no longer need
	mbedtls_ecdsa_free(&transport->ecdsa_ephemeral_key);
	if (transport->client_kexinit != NULL) {
		sys_heap_free(&transport->kex_heap, transport->client_kexinit);
		transport->client_kexinit = NULL;
	}
	if (transport->server_kexinit != NULL) {
		sys_heap_free(&transport->kex_heap, transport->server_kexinit);
		transport->server_kexinit = NULL;
	}
	if (transport->shared_secret != NULL) {
		mbedtls_platform_zeroize((void *)transport->shared_secret->data, transport->shared_secret->len);
		sys_heap_free(&transport->kex_heap, transport->shared_secret);
		transport->shared_secret = NULL;
	}
	if (transport->exchange_hash != NULL) {
		mbedtls_platform_zeroize((void *)transport->exchange_hash->data, transport->exchange_hash->len);
		sys_heap_free(&transport->kex_heap, transport->exchange_hash);
		transport->exchange_hash = NULL;
	}
#ifdef CONFIG_SSH_CLIENT
	if (!transport->server && !transport->authenticated) {
		static const struct ssh_string service_name = SSH_STRING_LITERAL("ssh-userauth");
		res = ssh_transport_send_service_request(transport, &service_name);
		if (res < 0) {
			return res;
		}
	}
#endif
#ifdef CONFIG_SSH_SERVER
	if (transport->server && !transport->authenticated &&
	    transport->auths_allowed_mask & BIT(SSH_AUTH_PUBKEY)) {
		// Send "server-sig-algs" RFC8308 extension to
		// avoid using SHA-1 signatures in pubkey auth
		res = ssh_transport_send_server_sig_algs(transport);
		if (res < 0) {
			return res;
		}
	}
#endif

	return 0;
}

int ssh_kex_process_msg(struct ssh_transport *transport, uint8_t msg_id, struct ssh_payload *rx_pkt)
{
	return ssh_kex_ecdh_process_msg(transport, msg_id, rx_pkt);
}

int ssh_kex_gen_exchange_hash(struct ssh_transport *transport, const struct ssh_string *remote_ephemeral_key, const struct ssh_string *server_host_key)
{
	int res;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);
	uint8_t buf[4];
	mbedtls_sha256_context ctx;
	mbedtls_sha256_init(&ctx);

	// The exchange hash H is computed as the hash of the concatenation of
	// the following.
	//     string   V_C, client's identification string (CR and LF excluded)
	//     string   V_S, server's identification string (CR and LF excluded)
	//     string   I_C, payload of the client's SSH_MSG_KEXINIT
	//     string   I_S, payload of the server's SSH_MSG_KEXINIT
	//     string   K_S, server's public host key
	//     string   Q_C, client's ephemeral public key octet string
	//     string   Q_S, server's ephemeral public key octet string
	//     mpint    K,   shared secret

	// The exchange hash data is quite large, each item is
	// hashed piecemeal to reduce memory usage

	// TODO: Zeroise buffers clear sensitive data from memory

	int is224 = 0;
	if (mbedtls_sha256_starts(&ctx, is224) != 0) {
		res = -EIO;
		goto exit;
	}

	uint8_t hash[10000];
	size_t hash_offset = 0;

	// Client identity
	sys_put_be32(transport->client_identity->len, buf);
	if (mbedtls_sha256_update(&ctx, buf, sizeof(buf)) != 0) {
		res = -EIO;
		goto exit;
	}

	if (mbedtls_sha256_update(&ctx, transport->client_identity->data, transport->client_identity->len) != 0) {
		res = -EIO;
		goto exit;
	}
	memcpy(&hash[hash_offset], buf, sizeof(buf));
	hash_offset += sizeof(buf);
	memcpy(&hash[hash_offset], transport->client_identity->data, transport->client_identity->len);
	hash_offset += transport->client_identity->len;

	// Server identity
	sys_put_be32(transport->server_identity->len, buf);
	if (mbedtls_sha256_update(&ctx, buf, sizeof(buf)) != 0) {
		res = -EIO;
		goto exit;
	}
	if (mbedtls_sha256_update(&ctx, transport->server_identity->data, transport->server_identity->len) != 0) {
		res = -EIO;
		goto exit;
	}
	memcpy(&hash[hash_offset], buf, sizeof(buf));
	hash_offset += sizeof(buf);
	memcpy(&hash[hash_offset], transport->server_identity->data, transport->server_identity->len);
	hash_offset += transport->server_identity->len;

	// Client kexinit payload
	sys_put_be32(transport->client_kexinit->len, buf);
	if (mbedtls_sha256_update(&ctx, buf, sizeof(buf)) != 0) {
		res = -EIO;
		goto exit;
	}
	if (mbedtls_sha256_update(&ctx, transport->client_kexinit->data, transport->client_kexinit->len) != 0) {
		res = -EIO;
		goto exit;
	}
	memcpy(&hash[hash_offset], buf, sizeof(buf));
	hash_offset += sizeof(buf);
	memcpy(&hash[hash_offset], transport->client_kexinit->data, transport->client_kexinit->len);
	hash_offset += transport->client_kexinit->len;

	// Server kexinit payload
	sys_put_be32(transport->server_kexinit->len, buf);
	if (mbedtls_sha256_update(&ctx, buf, sizeof(buf)) != 0) {
		res = -EIO;
		goto exit;
	}
	if (mbedtls_sha256_update(&ctx, transport->server_kexinit->data, transport->server_kexinit->len) != 0) {
		res = -EIO;
		goto exit;
	}
	memcpy(&hash[hash_offset], buf, sizeof(buf));
	hash_offset += sizeof(buf);
	memcpy(&hash[hash_offset], transport->server_kexinit->data, transport->server_kexinit->len);
	hash_offset += transport->server_kexinit->len;

	// Server public host key
	if (transport->server) {
		payload.len = 0;
		res = ssh_host_key_write_pub_key(&payload, transport->host_key_index);
		if (res != 0) {
			goto exit;
		}
	} else {
		payload.len = 0;
		if (!ssh_payload_write_string(&payload, server_host_key)) {
			res = -ENOBUFS;
			goto exit;
		}
	}
	if (mbedtls_sha256_update(&ctx, payload.data, payload.len) != 0) {
		res = -EIO;
		goto exit;
	}

	memcpy(&hash[hash_offset], payload.data, payload.len);
	hash_offset += payload.len;

	// Client then server ephemeral pub key
	for (int i = 0; i < 2; i++) {
		if ((transport->server && i == 0) || (!transport->server && i == 1)) {
			// Remote key, first if we are a server otherwise second
			sys_put_be32(remote_ephemeral_key->len, buf);
			if (mbedtls_sha256_update(&ctx, buf, sizeof(buf)) != 0) {
				res = -EIO;
				goto exit;
			}
			if (mbedtls_sha256_update(&ctx, remote_ephemeral_key->data, remote_ephemeral_key->len) != 0) {
				res = -EIO;
				goto exit;
			}

			memcpy(&hash[hash_offset], buf, sizeof(buf));
			hash_offset += sizeof(buf);
			memcpy(&hash[hash_offset], remote_ephemeral_key->data, remote_ephemeral_key->len);
			hash_offset += remote_ephemeral_key->len;
		} else {
			// Local key, first if we are a client otherwise second
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
			sys_put_be32(pubkey_len, buf);
			if (mbedtls_sha256_update(&ctx, buf, sizeof(buf)) != 0) {
				res = -EIO;
				goto exit;
			}
			if (mbedtls_sha256_update(&ctx, pubkey_buff, pubkey_len) != 0) {
				res = -EIO;
				goto exit;
			}

			memcpy(&hash[hash_offset], buf, sizeof(buf));
			hash_offset += sizeof(buf);
			memcpy(&hash[hash_offset], pubkey_buff, pubkey_len);
			hash_offset += pubkey_len;
		}
	}

	// mpint K, shared secret
	payload.len = 0;
	if (!ssh_payload_write_mpint(&payload, transport->shared_secret->data, transport->shared_secret->len, false)) {
		res = -ENOBUFS;
		goto exit;
	}
	if (mbedtls_sha256_update(&ctx, payload.data, payload.len) != 0) {
		res = -EIO;
		goto exit;
	}

	memcpy(&hash[hash_offset], payload.data, payload.len);
	hash_offset += payload.len;

	LOG_HEXDUMP_DBG(hash, hash_offset, "hash");

	transport->exchange_hash = ssh_payload_string_alloc(&transport->kex_heap, NULL, 32);
	if (transport->exchange_hash == NULL) {
		res = -ENOMEM;
		goto exit;
	}
	if (mbedtls_sha256_finish(&ctx, (void *)transport->exchange_hash->data) != 0) {
		res = -EIO;
		goto exit;
	}

	LOG_HEXDUMP_DBG(transport->exchange_hash->data, transport->exchange_hash->len, "exchange_hash");

exit:
	//mbedtls_platform_zeroize(payload.data, payload.size);
	mbedtls_sha256_free(&ctx);

	return res;
}

static int gen_all_keys(struct ssh_transport *transport)
{
	//   o  Initial IV client to server: HASH(K || H || "A" || session_id)
	//      (Here K is encoded as mpint and "A" as byte and session_id as raw
	//      data.  "A" means the single character A, ASCII 65).
	//   o  Initial IV server to client: HASH(K || H || "B" || session_id)
	//   o  Encryption key client to server: HASH(K || H || "C" || session_id)
	//   o  Encryption key server to client: HASH(K || H || "D" || session_id)
	//   o  Integrity key client to server: HASH(K || H || "E" || session_id)
	//   o  Integrity key server to client: HASH(K || H || "F" || session_id)
	struct {
		char c;
		uint8_t *buf;
		size_t len;
	} keygen[] = {
		{.c = 'A', .buf = transport->iv_client, .len = sizeof(transport->iv_client)},
		{.c = 'B', .buf = transport->iv_server, .len = sizeof(transport->iv_server)},
		{.c = 'C', .buf = transport->encrypt_key_client, .len = sizeof(transport->encrypt_key_client)},
		{.c = 'D', .buf = transport->encrypt_key_server, .len = sizeof(transport->encrypt_key_server)},
		{.c = 'E', .buf = transport->integ_key_client, .len = sizeof(transport->integ_key_client)},
		{.c = 'F', .buf = transport->integ_key_server, .len = sizeof(transport->integ_key_server)},
	};

	for (unsigned i = 0; i < ARRAY_SIZE(keygen); i++) {
		int res = gen_key(transport, keygen[i].c, keygen[i].buf, keygen[i].len);
		if (res != 0) {
			LOG_ERR("Failed to generate keys");
			return res;
		}
		LOG_DBG("Key %d (%c)", i, keygen[i].c);
		LOG_HEXDUMP_DBG(keygen[i].buf, keygen[i].len, "key");
	}

	return 0;
}

static int gen_key(struct ssh_transport *transport, char c, uint8_t *buf, size_t len)
{
	int res = 0;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);
	uint8_t hash[32];
	mbedtls_sha256_context ctx;
	mbedtls_sha256_init(&ctx);

	// mpint K, shared secret
	if (!ssh_payload_write_mpint(&payload, transport->shared_secret->data, transport->shared_secret->len, false)) {
		res = -ENOBUFS;
		goto exit;
	}

	size_t offset = 0;
	while (offset < len) {
		int is224 = 0;
		if (mbedtls_sha256_starts(&ctx, is224) != 0) {
			res = -EIO;
			goto exit;
		}

		if (mbedtls_sha256_update(&ctx, payload.data, payload.len) != 0) {
			res = -EIO;
			goto exit;
		}
		if (mbedtls_sha256_update(&ctx, transport->exchange_hash->data, transport->exchange_hash->len) != 0) {
			res = -EIO;
			goto exit;
		}
		if (offset == 0) {
			if (mbedtls_sha256_update(&ctx, &c, 1) != 0) {
				res = -EIO;
				goto exit;
			}
			if (mbedtls_sha256_update(&ctx, transport->session_id->data, transport->session_id->len) != 0) {
				res = -EIO;
				goto exit;
			}
		} else {
			if (mbedtls_sha256_update(&ctx, buf, offset) != 0) {
				res = -EIO;
				goto exit;
			}
		}
		if (mbedtls_sha256_finish(&ctx, hash) != 0) {
			res = -EIO;
			goto exit;
		}
		size_t copy_len = MIN(len - offset, sizeof(hash));
		memcpy(&buf[offset], hash, copy_len);
		offset += copy_len;
	}

exit:
	mbedtls_sha256_free(&ctx);

	return res;
}
