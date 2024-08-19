/*
* Copyright (c) 2024 Grant Ramsay <grant.ramsay@hotmail.com>
*
* SPDX-License-Identifier: Apache-2.0
*/
#include "ssh_transport.h"

#include "ssh_kex.h"
#include "ssh_auth.h"
#include "ssh_connection.h"

#include <zephyr/random/random.h>
#include <zephyr/zvfs/eventfd.h>

#include CONFIG_MBEDTLS_CFG_FILE
#include "mbedtls/platform.h"

#include <mbedtls/constant_time.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(ssh, CONFIG_NET_SSH_LOG_LEVEL);

#ifdef CONFIG_SSH_IDENTITY_OVERRIDE_ENABLE
#define ZEPHYR_SSH_IDENTITY CONFIG_SSH_IDENTITY_OVERRIDE
#else
#define ZEPHYR_SSH_IDENTITY ("SSH-2.0-zephyr " ZEPHYR_SSH_VERSION)
#endif

static int update_channels(struct ssh_transport *transport);
static int check_kex_expiry(struct ssh_transport *transport);
static int process_user_requests(struct ssh_transport *transport);
static int process_user_request(struct ssh_transport *transport, const struct ssh_transport_user_request *request);

static int send_identity(struct ssh_transport *transport);
static int process_msg(struct ssh_transport *transport);
static int ssh_transport_process_msg(struct ssh_transport *transport, uint8_t msg_id, struct ssh_payload *rx_pkt);
#ifdef CONFIG_SSH_CLIENT
static int process_server_sig_algs(struct ssh_transport *transport,
				   const struct ssh_string *server_sig_algs_str);
#endif
#ifdef CONFIG_SSH_SERVER
static int send_service_accept(struct ssh_transport *transport, const struct ssh_string *service_name);
#endif
static int mac_calculate(struct ssh_transport *transport, const uint8_t *key, size_t key_len,
			 uint32_t seq_num, const void *data, size_t len, uint8_t *mac_tag_out);
static ssize_t sendall(int sock, const void *buf, size_t len);

static const char zephyr_ssh_identity[] = ZEPHYR_SSH_IDENTITY;

static const struct ssh_string server_sig_algs_str = SSH_STRING_LITERAL("server-sig-algs");

static const struct ssh_string supported_server_sig_algs[] = {
#ifdef CONFIG_SSH_HOST_KEY_ALG_RSA_SHA2_256
	[SSH_SERVER_SIG_ALG_RSA_SHA2_256] = SSH_STRING_LITERAL("rsa-sha2-256"),
#endif
#ifdef CONFIG_SSH_HOST_KEY_ALG_RSA_SHA2_512
	[SSH_SERVER_SIG_ALG_RSA_SHA2_512] = SSH_STRING_LITERAL("rsa-sha2-512"),
#endif
};
BUILD_ASSERT(ARRAY_SIZE(supported_server_sig_algs) > 0);

int ssh_transport_start(struct ssh_transport *transport, bool server, void *parent,
			int sock, const struct sockaddr_in *addr, int host_key_index,
			ssh_transport_event_callback_t callback, void *user_data)
{
	*transport = (struct ssh_transport) {
		.server = server,
		.parent = parent,
		.sock = sock,
		.addr = *addr,
		.host_key_index = host_key_index,
		.callback = callback,
		.callback_user_data = user_data,
		.recv_state = SSH_RECV_STATE_IDENTITY_INIT,
		// TODO: Make allowed authentication methods configurable
		.auths_allowed_mask = BIT(SSH_AUTH_NONE) | BIT(SSH_AUTH_PASSWORD) | BIT(SSH_AUTH_PUBKEY)
	};

	k_msgq_init(&transport->user_request_msgq, (void *)transport->user_request_msgq_buf,
		    sizeof(transport->user_request_msgq_buf[0]), ARRAY_SIZE(transport->user_request_msgq_buf));

	sys_heap_init(&transport->kex_heap, transport->kex_heap_buf, sizeof(transport->kex_heap_buf));

	int res = send_identity(transport);
	if (res == 0) {
		transport->running = true;
	}
	return res;
}

void ssh_transport_close(struct ssh_transport *transport)
{
	for (int i = 0; i < ARRAY_SIZE(transport->channels); i++) {
		struct ssh_channel *channel = &transport->channels[i];
		if (!channel->in_use) {
			continue;
		}
		ssh_connection_free_channel(channel);
	}
	if (transport->encrypted) {
		mbedtls_aes_free(&transport->tx_cipher.aes_crypt);
		mbedtls_aes_free(&transport->rx_cipher.aes_crypt);
	}
	if (transport->client_identity != NULL) {
		sys_heap_free(&transport->kex_heap, transport->client_identity);
		transport->client_identity = NULL;
	}
	if (transport->server_identity != NULL) {
		sys_heap_free(&transport->kex_heap, transport->server_identity);
		transport->server_identity = NULL;
	}
	if (transport->client_kexinit != NULL) {
		sys_heap_free(&transport->kex_heap, transport->client_kexinit);
		transport->client_kexinit = NULL;
	}
	if (transport->server_kexinit != NULL) {
		sys_heap_free(&transport->kex_heap, transport->server_kexinit);
		transport->server_kexinit = NULL;
	}
	if (transport->shared_secret != NULL) {
		sys_heap_free(&transport->kex_heap, transport->shared_secret);
		transport->shared_secret = NULL;
	}
	if (transport->exchange_hash != NULL) {
		sys_heap_free(&transport->kex_heap, transport->exchange_hash);
		transport->exchange_hash = NULL;
	}
	if (transport->session_id != NULL) {
		sys_heap_free(&transport->kex_heap, transport->session_id);
		transport->session_id = NULL;
	}

	transport->running = false;
}

int ssh_transport_input(struct ssh_transport *transport)
{
	struct ssh_payload *rx_pkt = &transport->rx_pkt;
	uint32_t rx_cipher_block_size = 1;
	uint32_t mac_len = 0;
	if (transport->encrypted) {
		rx_cipher_block_size = MBEDTLS_AES_BLOCK_SIZE; // AES-128
		mac_len = 32; // AES-256
	}
	size_t read_len;

	switch (transport->recv_state) {
	case SSH_RECV_STATE_IDENTITY_INIT: {
		*rx_pkt = (struct ssh_payload) {
			.size = MIN(sizeof(transport->rx_buf), SSH_IDENTITY_MAX_LEN),
			.len = 0, .data = transport->rx_buf
		};
		transport->recv_state = SSH_RECV_STATE_IDENTITY;
		// fallthrough
	}
	case SSH_RECV_STATE_IDENTITY:
		// TODO: Currently just reading one byte at a time.
		//  Could read 5 bytes at a time during identity?
		//  Or (say) ~128 bytes every time and just "process data"?
		//  ZSOCK_MSG_PEEK isn't well supported
		//  ZSOCK_MSG_DONTWAIT could be an option?
		// TODO: The server MAY send other lines of data before sending the version string.
		read_len = 1;
		break;
	case SSH_RECV_STATE_PKT_INIT: {
		uint32_t header_read_len = MAX(rx_cipher_block_size, 8);
		if(header_read_len > sizeof(transport->rx_buf)) {
			return -1;
		}
		*rx_pkt = (struct ssh_payload) {
			.size = header_read_len, .len = 0, .data = transport->rx_buf
		};
		transport->recv_state = SSH_RECV_STATE_PKT_HEADER;
		// fallthrough
	}
	case SSH_RECV_STATE_PKT_HEADER:
	case SSH_RECV_STATE_PKT_PAYLOAD:
		read_len = rx_pkt->size - rx_pkt->len;
		break;
	default:
		// Bad state
		return -1;
	}

	void *buf = &rx_pkt->data[rx_pkt->len];
	ssize_t res = zsock_recv(transport->sock, buf, read_len, 0);
	if (res <= 0) {
		char str[32];
		zsock_inet_ntop(transport->addr.sin_family, &transport->addr.sin_addr, str, sizeof(str));
		if (res == 0) {
			LOG_INF("Connection closed %s:%d", str, htons(transport->addr.sin_port));
		} else {
			LOG_INF("recv error (%d) %s:%d",
				errno, str, htons(transport->addr.sin_port));
		}
		return -1;
	}
	LOG_HEXDUMP_DBG(buf, res, "RX:");

	switch (transport->recv_state) {
	case SSH_RECV_STATE_IDENTITY: {
		rx_pkt->len += res;
		if (rx_pkt->len > 2 &&
		    rx_pkt->data[rx_pkt->len-2] == '\r'
		    && rx_pkt->data[rx_pkt->len-1] == '\n') {
			// Truncate "\r\n"
			rx_pkt->len -= 2;
			LOG_INF("Remote identity: \"%.*s\"", rx_pkt->len, rx_pkt->data);

			// Save remote identity for KEX hash
			struct ssh_string **remote_identity = transport->server ? &transport->client_identity : &transport->server_identity;
			*remote_identity = ssh_payload_string_alloc(&transport->kex_heap, rx_pkt->data, rx_pkt->len);
			if (*remote_identity == NULL) {
				return -ENOMEM;
			}

			transport->recv_state = SSH_RECV_STATE_PKT_INIT;
			return ssh_kex_send_kexinit(transport);
		} else if (rx_pkt->len == rx_pkt->size - 1) {
			return -1;
		}
		break;
	}
	case SSH_RECV_STATE_PKT_HEADER: {
		rx_pkt->len += res;
		if (rx_pkt->len < rx_pkt->size) {
			break;
		}
		if (transport->encrypted) {
			// Decrypt
			size_t decrypt_len = rx_cipher_block_size;
			uint8_t *decrypt_buf = &rx_pkt->data[SSH_PKT_LEN_OFFSET];
//			uint8_t nonce[12] = {0};
//			sys_put_be64(transport->rx_seq_num, &nonce[4]);
//			res = mbedtls_chacha20_crypt(
//				&transport->encrypt_key_client[32], nonce, 0,
//				decrypt_len, decrypt_buf, decrypt_buf);
			struct ssh_cipher_aes128_ctr *cipher = &transport->rx_cipher;
			uint8_t *iv = transport->server ? transport->iv_client : transport->iv_server;
			cipher->aes_nc_off = 0;
			res = mbedtls_aes_crypt_ctr(&cipher->aes_crypt, decrypt_len, &cipher->aes_nc_off, iv,
						    cipher->aes_stream_block, decrypt_buf, decrypt_buf);
			if (res != 0) {
				LOG_ERR("Decrypt error");
				return -1;
			}
			LOG_HEXDUMP_DBG(decrypt_buf, decrypt_len, "RX hdr decrypt:");
		}
		uint32_t packet_len = sys_get_be32(&rx_pkt->data[SSH_PKT_LEN_OFFSET]);
		LOG_DBG("RX: Packet len %lu", packet_len);
		uint32_t total_len = SSH_PKT_LEN_SIZE + packet_len;

		// TODO: Encrypt Then Mac (ETM) MAC algorithms pad the packet without the packet length field
		if (total_len < packet_len || // wrapped
		    total_len < SSH_MIN_PACKET_LEN ||
		    total_len > SSH_MAX_PACKET_LEN ||
		    (total_len % MAX(rx_cipher_block_size, 8)) != 0) {
			LOG_ERR("Length error");
			return -1;
		}

		if(total_len + mac_len > sizeof(transport->rx_buf)) {
			LOG_ERR("Length error");
			return -1;
		}
		rx_pkt->size = total_len + mac_len;

		transport->recv_state = SSH_RECV_STATE_PKT_PAYLOAD;

		// It's possible we have received the full packet, fallthrough to check
		res = 0;
		// fallthrough
	}
	case SSH_RECV_STATE_PKT_PAYLOAD: {
		rx_pkt->len += res;
		if (rx_pkt->len < rx_pkt->size) {
			break;
		}
		uint32_t total_len = rx_pkt->len - mac_len;

		if (transport->encrypted) {
			// Decrypt
			size_t decrypt_len = total_len - rx_cipher_block_size;
			uint8_t *decrypt_buf = &rx_pkt->data[rx_cipher_block_size];
			if (decrypt_len > 0) {
//				uint8_t nonce[12] = {0};
//				sys_put_be64(transport->rx_seq_num, &nonce[4]);
//				res = mbedtls_chacha20_crypt(
//					&transport->encrypt_key_client[0], nonce, 1,
//					decrypt_len, decrypt_buf, decrypt_buf);
				struct ssh_cipher_aes128_ctr *cipher = &transport->rx_cipher;
				uint8_t *iv = transport->server ? transport->iv_client : transport->iv_server;
				res = mbedtls_aes_crypt_ctr(&cipher->aes_crypt, decrypt_len, &cipher->aes_nc_off, iv,
							    cipher->aes_stream_block, decrypt_buf, decrypt_buf);
				if (res != 0) {
					LOG_ERR("Decrypt error");
					return -1;
				}
				LOG_HEXDUMP_DBG(decrypt_buf, decrypt_len, "RX decrypt:");
			}
		}

		if (mac_len > 0) {
			uint8_t calculated_mac[mac_len];
			const uint8_t *mac_tag = &rx_pkt->data[total_len];
			const uint8_t *integ_key = transport->server ? transport->integ_key_client : transport->integ_key_server;
			res = mac_calculate(transport, integ_key, sizeof(transport->integ_key_client),
					    transport->rx_seq_num, rx_pkt->data, total_len, calculated_mac);
			if (res != 0) {
				return (int)res;
			}
			if (mbedtls_ct_memcmp(mac_tag, calculated_mac, mac_len) != 0) {
				LOG_ERR("MAC incorrect");
				return -1;
			}

			// Strip off the MAC before processing
			rx_pkt->size = total_len;
			rx_pkt->len = total_len;
		}

		transport->rx_bytes_since_kex += total_len + mac_len;
		transport->recv_state = SSH_RECV_STATE_PKT_INIT;
		return process_msg(transport);
	}
	default:
		// Bad state
		return -1;
	}

	return 0;
}

int ssh_transport_send_packet(struct ssh_transport *transport, /*const*/ struct ssh_payload *payload)
{
	int res;
	uint32_t total_len = payload->len;

	uint32_t len_to_pad = total_len;
	uint8_t padding_align = 8;
	if (transport->encrypted) {
//		// Encrypt Then Mac (ETM) MAC algorithms pad the packet without the packet length field...
//		len_to_pad -= SSH_BIN_PKT_LEN_SIZE;
		padding_align = 16; // AES-128
	}

	// Padding (4 byte minimum, 8 or more byte aligned)
	uint8_t padding_len = ROUND_UP(len_to_pad + 4, padding_align) - len_to_pad;
	total_len += padding_len;

	if (total_len < SSH_MIN_PACKET_LEN) {
		padding_len += padding_align;
		total_len += padding_align;
	}

	// Check that there is enough room for the random padding
	if (payload->size < total_len) {
		return -ENOBUFS;
	}

	// Prepend header
	uint32_t packet_len = total_len - SSH_PKT_LEN_SIZE;
	sys_put_be32(packet_len, &payload->data[SSH_PKT_LEN_OFFSET]);
	payload->data[SSH_PKT_PADDING_OFFSET] = padding_len;
	sys_rand_get(&payload->data[total_len - padding_len], padding_len);
	LOG_HEXDUMP_DBG(payload->data, total_len, "TX:");

	uint8_t mac_tag[32];

	if (transport->encrypted) {
		const uint8_t *integ_key = transport->server ? transport->integ_key_server : transport->integ_key_client;
		res = mac_calculate(transport, integ_key, sizeof(transport->integ_key_server),
				    transport->tx_seq_num, payload->data, total_len, mac_tag);
		if (res != 0) {
			return res;
		}

		// Encrypt
		size_t encrypt_len = total_len;
		uint8_t *encrypt_buf = payload->data;
//		uint8_t nonce[12] = {0};
//		sys_put_be64(transport->tx_seq_num, &nonce[4]);
//		res = mbedtls_chacha20_crypt(
//			&transport->encrypt_key_server[32], nonce, 0,
//			encrypt_len, encrypt_buf, encrypt_buf);

		struct ssh_cipher_aes128_ctr *cipher = &transport->tx_cipher;
		uint8_t *iv = transport->server ? transport->iv_server : transport->iv_client;
		size_t aes_nc_off = 0;
		res = mbedtls_aes_crypt_ctr(&cipher->aes_crypt, encrypt_len, &aes_nc_off, iv,
					    cipher->aes_stream_block, encrypt_buf, encrypt_buf);

		if (res != 0) {
			LOG_ERR("Encrypt error");
			return -1;
		}
		LOG_HEXDUMP_DBG(encrypt_buf, encrypt_len, "TX encrypt:");
	}
	ssize_t send_res = sendall(transport->sock, payload->data, total_len);
	if (send_res < 0) {
		return -errno;
	}
	transport->tx_bytes_since_kex += total_len;
	if (transport->encrypted) {
		LOG_HEXDUMP_DBG(mac_tag, sizeof(mac_tag), "TX digest:");
		send_res = sendall(transport->sock, mac_tag, sizeof(mac_tag));
		if (send_res < 0) {
			return -errno;
		}
		transport->tx_bytes_since_kex += sizeof(mac_tag);
	}

	transport->tx_seq_num++;

	return 0;
}

int ssh_transport_queue_user_request(struct ssh_transport *transport, const struct ssh_transport_user_request *request)
{
	if (!transport->running) {
		return -EINVAL;
	}
	int res = k_msgq_put(&transport->user_request_msgq, request, K_NO_WAIT);
	if (res != 0) {
		return res;
	}
	return ssh_transport_wakeup(transport);
}

int ssh_transport_wakeup(struct ssh_transport *transport)
{
	int eventfd = -1;
	if (transport->server) {
#ifdef CONFIG_SSH_SERVER
		eventfd = transport->ssh_server->eventfd;
#endif
	} else {
#ifdef CONFIG_SSH_CLIENT
		eventfd = transport->ssh_client->eventfd;
#endif
	}
	zvfs_eventfd_t value = 1;
	return zvfs_eventfd_write(eventfd, value);
}

int ssh_transport_update(struct ssh_transport *transport)
{
	// Don't try and do anything during key exchange
	if (transport->kexinit_sent) {
		return 0;
	}

	// Process any pending events
	int res = process_user_requests(transport);
	if (res != 0) {
		return res;
	}

	// Send pending data, update RX window
	res = update_channels(transport);
	if (res != 0) {
		return res;
	}

	// Check if it is time to for key re-exchange
	res = check_kex_expiry(transport);
	if (res != 0) {
		return res;
	}

	return 0;
}

int update_channels(struct ssh_transport *transport)
{
	int res = 0;

	if (!transport->authenticated || transport->kexinit_sent || transport->kexinit_received) {
		return 0;
	}

	for (int i = 0; i < ARRAY_SIZE(transport->channels); i++) {
		struct ssh_channel *channel = &transport->channels[i];
		if (!channel->in_use) {
			continue;
		}
		// Send any pending data
		while (channel->tx_window_rem > 0 && !ring_buf_is_empty(&channel->tx_ring_buf)) {
			uint8_t *data;
			uint32_t len = MIN(channel->tx_mtu, channel->tx_window_rem);
			// Assuming up to 256 bytes overhead for headers and random padding
			BUILD_ASSERT(sizeof(transport->tx_buf) > 256);
			len = MIN(len, sizeof(transport->tx_buf) - 256);
			len = ring_buf_get_claim(&channel->tx_ring_buf, &data, len);
			channel->tx_window_rem -= len;
			res = ssh_connection_send_channel_data(
				transport, channel->remote_channel, data, len);
			ring_buf_get_finish(&channel->tx_ring_buf, len);
			if (res != 0) {
				// Close channel?
				break;
			}

			struct ssh_channel_event event;
			event.type = SSH_CHANNEL_EVENT_TX_DATA_READY;
			if (channel->callback != NULL) {
				channel->callback(channel, &event, channel->user_data);
			}
		}
		while (channel->tx_window_rem > 0 && !ring_buf_is_empty(&channel->tx_stderr_ring_buf)) {
			uint8_t *data;
			uint32_t len = MIN(channel->tx_mtu, channel->tx_window_rem);
			// Assuming up to 256 bytes overhead for headers and random padding
			BUILD_ASSERT(sizeof(transport->tx_buf) > 256);
			len = MIN(len, sizeof(transport->tx_buf) - 256);
			len = ring_buf_get_claim(&channel->tx_stderr_ring_buf, &data, len);
			channel->tx_window_rem -= len;
			res = ssh_connection_send_channel_extended_data(
				transport, channel->remote_channel,
				SSH_EXTENDED_DATA_STDERR, data, len);
			ring_buf_get_finish(&channel->tx_stderr_ring_buf, len);
			if (res != 0) {
				// Close channel?
				break;
			}

			struct ssh_channel_event event;
			event.type = SSH_CHANNEL_EVENT_TX_DATA_READY;
			if (channel->callback != NULL) {
				channel->callback(channel, &event, channel->user_data);
			}
		}

		// Adjust RX window
		if (channel->rx_window_rem == 0) {
			uint32_t available_space = MIN(ring_buf_space_get(&channel->rx_ring_buf),
						       ring_buf_space_get(&channel->rx_stderr_ring_buf));
			if (available_space > 0) {
				channel->rx_window_rem = available_space;
				res = ssh_connection_send_window_adjust(
					transport, channel->remote_channel, available_space);
				if (res != 0) {
					// Close channel?
					break;
				}
			}
		}
	}

	return res;
}

int check_kex_expiry(struct ssh_transport *transport)
{
	if (!transport->encrypted || transport->kexinit_sent) {
		return 0;
	}

	if (sys_timepoint_expired(transport->kex_expiry) ||
	    transport->tx_bytes_since_kex >= GB(1) ||
	    transport->rx_bytes_since_kex >= GB(1)) {
		return ssh_kex_send_kexinit(transport);
	}
	return 0;
}

static int process_user_requests(struct ssh_transport *transport)
{
	int res;

	if (transport->kexinit_sent || transport->kexinit_received) {
		return 0;
	}

	// Process any pending requests
	while (true) {
		struct ssh_transport_user_request request;
		res = k_msgq_get(&transport->user_request_msgq, &request, K_NO_WAIT);
		if (res != 0) {
			return 0;
		}
		res = process_user_request(transport, &request);
		if (res != 0) {
			return res;
		}
	}
}

#ifdef CONFIG_SSH_CLIENT
const char *ssh_transport_client_user_name(struct ssh_transport *transport)
{
	if (transport == NULL || transport->server) {
		return NULL;
	}
	return transport->ssh_client->user_name;
}

int ssh_transport_auth_password(struct ssh_transport *transport, const char *user_name, const char *password)
{
	if (transport == NULL || !transport->running || !transport->encrypted || transport->server) {
		return -EINVAL;
	}
	struct ssh_transport_user_request request;
	request.type = SSH_TRANSPORT_USER_REQUEST_AUTHENTICATE;
	request.authenticate.type = SSH_AUTH_PASSWORD;
	size_t user_name_len = strlen(user_name);
	if (user_name_len + 1 >= ARRAY_SIZE(request.authenticate.user_name)) {
		return -EINVAL;
	}
	memcpy(request.authenticate.user_name, user_name, user_name_len + 1);
	size_t password_len = strlen(password);
	if (password_len + 1 >= ARRAY_SIZE(request.authenticate.password)) {
		return -EINVAL;
	}
	memcpy(request.authenticate.password, password, password_len + 1);
	return ssh_transport_queue_user_request(transport, &request);
}

int ssh_transport_channel_open(struct ssh_transport *transport, ssh_channel_event_callback_t callback, void *user_data)
{
	if (transport == NULL || !transport->running || !transport->authenticated || transport->server) {
		return -EINVAL;
	}
	struct ssh_transport_user_request request;
	request.type = SSH_TRANSPORT_USER_REQUEST_OPEN_CHANNEL;
	request.open_channel.callback = callback;
	request.open_channel.user_data = user_data;
	return ssh_transport_queue_user_request(transport, &request);
}
#endif

static int process_user_request(struct ssh_transport *transport, const struct ssh_transport_user_request *request)
{
	switch (request->type) {
#ifdef CONFIG_SSH_SERVER
	case SSH_TRANSPORT_USER_REQUEST_OPEN_CHANNEL_RESULT: {
		struct ssh_channel *channel = request->open_channel_result.channel;
		channel->callback = request->open_channel_result.callback;
		channel->user_data = request->open_channel_result.user_data;

		int res = -1;
		if (request->open_channel_result.success) {
			res = ssh_connection_send_channel_open_confirmation(
				transport, channel->remote_channel, channel->local_channel,
				channel->rx_window_rem, channel->rx_mtu);
			if (res == 0) {
				channel->open = true;
			}
		}
		// TODO: else send channel open failure
		if (res != 0) {
			ssh_connection_free_channel(channel);
		}
		return res;
	}
#endif
	case SSH_TRANSPORT_USER_REQUEST_CHANNEL_REQUEST_RESULT: {
		struct ssh_channel *channel = request->channel_request_result.channel;
		bool success = request->channel_request_result.success;
		int res = ssh_connection_send_channel_result(transport, success, channel->remote_channel);
		if (res != 0) {
			ssh_connection_free_channel(channel);
		}
		return res;
	}
#ifdef CONFIG_SSH_CLIENT
	case SSH_TRANSPORT_USER_REQUEST_AUTHENTICATE:
		if (!transport->encrypted || transport->authenticated) {
			return -1;
		}
		switch (request->authenticate.type) {
		case SSH_AUTH_NONE:
			return ssh_auth_send_userauth_request_none(
				transport, request->authenticate.user_name);
		case SSH_AUTH_PASSWORD:
			return ssh_auth_send_userauth_request_password(
				transport, request->authenticate.user_name,
				request->authenticate.password);
		default:
			return -1;
		}
		break;
	case SSH_TRANSPORT_USER_REQUEST_OPEN_CHANNEL: {
		if (!transport->authenticated) {
			return -1;
		}
		struct ssh_channel *channel = ssh_connection_allocate_channel(transport);
		if (channel == NULL) {
			LOG_ERR("Failed to alloc channel");
			return -ENOBUFS;
		}
		channel->callback = request->open_channel.callback;
		channel->user_data = request->open_channel.user_data;

		struct ssh_string channel_type = SSH_STRING_LITERAL("session");
		uint32_t sender_channel = channel->local_channel;
		channel->rx_window_rem = sizeof(channel->rx_ring_buf_data);
		// TODO: MTU = sizeof(transport->rx_buf) - HEADER_LEN - MAX_PADDING - MAC_LEN?
		channel->rx_mtu = sizeof(channel->rx_ring_buf_data);
		uint32_t initial_window_size = channel->rx_window_rem;
		uint32_t maximum_packet_size = channel->rx_mtu;
		int res = ssh_connection_send_channel_open(
			transport, &channel_type, sender_channel,
			initial_window_size, maximum_packet_size);
		if (res != 0) {
			ssh_connection_free_channel(channel);
		}
		return res;
	}
#endif
	case SSH_TRANSPORT_USER_REQUEST_CHANNEL_REQUEST: {
		if (!transport->authenticated) {
			return -1;
		}
		struct ssh_channel *channel = request->channel_request.channel;
		static const struct ssh_string channel_type_shell = SSH_STRING_LITERAL("shell");
		const struct ssh_string *channel_type;
		switch (request->channel_request.type) {
		case SSH_CHANNEL_REQUEST_SHELL: {
			// TODO: Hack: sending pseudo terminal request here too...
			int res = ssh_connection_send_channel_request_pseudo_terminal(
				transport, channel->remote_channel, true);
			(void)res;
			channel_type = &channel_type_shell;
			break;
		}
		default:
			return -1;
		}
		bool want_reply = request->channel_request.want_reply;
		return ssh_connection_send_channel_request(
			transport, channel->remote_channel,
			channel_type, want_reply);
	}
	default:
		return -1;
	}

	return -1;
}

static int send_identity(struct ssh_transport *transport)
{
	const uint32_t identity_len = sizeof(zephyr_ssh_identity) - 1;

	LOG_HEXDUMP_DBG(zephyr_ssh_identity, identity_len, "TX:");
	ssize_t send_res = sendall(transport->sock, zephyr_ssh_identity, identity_len);
	if (send_res == 0) {
		LOG_HEXDUMP_DBG("\r\n", 2, "TX:");
		send_res = sendall(transport->sock, "\r\n", 2);
	}
	if (send_res != 0) {
		LOG_WRN("Failed to send identity (%d)", errno);
		return -errno;
	}

	// Save local identity for KEX hash
	struct ssh_string **local_identity = transport->server ? &transport->server_identity : &transport->client_identity;
	*local_identity = ssh_payload_string_alloc(&transport->kex_heap, zephyr_ssh_identity, identity_len);
	if (*local_identity == NULL) {
		return -ENOMEM;
	}

	return 0;
}

static int process_msg(struct ssh_transport *transport)
{
	int res;
	struct ssh_payload *rx_pkt = &transport->rx_pkt;

	// Strip off the random padding and MAC before processing
	uint32_t packet_len = rx_pkt->size - SSH_PKT_LEN_SIZE;
	uint8_t padding_len = rx_pkt->data[SSH_PKT_LEN_SIZE];

	// At least 1 byte for message ID
	if (packet_len < SSH_PKT_PADDING_SIZE + SSH_PKT_MSG_ID_SIZE + padding_len) {
		LOG_ERR("Length error");
		return -1;
	}

	// Strip off the random padding
	rx_pkt->size -= padding_len;

	rx_pkt->len = SSH_PKT_MSG_ID_OFFSET;
	uint8_t msg_id = rx_pkt->data[rx_pkt->len++];

	LOG_DBG("RX: Packet len %lu, padding len %u, msg ID %u",
		packet_len, padding_len, msg_id);

	if (IN_RANGE(msg_id, 1, 49)) {
//		if (transport->kexinit_received) {
//			switch (msg_id) {
//			case SSH_MSG_SERVICE_REQUEST:
//			case SSH_MSG_SERVICE_ACCEPT:
//			case SSH_MSG_KEXINIT:
//				// These messages are not allowed between kexinit and newkeys
//				return -1;
//			default:
//				break;
//			}
//		}
		res = ssh_transport_process_msg(transport, msg_id, rx_pkt);
	} else if (IN_RANGE(msg_id, 50, 79)) {
		if (!transport->encrypted || transport->kexinit_received) {
			return -1;
		}
		res = ssh_auth_process_msg(transport, msg_id, rx_pkt);
	} else if (IN_RANGE(msg_id, 80, 100)) {
		if (!transport->encrypted || !transport->authenticated || transport->kexinit_received) {
			return -1;
		}
		res = ssh_connection_process_msg(transport, msg_id, rx_pkt);
	} else {
		return -1;
	}

	if (rx_pkt->data != NULL) {
		// mbedtls_platform_zeroize(rx_pkt->data, rx_pkt->len);
	}

	transport->rx_seq_num++;

	if (res != 0 && msg_id != SSH_MSG_DISCONNECT) {
		LOG_ERR("Error processing message (%u)", msg_id);
		return -1;
	}

	return 0;
}

static int ssh_transport_process_msg(struct ssh_transport *transport, uint8_t msg_id, struct ssh_payload *rx_pkt)
{
	int res = -1;

	if (IN_RANGE(msg_id, 30, 49)) {
		return ssh_kex_process_msg(transport, msg_id, rx_pkt);
	}

	switch (msg_id) {
	case SSH_MSG_DISCONNECT: {
		LOG_INF("DISCONNECT");
		uint32_t reason_code;
		struct ssh_string description, language_tag;
		if (!ssh_payload_read_u32(rx_pkt, &reason_code) ||
		    !ssh_payload_read_string(rx_pkt, &description) ||
		    !ssh_payload_read_string(rx_pkt, &language_tag) ||
		    !ssh_payload_read_complete(rx_pkt)) {
			LOG_ERR("Length error");
			return -1;
		}
		LOG_INF("DISCONNECT: reason %u \"%.*s\"", reason_code, description.len, description.data);
		return -1;
	}
	case SSH_MSG_UNIMPLEMENTED: {
		LOG_INF("UNIMPLEMENTED");
		uint32_t rejected_seq_num;
		if (!ssh_payload_read_u32(rx_pkt, &rejected_seq_num) ||
		    !ssh_payload_read_complete(rx_pkt)) {
			LOG_ERR("Length error");
			return -1;
		}
		return -1;
	}
	case SSH_MSG_IGNORE: {
		LOG_INF("IGNORE");
		struct ssh_string ignore_data;
		if (!ssh_payload_read_string(rx_pkt, &ignore_data) ||
		    !ssh_payload_read_complete(rx_pkt)) {
			LOG_ERR("Length error");
			return -1;
		}
		res = 0;
		break;
	}
	case SSH_MSG_DEBUG: {
		LOG_INF("DEBUG");
		bool always_display;
		struct ssh_string dbg_msg, language_tag;
		if (!ssh_payload_read_bool(rx_pkt, &always_display) ||
		    !ssh_payload_read_string(rx_pkt, &dbg_msg) ||
		    !ssh_payload_read_string(rx_pkt, &language_tag) ||
		    !ssh_payload_read_complete(rx_pkt)) {
			LOG_ERR("Length error");
			return -1;
		}
		if (always_display) {
			LOG_INF("Remote dbg: %.*s", dbg_msg.len, dbg_msg.data);
		} else {
			LOG_DBG("Remote dbg: %.*s", dbg_msg.len, dbg_msg.data);
		}
		res = 0;
		break;
	}
#ifdef CONFIG_SSH_SERVER
	case SSH_MSG_SERVICE_REQUEST: {
		LOG_INF("SERVICE_REQUEST");
		// Server only
		if (!transport->server || !transport->encrypted || transport->kexinit_received) {
			break;
		}
		struct ssh_string service_name;
		if (!ssh_payload_read_string(rx_pkt, &service_name) ||
		    !ssh_payload_read_complete(rx_pkt)) {
			LOG_ERR("Length error");
			return -1;
		}
		static const struct ssh_string supported_service_name = SSH_STRING_LITERAL("ssh-userauth");
		if (!ssh_strings_equal(&service_name, &supported_service_name)) {
			LOG_WRN("Unsupported service");
			return -1;
		}
		res = send_service_accept(transport, &service_name);
		break;
	}
#endif
#ifdef CONFIG_SSH_CLIENT
	case SSH_MSG_SERVICE_ACCEPT: {
		LOG_INF("SERVICE_ACCEPT");
		// Client only
		if (transport->server || !transport->encrypted || transport->kexinit_received) {
			break;
		}
		struct ssh_string service_name;
		if (!ssh_payload_read_string(rx_pkt, &service_name) ||
		    !ssh_payload_read_complete(rx_pkt)) {
			LOG_ERR("Length error");
			return -1;
		}

		// Start by sending a userauth "none" request.
		// This may succeed, but more generally it's used to get a list
		// of available authentication methods in the failure reply.
		struct ssh_client *ssh_client = transport->ssh_client;
		return ssh_auth_send_userauth_request_none(transport, ssh_client->user_name);
	}
	case SSH_MSG_EXT_INFO: {
		LOG_INF("EXT_INFO");
		// Client only
		if (transport->server || !transport->encrypted || transport->kexinit_received) {
			break;
		}
		uint32_t num_extensions;
		if (!ssh_payload_read_u32(rx_pkt, &num_extensions)) {
			LOG_ERR("Length error");
			return -1;
		}
		for (uint32_t i = 0; i < num_extensions; i++) {
			struct ssh_string extension_name;
			struct ssh_string extension_value;
			if (!ssh_payload_read_string(rx_pkt, &extension_name) ||
			    !ssh_payload_read_string(rx_pkt, &extension_value)) {
				LOG_ERR("Length error");
				return -1;
			}
			LOG_DBG("Extension: %.*s", extension_name.len, extension_name.data);
			LOG_HEXDUMP_DBG(extension_value.data, extension_value.len, "Value");
			if (ssh_strings_equal(&extension_name, &server_sig_algs_str)) {
				res = process_server_sig_algs(transport, &extension_value);
				if (res != 0) {
					return res;
				}
			}

		}
		if (!ssh_payload_read_complete(rx_pkt)) {
			LOG_ERR("Length error");
			return -1;
		}
		res = 0;
		break;
	}
#endif
	case SSH_MSG_KEXINIT:
		return ssh_kex_process_kexinit(transport, rx_pkt);
	case SSH_MSG_NEWKEYS:
		return ssh_kex_process_newkeys(transport, rx_pkt);
	default:
		break;
	}

	return res;
}

#ifdef CONFIG_SSH_CLIENT
int ssh_transport_send_service_request(struct ssh_transport *transport, const struct ssh_string *service_name)
{
	int res;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);

	if (!ssh_payload_skip_bytes(&payload, SSH_PKT_MSG_ID_OFFSET) ||
	    !ssh_payload_write_byte(&payload, SSH_MSG_SERVICE_REQUEST) ||
	    !ssh_payload_write_string(&payload, service_name)) {
		return -ENOBUFS;
	}

	res = ssh_transport_send_packet(transport, &payload);
	if (res < 0) {
		LOG_WRN("Failed to send SERVICE_REQUEST %d", res);
	}
	return res;
}

static int process_server_sig_algs(struct ssh_transport *transport,
				   const struct ssh_string *server_sig_algs)
{
	struct ssh_string alg_name;
	struct ssh_payload alg_name_list = {
		.size = server_sig_algs->len,
		.len = 0,
		.data = (void *)server_sig_algs->data
	};

	LOG_DBG("server-sig-algs: %.*s", server_sig_algs->len, server_sig_algs->data);
	transport->sig_algs_mask = 0;

	while (ssh_payload_name_list_iter(&alg_name_list, &alg_name)) {
		for (int j = 0; j < ARRAY_SIZE(supported_server_sig_algs); j++) {
			if (ssh_strings_equal(&supported_server_sig_algs[j], &alg_name)) {
				LOG_DBG("Adding supported server-sig-alg: %.*s",
					alg_name.len, alg_name.data);
				transport->sig_algs_mask |= BIT(j);
			}
		}
	}

	return 0;
}
#endif

#ifdef CONFIG_SSH_SERVER
int ssh_transport_send_server_sig_algs(struct ssh_transport *transport)
{
	int res;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);
	uint32_t num_extensions = 1;

	if (!ssh_payload_skip_bytes(&payload, SSH_PKT_MSG_ID_OFFSET) ||
	    !ssh_payload_write_byte(&payload, SSH_MSG_EXT_INFO) ||
	    !ssh_payload_write_u32(&payload, num_extensions) ||
	    !ssh_payload_write_string(&payload, &server_sig_algs_str) ||
	    !ssh_payload_write_name_list(&payload, supported_server_sig_algs, ARRAY_SIZE(supported_server_sig_algs))) {
		return -ENOBUFS;
	}

	res = ssh_transport_send_packet(transport, &payload);
	if (res < 0) {
		LOG_WRN("Failed to send EXT_INFO %d", res);
	}
	return res;
}

static int send_service_accept(struct ssh_transport *transport, const struct ssh_string *service_name)
{
	int res;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);

	if (!ssh_payload_skip_bytes(&payload, SSH_PKT_MSG_ID_OFFSET) ||
	    !ssh_payload_write_byte(&payload, SSH_MSG_SERVICE_ACCEPT) ||
	    !ssh_payload_write_string(&payload, service_name)) {
		return -ENOBUFS;
	}

	res = ssh_transport_send_packet(transport, &payload);
	if (res < 0) {
		LOG_WRN("Failed to send SERVICE_ACCEPT %d", res);
	}
	return res;
}
#endif

static int mac_calculate(struct ssh_transport *transport, const uint8_t *key, size_t key_len,
			 uint32_t seq_num, const void *data, size_t len, uint8_t *mac_tag_out)
{
	ARG_UNUSED(transport);
	int res;
	// HMAC
	mbedtls_md_context_t md_ctx;
	mbedtls_md_init(&md_ctx);
	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (md_info == NULL) {
		res = -EIO;
		goto exit;
	}
	int hmac = 1;
	res = mbedtls_md_setup(&md_ctx, md_info, hmac);
	if (res != 0) {
		res = -EIO;
		goto exit;
	}
	res = mbedtls_md_hmac_starts(&md_ctx, key, key_len);
	if (res != 0) {
		res = -EIO;
		goto exit;
	}
	uint8_t tmp[4];
	sys_put_be32(seq_num, tmp);
	res = mbedtls_md_hmac_update(&md_ctx, tmp, sizeof(tmp));
	if (res != 0) {
		res = -EIO;
		goto exit;
	}
	res = mbedtls_md_hmac_update(&md_ctx, data, len);
	if (res != 0) {
		res = -EIO;
		goto exit;
	}
	res = mbedtls_md_hmac_finish(&md_ctx, mac_tag_out);
	if (res != 0) {
		res = -EIO;
		goto exit;
	}

exit:
	mbedtls_md_free(&md_ctx);

	return res;
}

static ssize_t sendall(int sock, const void *buf, size_t len)
{
	while (len) {
		ssize_t out_len = zsock_send(sock, buf, len, 0);

		if (out_len < 0) {
			return out_len;
		}
		buf = (const char *)buf + out_len;
		len -= out_len;
	}

	return 0;
}
