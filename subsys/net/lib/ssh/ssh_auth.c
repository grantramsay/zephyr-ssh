/*
* Copyright (c) 2024 Grant Ramsay <grant.ramsay@hotmail.com>
*
* SPDX-License-Identifier: Apache-2.0
*/
#include "ssh_auth.h"

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(ssh, CONFIG_NET_SSH_LOG_LEVEL);

#define ZEPHYR_SSH_BANNER ("Welcome to Zephyr OS build " ZEPHYR_SSH_VERSION)

#ifdef CONFIG_SSH_SERVER
static int send_userauth_failure(struct ssh_transport *transport, bool partial_success);
static int send_userauth_success(struct ssh_transport *transport);
static int send_userauth_banner(struct ssh_transport *transport);
static int send_userauth_pk_ok(struct ssh_transport *transport,
			       const struct ssh_string *pub_key_alg,
			       const struct ssh_string *pub_key);
#endif

static const struct ssh_string auth_methods[] = {
	[SSH_AUTH_NONE] = SSH_STRING_LITERAL("none"),
	[SSH_AUTH_PASSWORD] = SSH_STRING_LITERAL("password"),
	[SSH_AUTH_PUBKEY] = SSH_STRING_LITERAL("publickey")
};

static int auth_method_str_to_id(const struct ssh_string *method)
{
	for (int i = 0; i < ARRAY_SIZE(auth_methods); i++) {
		if (ssh_strings_equal(&auth_methods[i], method)) {
			return i;
		}
	}
	return -ENOTSUP;
}

#ifdef CONFIG_SSH_CLIENT
int ssh_auth_send_userauth_request_none(struct ssh_transport *transport, const char *user_name)
{
	int res;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);
	static const struct ssh_string service_name = SSH_STRING_LITERAL("ssh-connection");
	const struct ssh_string *method_name = &auth_methods[SSH_AUTH_NONE];

	if (!ssh_payload_skip_bytes(&payload, SSH_PKT_MSG_ID_OFFSET) ||
	    !ssh_payload_write_byte(&payload, SSH_MSG_USERAUTH_REQUEST) ||
	    !ssh_payload_write_cstring(&payload, user_name) ||
	    !ssh_payload_write_string(&payload, &service_name) ||
	    !ssh_payload_write_string(&payload, method_name)) {
		return -ENOBUFS;
	}

	res = ssh_transport_send_packet(transport, &payload);
	if (res < 0) {
		LOG_WRN("Failed to send USERAUTH_REQUEST %d", res);
	}
	return res;
}

int ssh_auth_send_userauth_request_password(struct ssh_transport *transport, const char *user_name, const char *password)
{
	int res;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);
	static const struct ssh_string service_name = SSH_STRING_LITERAL("ssh-connection");
	const struct ssh_string *method_name = &auth_methods[SSH_AUTH_PASSWORD];

	if (!ssh_payload_skip_bytes(&payload, SSH_PKT_MSG_ID_OFFSET) ||
	    !ssh_payload_write_byte(&payload, SSH_MSG_USERAUTH_REQUEST) ||
	    !ssh_payload_write_cstring(&payload, user_name) ||
	    !ssh_payload_write_string(&payload, &service_name) ||
	    !ssh_payload_write_string(&payload, method_name) ||
	    !ssh_payload_write_bool(&payload, false) ||
	    !ssh_payload_write_cstring(&payload, password)) {
		return -ENOBUFS;
	}

	res = ssh_transport_send_packet(transport, &payload);
	if (res < 0) {
		LOG_WRN("Failed to send USERAUTH_REQUEST %d", res);
	}
	return res;
}

static int ssh_auth_send_userauth_request_pubkey(struct ssh_transport *transport,
						 const char *user_name, int host_key_index)
{
	int res;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);
	static const struct ssh_string service_name = SSH_STRING_LITERAL("ssh-connection");
	const struct ssh_string *method_name = &auth_methods[SSH_AUTH_PUBKEY];
	// Normally you would send each public key without a signature and
	// check for a SSH_MSG_USERAUTH_PK_OK response. However, since only
	// a single public key is supported, just send once with the signature.
	const bool has_signature = true;

	struct ssh_string todo = SSH_STRING_LITERAL("rsa-sha2-256");

	// First create the signature
	if (!ssh_payload_write_string(&payload, transport->session_id) ||
	    !ssh_payload_write_byte(&payload, SSH_MSG_USERAUTH_REQUEST) ||
	    !ssh_payload_write_cstring(&payload, user_name) ||
	    !ssh_payload_write_string(&payload, &service_name) ||
	    !ssh_payload_write_string(&payload, method_name) ||
	    !ssh_payload_write_bool(&payload, has_signature) ||
	    !ssh_payload_write_string(&payload, &todo)) {
		return -ENOBUFS;
	}
	res = ssh_host_key_write_pub_key(&payload, host_key_index);
	if (res != 0) {
		return res;
	}

	// TODO: Get this from transport->sig_algs_mask
	enum ssh_host_key_alg host_key_alg = SSH_HOST_KEY_ALG_RSA_SHA2_256;
	res = ssh_host_key_write_signature(&payload, host_key_index, host_key_alg,
					   payload.data, payload.len);
	if (res != 0) {
		return res;
	}

	if (transport->session_id->len < SSH_PKT_MSG_ID_OFFSET) {
		// This should never occur
		return -1;
	}
	// Move the payload into place (stripping session_id from the front)
	payload.len = payload.len + SSH_PKT_MSG_ID_OFFSET - transport->session_id->len - 4;
	memmove(&payload.data[SSH_PKT_MSG_ID_OFFSET], &payload.data[transport->session_id->len + 4], payload.len);

	res = ssh_transport_send_packet(transport, &payload);
	if (res < 0) {
		LOG_WRN("Failed to send USERAUTH_REQUEST %d", res);
	}
	return res;
}
#endif

int ssh_auth_process_msg(struct ssh_transport *transport, uint8_t msg_id, struct ssh_payload *rx_pkt)
{
	int res = -1;

	switch (msg_id) {
#ifdef CONFIG_SSH_SERVER
	case SSH_MSG_USERAUTH_REQUEST: {
		LOG_INF("USERAUTH_REQUEST");
		// Server only
		if (!transport->server) {
			return -1;
		}

		/* Clients can send multiple authentication requests at once.
		 * After one is accepted we must reply with failure for the rest
		 */
		if (transport->authenticated) {
			return send_userauth_failure(transport, false);
		}

		struct ssh_string user_name, service_name, method_name;
		if (!ssh_payload_read_string(rx_pkt, &user_name) ||
		    !ssh_payload_read_string(rx_pkt, &service_name) ||
		    !ssh_payload_read_string(rx_pkt, &method_name)) {
			LOG_ERR("Length error");
			return -1;
		}
		// TODO: ssh_payload_read_complete for different auth methods
		LOG_INF("USERAUTH_REQUEST: %.*s %.*s %.*s", user_name.len, user_name.data,
			service_name.len, service_name.data, method_name.len, method_name.data);

		res = auth_method_str_to_id(&method_name);

		switch (res) {
		case SSH_AUTH_NONE:
			//if ((transport->auths_allowed_mask & BIT(SSH_AUTH_NONE)) != 0) {}
			return send_userauth_failure(transport, false);
		case SSH_AUTH_PASSWORD: {
			//if ((transport->auths_allowed_mask & BIT(SSH_AUTH_PASSWORD)) != 0) {}
			struct ssh_string password;
			if (!ssh_payload_read_bool(rx_pkt, NULL) ||
			    !ssh_payload_read_string(rx_pkt, &password) ||
			    !ssh_payload_read_complete(rx_pkt)) {
				LOG_ERR("Length error");
				return -1;
			}
			// Check password
			struct ssh_server *ssh_server = transport->ssh_server;
			size_t password_len = strlen(ssh_server->password);
			if (password_len == 0 || password_len != password.len ||
			    strncmp(ssh_server->password, password.data, password_len) != 0) {
				return send_userauth_failure(transport, false);
			}
			// Else success!
			break;
		}
		case SSH_AUTH_PUBKEY: {
			//if ((transport->auths_allowed_mask & BIT(SSH_AUTH_PUBKEY)) != 0) {}
			bool has_signature;
			struct ssh_string pub_key_alg, pub_key, signature;
			if (!ssh_payload_read_bool(rx_pkt, &has_signature) ||
			    !ssh_payload_read_string(rx_pkt, &pub_key_alg) ||
			    !ssh_payload_read_string(rx_pkt, &pub_key)) {
				LOG_ERR("Length error");
				return -1;
			}
			if (has_signature) {
				if (!ssh_payload_read_string(rx_pkt, &signature)) {
					LOG_ERR("Length error");
					return -1;
				}
			}
			if (!ssh_payload_read_complete(rx_pkt)) {
				LOG_ERR("Length error");
				return -1;
			}

			// Try to find a matching public key
			struct ssh_server *ssh_server = transport->ssh_server;
			int pub_key_index = -1;
			for (size_t i = 0 ; i < ssh_server->authorized_keys_len; i++) {
				// Re-use the TX buf for temporary storage
				SSH_PAYLOAD_BUF(payload, transport->tx_buf);
				struct ssh_string tmp_pub_key;
				res = ssh_host_key_write_pub_key(&payload, ssh_server->authorized_keys[i]);
				payload.size = payload.len;
				payload.len = 0;
				if (res == 0 && ssh_payload_read_string(&payload, &tmp_pub_key) &&
				    ssh_strings_equal(&pub_key, &tmp_pub_key)) {
					pub_key_index = ssh_server->authorized_keys[i];
					break;
				}
			}
			if (pub_key_index < 0) {
				return send_userauth_failure(transport, false);
			}

			if (has_signature) {
				// Re-use the TX buf for temporary storage
				SSH_PAYLOAD_BUF(payload, transport->tx_buf);
				if (!ssh_payload_write_string(&payload, transport->session_id) ||
				    !ssh_payload_write_raw(&payload, &rx_pkt->data[SSH_PKT_MSG_ID_OFFSET],
							   rx_pkt->size - SSH_PKT_MSG_ID_OFFSET - 4 - signature.len)) {
					// Too big
					return send_userauth_failure(transport, false);
				}
				res = ssh_host_key_verify_signature(
					NULL, &pub_key, &signature, payload.data, payload.len);
				if (res < 0) {
					return send_userauth_failure(transport, false);
				}
				// Else success!
			} else {
				return send_userauth_pk_ok(transport, &pub_key_alg, &pub_key);
			}
			break;
		}
		default:
			// Unsupported auth method
			return send_userauth_failure(transport, false);
		}

		res = send_userauth_banner(transport);
		if (res < 0) {
			return res;
		}
		res = send_userauth_success(transport);
		if (res < 0) {
			return res;
		}
		transport->authenticated = true;
		break;
	}
#endif
#ifdef CONFIG_SSH_CLIENT
	case SSH_MSG_USERAUTH_FAILURE: {
		LOG_INF("USERAUTH_FAILURE");
		// Client only
		if (transport->server || transport->authenticated) {
			return -1;
		}
		struct ssh_payload auths_allowed_name_list;
		bool partial_success;
		if (!ssh_payload_read_name_list(rx_pkt, &auths_allowed_name_list) ||
		    !ssh_payload_read_bool(rx_pkt, &partial_success) ||
		    !ssh_payload_read_complete(rx_pkt)) {
			LOG_ERR("Length error");
			return -1;
		}
		LOG_DBG("Available auth methods: %.*s", auths_allowed_name_list.size, auths_allowed_name_list.data);
		struct ssh_string auth_name;
		uint32_t auths_allowed_mask = 0;
		while (ssh_payload_name_list_iter(&auths_allowed_name_list, &auth_name)) {
			int auth = auth_method_str_to_id(&auth_name);
			if (auth < 0 || auth == SSH_AUTH_NONE) {
				continue;
			}
			auths_allowed_mask |= BIT(auth);
		}
		transport->auths_allowed_mask &= auths_allowed_mask;

		// Attempt public key auth if server allows it, it has
		// not already been attempted, we have a public key and
		// the server supports one of our signature algorithms
		struct ssh_client *ssh_client = transport->ssh_client;
		if ((transport->auths_allowed_mask & BIT(SSH_AUTH_PUBKEY)) != 0 &&
		    ssh_client->host_key_index >= 0 && transport->sig_algs_mask != 0) {
			res = ssh_auth_send_userauth_request_pubkey(
				transport, ssh_client->user_name, ssh_client->host_key_index);
			transport->auths_allowed_mask &= ~BIT(SSH_AUTH_PUBKEY);
		} else if ((transport->auths_allowed_mask & BIT(SSH_AUTH_PASSWORD)) != 0 &&
			   transport->callback != NULL) {
			struct ssh_transport_event event;
			event.type = SSH_TRANSPORT_EVENT_SERVICE_ACCEPTED;
			res = transport->callback(transport, &event, transport->callback_user_data);
			transport->auths_allowed_mask &= ~BIT(SSH_AUTH_PASSWORD);
		} else {
			LOG_INF("No available auth methods");
			return -1;
		}
		break;
	}
	case SSH_MSG_USERAUTH_SUCCESS: {
		LOG_INF("USERAUTH_SUCCESS");
		// Client only
		if (transport->server || transport->authenticated) {
			return -1;
		}
		if (!ssh_payload_read_complete(rx_pkt)) {
			LOG_ERR("Length error");
			return -1;
		}
		transport->authenticated = true;

		if (transport->callback != NULL) {
			struct ssh_transport_event event;
			event.type = SSH_TRANSPORT_EVENT_AUTHENTICATE_RESULT;
			event.authenticate_result.success = true;
			res = transport->callback(transport, &event, transport->callback_user_data);
		}
		break;
	}
	case SSH_MSG_USERAUTH_BANNER: {
		LOG_INF("USERAUTH_BANNER");
		struct ssh_string zephyr_ssh_banner, language_tag;
		if (!ssh_payload_read_string(rx_pkt, &zephyr_ssh_banner) ||
		    !ssh_payload_read_string(rx_pkt, &language_tag) ||
		    !ssh_payload_read_complete(rx_pkt)) {
			LOG_ERR("Length error");
			return -1;
		}
		LOG_INF("USERAUTH_BANNER: \"%.*s\"", zephyr_ssh_banner.len, zephyr_ssh_banner.data);
		res = 0;
		break;
	}
	case SSH_MSG_USERAUTH_PK_OK: {
		LOG_INF("USERAUTH_PK_OK");
		// This is currently not used (see ssh_auth_send_userauth_request_pubkey)
		res = -1;
		break;
	}
#endif
	default:
		break;
	}

	return res;
}

#ifdef CONFIG_SSH_SERVER
static int send_userauth_failure(struct ssh_transport *transport, bool partial_success)
{
	int res;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);

	struct ssh_string auths_allowed_name_list[ARRAY_SIZE(auth_methods)];
	uint32_t num_auths_allowed = 0;
	for (uint32_t i = 0; i < ARRAY_SIZE(auth_methods); i++) {
		// Auth method "none" MUST NOT be listed as supported by the server.
		if (i == SSH_AUTH_NONE) {
			continue;
		}
		if ((BIT(i) & transport->auths_allowed_mask) != 0) {
			auths_allowed_name_list[num_auths_allowed++] = auth_methods[i];
		}
	}

	if (!ssh_payload_skip_bytes(&payload, SSH_PKT_MSG_ID_OFFSET) ||
	    !ssh_payload_write_byte(&payload, SSH_MSG_USERAUTH_FAILURE) ||
	    !ssh_payload_write_name_list(&payload, auths_allowed_name_list, num_auths_allowed) ||
	    !ssh_payload_write_bool(&payload, partial_success)) {
		return -ENOBUFS;
	}

	res = ssh_transport_send_packet(transport, &payload);
	if (res < 0) {
		LOG_WRN("Failed to send USERAUTH_FAILURE %d", res);
	}
	return res;
}

static int send_userauth_success(struct ssh_transport *transport)
{
	int res;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);

	if (!ssh_payload_skip_bytes(&payload, SSH_PKT_MSG_ID_OFFSET) ||
	    !ssh_payload_write_byte(&payload, SSH_MSG_USERAUTH_SUCCESS)) {
		return -ENOBUFS;
	}

	res = ssh_transport_send_packet(transport, &payload);
	if (res < 0) {
		LOG_WRN("Failed to send USERAUTH_SUCCESS %d", res);
	}
	return res;
}

static int send_userauth_banner(struct ssh_transport *transport)
{
	int res;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);
	static const struct ssh_string language_tag = SSH_STRING_LITERAL("");
	static const struct ssh_string zephyr_ssh_banner = SSH_STRING_LITERAL(ZEPHYR_SSH_BANNER);

	if (!ssh_payload_skip_bytes(&payload, SSH_PKT_MSG_ID_OFFSET) ||
	    !ssh_payload_write_byte(&payload, SSH_MSG_USERAUTH_BANNER) ||
	    !ssh_payload_write_string(&payload, &zephyr_ssh_banner) ||
	    !ssh_payload_write_string(&payload, &language_tag)) {
		return -ENOBUFS;
	}

	res = ssh_transport_send_packet(transport, &payload);
	if (res < 0) {
		LOG_WRN("Failed to send USERAUTH_BANNER %d", res);
	}
	return res;
}

static int send_userauth_pk_ok(struct ssh_transport *transport,
			       const struct ssh_string *pub_key_alg,
			       const struct ssh_string *pub_key)
{
	int res;
	SSH_PAYLOAD_BUF(payload, transport->tx_buf);

	if (!ssh_payload_skip_bytes(&payload, SSH_PKT_MSG_ID_OFFSET) ||
	    !ssh_payload_write_byte(&payload, SSH_MSG_USERAUTH_PK_OK) ||
	    !ssh_payload_write_string(&payload, pub_key_alg) ||
	    !ssh_payload_write_string(&payload, pub_key)) {
		return -ENOBUFS;
	}

	res = ssh_transport_send_packet(transport, &payload);
	if (res < 0) {
		LOG_WRN("Failed to send USERAUTH_PK_OK %d", res);
	}
	return res;
}
#endif