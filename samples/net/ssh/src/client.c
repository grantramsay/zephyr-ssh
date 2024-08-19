/*
* Copyright (c) 2024 Grant Ramsay <grant.ramsay@hotmail.com>
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <zephyr/kernel.h>
#include <zephyr/net/ssh/client.h>
#include <zephyr/shell/shell.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(ssh_sample, LOG_LEVEL_INF);

// TODO: Why isn't this in <string.h>?
char *strtok_r(char *str, const char *delim, char **saveptr);

#define DEFAULT_SSH_PORT 22

static int ssh_client_transport_event_callback(struct ssh_transport *transport, const struct ssh_transport_event *event, void *user_data);
static int ssh_client_channel_event_callback(struct ssh_channel *channel, const struct ssh_channel_event *event, void *user_data);

// TODO: Shell bypass could be done using a stack data structure
// For now it's just single instance and would break if bypassed multiple times
static struct ssh_transport *shell_bypass_ssh_transport = NULL;
static struct ssh_channel *shell_bypass_ssh_channel = NULL;
static uint8_t password_buff[32 + 1];
static int password_len = 0;

static void shell_bypass_password(const struct shell *sh, uint8_t *data, size_t len)
{
	while (len--) {
		uint8_t c = *data++;
		if (c == '\r' || c == '\n' || password_len >= sizeof(password_buff) - 1) {
			password_buff[password_len] = 0;
			shell_set_bypass(sh, NULL);
			struct ssh_transport *transport = shell_bypass_ssh_transport;
			if (transport != NULL) {
				const char *user_name = ssh_transport_client_user_name(transport);
				(void)ssh_transport_auth_password(
					transport, user_name, password_buff);
			}
			// mbedtls_platform_zeroize(password_buff, sizeof(password_buff));
			memset(password_buff, 0, sizeof(password_buff));
			password_len = 0;
			shell_bypass_ssh_transport = NULL;
			break;
		}
		password_buff[password_len++] = c;
	}
}

static void shell_bypass_ssh_shell(const struct shell *sh, uint8_t *data, size_t len)
{
	if (shell_bypass_ssh_channel == NULL) {
		return;
	}
	int written = ssh_channel_write(shell_bypass_ssh_channel, data, len);
	ARG_UNUSED(written);
	//return written == len ? 0 : -1;
}

static int ssh_client_transport_event_callback(struct ssh_transport *transport, const struct ssh_transport_event *event, void *user_data)
{
	const struct shell *sh = user_data;

	switch (event->type) {
	case SSH_TRANSPORT_EVENT_SERVICE_ACCEPTED: {
		// Authenticate
		const char *user_name = ssh_transport_client_user_name(transport);
		password_len = 0;
		shell_bypass_ssh_transport = transport;
		shell_set_bypass(sh, shell_bypass_password);
		shell_fprintf(sh, SHELL_INFO, "%s's password: ", user_name);
		return 0;

	}
	case SSH_TRANSPORT_EVENT_AUTHENTICATE_RESULT:
		if (event->authenticate_result.success) {
			// Open channel
			return ssh_transport_channel_open(transport, ssh_client_channel_event_callback, (void *)sh);
		}
		return -1;
	default:
		return -1;
	}

	return -1;

//	int res = -1;
//	const struct shell *sh = shell_backend_uart_get_ptr();
//	password_len = 0;
//	shell_set_bypass(sh, shell_bypass_password);
//	shell_fprintf(sh, SHELL_INFO, "%s's password: ", username);
//	k_sem_take(&password_sem, K_FOREVER);
//	if (password_len > 0) {
//		password_buff[password_len] = '\0';
//		res = ssh_client_auth_password(ssh_client, username, password_buff);
//	}
//	mbedtls_platform_zeroize(password_buff, sizeof(password_buff));
//	return res;
}

static int ssh_client_channel_event_callback(struct ssh_channel *channel, const struct ssh_channel_event *event, void *user_data)
{
	const struct shell *sh = user_data;

	switch (event->type) {
	case SSH_CHANNEL_EVENT_OPEN_RESULT: {
		LOG_INF("Client channel opened");
		return ssh_channel_request_shell(channel);
	}
	case SSH_CHANNEL_EVENT_REQUEST_RESULT: {
		// event->channel_request_result?
		LOG_INF("Client channel shell request complete");
		shell_bypass_ssh_channel = channel;
		shell_set_bypass(sh, shell_bypass_ssh_shell);

//		// Send some data
//		const char *data = "ls\n";
//		// const char *data = "echo \"Test stderr\" 1>&2\n";
//		uint32_t len = strlen(data);
//		int written = ssh_channel_write(channel, data, len);
//		return written == len ? 0 : -1;
	}
	case SSH_CHANNEL_EVENT_RX_DATA_READY: {
//		LOG_INF("Client channel RX data ready");
		uint8_t buff[64];
		while (true) {
			int len = ssh_channel_read(channel, buff, sizeof(buff));
			if (len <= 0) {
				return len;
			}
//			LOG_HEXDUMP_INF(buff, len, "Client channel data");
			shell_print_impl(sh, "%.*s", len, buff);
		}
		break;
	}
	case SSH_CHANNEL_EVENT_TX_DATA_READY:
		//LOG_INF("Client channel TX data ready");
		break;
	case SSH_CHANNEL_EVENT_RX_STDERR_DATA_READY: {
//		LOG_INF("Client channel RX ext data ready");
		uint8_t buff[64];
		while (true) {
			int len = ssh_channel_read_stderr(channel, buff, sizeof(buff));
			if (len <= 0) {
				return len;
			}
//			LOG_HEXDUMP_INF(buff, len, "Client channel ext data");
			shell_error_impl(sh, "%.*s", len, buff);
		}
		break;
	}
	case SSH_CHANNEL_EVENT_EOF:
		LOG_INF("Client channel EOF");
		break;
	case SSH_CHANNEL_EVENT_CLOSED:
		LOG_INF("Client channel closed");
		shell_set_bypass(sh, NULL);
		shell_bypass_ssh_channel = NULL;
		break;
	default:
		return -1;
	}

	return 0;
}

static int cmd_start(const struct shell *sh, size_t argc, char **argv)
{
	int res;
	struct sockaddr_in addr;
	int client_inst = strtol(argv[1], NULL, 10);
	char *user_at_addr_str = argv[2];
	int host_key_index = -1;
	uint16_t port = DEFAULT_SSH_PORT;
	if (argc > 3) {
		host_key_index = strtol(argv[3], NULL, 10);
	}
	if (argc > 4) {
		port = strtol(argv[4], NULL, 10);
	}

	char *tok_state;
	const char *user_name = strtok_r(user_at_addr_str, "@", &tok_state);
	const char *addr_str = strtok_r(NULL, "", &tok_state);

	// TODO: DNS lookup, IPv4 address only for now...

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	res = zsock_inet_pton(AF_INET, addr_str, &addr.sin_addr);
	if (res != 1) {
		shell_error(sh, "Failed to parse address");
		return -EINVAL;
	}

	struct ssh_client *ssh_client = ssh_client_instance(client_inst);
	if (ssh_client == NULL) {
		shell_error(sh, "Failed to get SSH client instance");
		return -EINVAL;
	}

	res = ssh_client_start(
		ssh_client, user_name, &addr, host_key_index,
		ssh_client_transport_event_callback, (void *)sh);
	if (res != 0) {
		shell_error(sh, "Failed to start SSH client: %d", res);
	}

	return res;
}

static int cmd_stop(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	int res;
	int client_inst = strtol(argv[1], NULL, 10);

	struct ssh_client *ssh_client = ssh_client_instance(client_inst);
	if (ssh_client == NULL) {
		shell_error(sh, "Failed to get SSH client instance");
		return -EINVAL;
	}

	res = ssh_client_stop(ssh_client);
	if (res != 0) {
		shell_error(sh, "Failed to stop SSH client: %d", res);
	}

	return res;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	sub_ssh,
	SHELL_CMD_ARG(start, NULL, "<inst> <user@addr> [<host-key-idx> <port>]", cmd_start, 3, 2),
	SHELL_CMD_ARG(stop, NULL, "<inst>", cmd_stop, 2, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(ssh, &sub_ssh, "SSH client commands", NULL);
