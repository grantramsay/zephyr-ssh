/*
* Copyright (c) 2024 Grant Ramsay <grant.ramsay@hotmail.com>
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <zephyr/kernel.h>
#include <zephyr/net/ssh/server.h>
#include <zephyr/shell/shell.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(ssh_sample, LOG_LEVEL_INF);

#define DEFAULT_SSH_PORT 22

static int ssh_server_event_callback(struct ssh_server *ssh_server, const struct ssh_server_event *event, void *user_data);
static int ssh_server_transport_event_callback(struct ssh_transport *transport, const struct ssh_transport_event *event, void *user_data);
static int ssh_server_channel_event_callback(struct ssh_channel *channel, const struct ssh_channel_event *event, void *user_data);

// TODO: Move shell stuff to an SSH shell backend
#define SHELL_SSH_DEFINE(_name)						\
	static struct shell_ssh _name##_shell_ssh;			\
	struct shell_transport _name = {				\
		.api = &shell_ssh_transport_api,			\
		.ctx = &_name##_shell_ssh				\
	}

struct shell_ssh {
	shell_transport_handler_t handler;
	void *context;
	struct ssh_channel *ssh_channel;
};

static int shell_ssh_init(const struct shell_transport *transport,
			  const void *config,
			  shell_transport_handler_t evt_handler,
			  void *context)
{
	struct shell_ssh *sh_ssh = (struct shell_ssh *)transport->ctx;

	sh_ssh->handler = evt_handler;
	sh_ssh->context = context;
	sh_ssh->ssh_channel = (void *)config;

	return 0;
}

static int shell_ssh_uninit(const struct shell_transport *transport)
{
	ARG_UNUSED(transport);
	return 0;
}

static int shell_ssh_enable(const struct shell_transport *transport, bool blocking)
{
	ARG_UNUSED(transport);
	ARG_UNUSED(blocking);
	return 0;
}

static int shell_ssh_write(const struct shell_transport *transport,
			   const void *data, size_t length, size_t *cnt)
{
	struct shell_ssh *sh_ssh = (struct shell_ssh *)transport->ctx;

	int res = ssh_channel_write(sh_ssh->ssh_channel, data, length);
	if (res < 0) {
		return res;
	}
	*cnt = res;

	return 0;
}

static int shell_ssh_read(const struct shell_transport *transport,
			  void *data, size_t length, size_t *cnt)
{
	struct shell_ssh *sh_ssh = (struct shell_ssh *)transport->ctx;

	int res = ssh_channel_read(sh_ssh->ssh_channel, data, length);
	if (res < 0) {
		return res;
	}
	*cnt = res;
	return 0;
}

const struct shell_transport_api shell_ssh_transport_api = {
	.init = shell_ssh_init,
	.uninit = shell_ssh_uninit,
	.enable = shell_ssh_enable,
	.write = shell_ssh_write,
	.read = shell_ssh_read
};

#define CONFIG_SSH_SERVER_SHELL_PROMPT "zephyr:~$ "

// TODO: Make an array of these?
SHELL_SSH_DEFINE(shell_transport_ssh);
SHELL_DEFINE(shell_ssh, CONFIG_SSH_SERVER_SHELL_PROMPT, &shell_transport_ssh,
	     CONFIG_SHELL_BACKEND_SERIAL_LOG_MESSAGE_QUEUE_SIZE,
	     CONFIG_SHELL_BACKEND_SERIAL_LOG_MESSAGE_QUEUE_TIMEOUT,
	     SHELL_FLAG_OLF_CRLF);
/*
#define CONFIG_SSH_SERVER_SHELL_COUNT 4

#define SHELL_SSH_DEFINE_ALL(n, _) \
	SHELL_SSH_DEFINE(shell_transport_ssh_##n); \
	SHELL_DEFINE(shell_ssh_##n, CONFIG_SHELL_PROMPT_SSH, &shell_transport_ssh_##n, \
		     CONFIG_SHELL_BACKEND_SERIAL_LOG_MESSAGE_QUEUE_SIZE, \
		     CONFIG_SHELL_BACKEND_SERIAL_LOG_MESSAGE_QUEUE_TIMEOUT, \
		     SHELL_FLAG_OLF_CRLF);

LISTIFY(CONFIG_SSH_SHELL_COUNT, SHELL_SSH_DEFINE_ALL, (;))

#define SHELL_SSH_REFERENCE_ALL(n, _) \
	&shell_ssh_##n

static const struct shell *const ssh_shell_instances[] = {
	LISTIFY(CONFIG_SSH_SHELL_COUNT, SHELL_SSH_REFERENCE_ALL, (,))
};
*/




static int ssh_server_event_callback(struct ssh_server *ssh_server, const struct ssh_server_event *event, void *user_data)
{
	ARG_UNUSED(ssh_server);
	ARG_UNUSED(user_data);

	switch (event->type) {
	case SSH_SERVER_EVENT_CLOSED:
		LOG_INF("Server closed");
		break;
	case SSH_SERVER_EVENT_CLIENT_CONNECTED:
		LOG_INF("Server client connected");
		break;
	case SSH_SERVER_EVENT_CLIENT_DISCONNECTED:
		LOG_INF("Server client disconnected");
		break;
	default:
		return -1;
	}

	return 0;
}

static int ssh_server_transport_event_callback(struct ssh_transport *transport, const struct ssh_transport_event *event, void *user_data)
{
	ARG_UNUSED(transport);
	ARG_UNUSED(user_data);

	switch (event->type) {
	case SSH_TRANSPORT_EVENT_CHANNEL_OPEN:
		return ssh_channel_open_result(event->channel_open.channel, true,
					       ssh_server_channel_event_callback, NULL);
	default:
		break;
	}

	return 0;
}

static int ssh_server_channel_event_callback(struct ssh_channel *channel, const struct ssh_channel_event *event, void *user_data)
{
	ARG_UNUSED(user_data);

	switch (event->type) {
	case SSH_CHANNEL_EVENT_REQUEST: {
		LOG_INF("Server channel request");
		bool success = false;
		switch (event->channel_request.type) {
		case SSH_CHANNEL_REQUEST_SHELL: {
			static const struct shell_backend_config_flags cfg_flags =
				SHELL_DEFAULT_BACKEND_CONFIG_FLAGS;
			int res = shell_init(&shell_ssh, channel, cfg_flags,
					     false, LOG_LEVEL_NONE);
			if (res != 0) {
				LOG_ERR("shell_init error");
			}
			success = true;
			break;
		}
		case SSH_CHANNEL_REQUEST_PSEUDO_TERMINAL:
		case SSH_CHANNEL_REQUEST_ENV_VAR:
		case SSH_CHANNEL_REQUEST_WINDOW_CHANGE:
			// Pretend like we support these for now
			success = true;
			break;
		default:
			break;
		}
		if (event->channel_request.want_reply) {
			return ssh_channel_request_result(channel, success);
		}
		return 0;
	}
	case SSH_CHANNEL_EVENT_RX_DATA_READY: {
		struct shell_ssh *sh_ssh = &shell_transport_ssh_shell_ssh;
		sh_ssh->handler(SHELL_TRANSPORT_EVT_RX_RDY, sh_ssh->context);
		break;
	}
	case SSH_CHANNEL_EVENT_TX_DATA_READY: {
		struct shell_ssh *sh_ssh = &shell_transport_ssh_shell_ssh;
		sh_ssh->handler(SHELL_TRANSPORT_EVT_TX_RDY, sh_ssh->context);
		break;
	}
	case SSH_CHANNEL_EVENT_RX_STDERR_DATA_READY:
		LOG_INF("Server channel RX ext data ready");
		break;
	case SSH_CHANNEL_EVENT_EOF:
		LOG_INF("Server channel EOF");
		break;
	case SSH_CHANNEL_EVENT_CLOSED:
		LOG_INF("Server channel closed");
		shell_uninit(&shell_ssh, NULL);
		break;
	default:
		return -1;
	}

	return 0;
}

static int cmd_start(const struct shell *sh, size_t argc, char **argv)
{
	int res;
	struct sockaddr_in bind_addr;
	int server_inst = strtol(argv[1], NULL, 10);
	const char *bind_addr_str = argv[2];
	int host_key_index = strtol(argv[3], NULL, 10);
	const char *password = argv[4];
	int port = DEFAULT_SSH_PORT;
	int authorized_keys_index[CONFIG_SSH_MAX_HOST_KEYS];
	int authorized_keys_count = argc > 6 ? MIN(argc - 6, ARRAY_SIZE(authorized_keys_index)) : 0;

	if (argc > 5) {
		port = strtol(argv[5], NULL, 10);
	}

	for (int i = 0; i < authorized_keys_count; i++) {
		authorized_keys_index[i] = strtol(argv[6 + i], NULL, 10);
	}

	// TODO: DNS lookup, IPv4 address only for now...

	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port = htons(port);
	res = zsock_inet_pton(AF_INET, bind_addr_str, &bind_addr.sin_addr);
	if (res != 1) {
		shell_error(sh, "Failed to parse bind address");
		return -EINVAL;
	}

	struct ssh_server *ssh_server = ssh_server_instance(server_inst);
	if (ssh_server == NULL) {
		shell_error(sh, "Failed to get SSH server instance");
		return -EINVAL;
	}

	res = ssh_server_start(
		ssh_server, &bind_addr, host_key_index, password,
		authorized_keys_index, authorized_keys_count,
		ssh_server_event_callback, ssh_server_transport_event_callback, NULL);
	if (res != 0) {
		shell_error(sh, "Failed to start SSH server: %d", res);
	}

	return res;
}

static int cmd_stop(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	int res;
	int server_inst = strtol(argv[1], NULL, 10);

	struct ssh_server *ssh_server = ssh_server_instance(server_inst);
	if (ssh_server == NULL) {
		shell_error(sh, "Failed to get SSH server instance");
		return -EINVAL;
	}

	res = ssh_server_stop(ssh_server);
	if (res != 0) {
		shell_error(sh, "Failed to stop SSH server: %d", res);
	}

	return res;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	sub_sshd,
	SHELL_CMD_ARG(start, NULL,
		      "<inst> <bind-addr> <host-key-idx> <password> [<port> <auth-key-idx> <auth-key-idx> ...]",
		      cmd_start, 5, 1 + CONFIG_SSH_MAX_HOST_KEYS),
	SHELL_CMD_ARG(stop, NULL, "<inst>", cmd_stop, 2, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(sshd, &sub_sshd, "SSH server commands", NULL);
