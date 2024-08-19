/*
* Copyright (c) 2024 Grant Ramsay <grant.ramsay@hotmail.com>
*
* SPDX-License-Identifier: Apache-2.0
*/
#include <zephyr/net/ssh/server.h>

#include "ssh_connection.h"
#include "ssh_transport.h"

#include <zephyr/zvfs/eventfd.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(ssh, CONFIG_NET_SSH_LOG_LEVEL);

static void ssh_server_thread_entry(void *p1, void *p2, void *p3);
static int ssh_server_thread_run(struct ssh_server *ssh_server);

static struct ssh_server ssh_server_instances[CONFIG_SSH_SERVER_MAX_SERVERS];

struct ssh_server *ssh_server_instance(int instance)
{
	if (instance < ARRAY_SIZE(ssh_server_instances)) {
		return &ssh_server_instances[instance];
	}

	return NULL;
}

int ssh_server_start(struct ssh_server *ssh_server, const struct sockaddr_in *bind_addr,
		     int host_key_index, const char *password,
		     const int *authorized_keys, size_t authorized_keys_len,
		     ssh_server_event_callback_t server_callback,
		     ssh_transport_event_callback_t transport_callback, void *user_data)
{
	if (password == NULL) {
		password = "";
	}
	if (ssh_server == NULL || bind_addr == NULL || host_key_index < 0 ||
	    server_callback == NULL || transport_callback == NULL ||
	    strlen(password) > sizeof(ssh_server->password) - 1 ||
	    authorized_keys_len > ARRAY_SIZE(ssh_server->authorized_keys)) {
		return -EINVAL;
	}
	if (ssh_server->running) {
		return -EALREADY;
	}

	*ssh_server = (struct ssh_server) {
		.bind_addr = *bind_addr,
		.host_key_index = host_key_index,
		.server_callback = server_callback,
		.transport_callback = transport_callback,
		.callback_user_data = user_data,
		.authorized_keys_len = authorized_keys_len,
	};
	strcpy(ssh_server->password, password);
	memcpy(ssh_server->authorized_keys, authorized_keys, authorized_keys_len * sizeof(authorized_keys[0]));

	k_thread_create(&ssh_server->thread, ssh_server->thread_stack,
			K_KERNEL_STACK_SIZEOF(ssh_server->thread_stack),
			ssh_server_thread_entry, ssh_server, NULL, NULL,
			5, 0, K_FOREVER);
	k_thread_name_set(&ssh_server->thread, "ssh_server");
	k_thread_start(&ssh_server->thread);

	return 0;
}

static void ssh_server_thread_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	struct ssh_server *ssh_server = p1;
	int res = ssh_server_thread_run(ssh_server);
	ARG_UNUSED(res);

	struct ssh_server_event event;
	event.type = SSH_SERVER_EVENT_CLOSED;
	ssh_server->server_callback(ssh_server, &event, ssh_server->callback_user_data);
}

static int ssh_server_thread_run(struct ssh_server *ssh_server)
{
	int res;
	const struct sockaddr_in *bind_addr = &ssh_server->bind_addr;

	LOG_INF("Starting SSH Server");

	ssh_server->eventfd = zvfs_eventfd(0, 0);
	if (ssh_server->eventfd < 0) {
		LOG_ERR("Failed to create eventfd: %d", errno);
		return -1;
	}

	ssh_server->sock = zsock_socket(bind_addr->sin_family, SOCK_STREAM, IPPROTO_TCP);
	if (ssh_server->sock < 0) {
		LOG_ERR("Failed to create TCP socket: %d", errno);
		zsock_close(ssh_server->eventfd);
		return -1;
	}

	res = zsock_bind(ssh_server->sock, (struct sockaddr *)bind_addr, sizeof(*bind_addr));
	if (res < 0) {
		LOG_ERR("Failed to bind TCP socket: %d", errno);
		zsock_close(ssh_server->sock);
		zsock_close(ssh_server->eventfd);
		return -1;
	}

	res = zsock_listen(ssh_server->sock, 1);
	if (res < 0) {
		LOG_ERR("Failed to listen on TCP socket: %d", errno);
		zsock_close(ssh_server->sock);
		zsock_close(ssh_server->eventfd);
		return -1;
	}

	struct zsock_pollfd fds[2 + CONFIG_SSH_SERVER_MAX_CLIENTS] = {
		{.fd = ssh_server->sock, .events = ZSOCK_POLLIN},
		{.fd = ssh_server->eventfd, .events = ZSOCK_POLLIN}
	};
	BUILD_ASSERT(CONFIG_NET_SOCKETS_POLL_MAX >= ARRAY_SIZE(fds));

	for (int i = 2; i < ARRAY_SIZE(fds); i++) {
		fds[i].fd = -1;
	}

	// Wake up every 10 seconds to check timeouts
	const int timeout = 10000;

	ssh_server->running = true;
	LOG_INF("Waiting for connection...");

	while (true) {
		res = zsock_poll(fds, ARRAY_SIZE(fds), timeout);
		if (res < 0) {
			LOG_ERR("Poll error (%d)", errno);
			res = -errno;
			break;
		}

		if (fds[0].revents & ZSOCK_POLLIN) {
			struct sockaddr_in client_addr;
			socklen_t client_addr_len = sizeof(client_addr);
			int client_sock = zsock_accept(ssh_server->sock, (struct sockaddr *)&client_addr,
						       &client_addr_len);
			if (client_sock < 0) {
				LOG_ERR("Accept error (%d)", errno);
				res = -1;
				break;
			}

			struct ssh_transport *transport = NULL;
			for (int i = 2; i < ARRAY_SIZE(fds); i++) {
				if (fds[i].fd == -1) {
					fds[i] = (struct zsock_pollfd){.fd = client_sock, .events = ZSOCK_POLLIN};
					transport = &ssh_server->transport[i-2];
					break;
				}
			}

			char str[32];
			zsock_inet_ntop(client_addr.sin_family, &client_addr.sin_addr, str, sizeof(str));
			if (transport != NULL) {
				res = ssh_transport_start(
					transport, true, ssh_server, client_sock, &client_addr,
					ssh_server->host_key_index, ssh_server->transport_callback,
					ssh_server->callback_user_data);
				if (res == 0) {
					LOG_INF("Connected %s:%d", str,
						htons(client_addr.sin_port));

					struct ssh_server_event event;
					event.type = SSH_SERVER_EVENT_CLIENT_CONNECTED;
					event.client_connected.transport = transport;
					ssh_server->server_callback(ssh_server, &event, ssh_server->callback_user_data);
				} else {
					LOG_WRN("Failed to init connection %s:%d", str,
						htons(client_addr.sin_port));
					ssh_transport_close(transport);
					zsock_close(transport->sock);
				}
			} else {
				LOG_INF("Too many connections, refusing %s:%d", str,
					htons(client_addr.sin_port));
				zsock_close(client_sock);
			}
		}
		if (fds[1].revents) {
			zvfs_eventfd_t value;
			zvfs_eventfd_read(ssh_server->eventfd, &value);
			if (ssh_server->stopping) {
				// Requested stop
				res = 0;
				break;
			}
		}
		for (int i = 2; i < ARRAY_SIZE(fds); i++) {
			if (fds[i].fd >= 0 && fds[i].revents) {
				struct ssh_transport *transport = &ssh_server->transport[i-2];
				res = ssh_transport_input(transport);
				if (res < 0) {
					struct ssh_server_event event;
					event.type = SSH_SERVER_EVENT_CLIENT_DISCONNECTED;
					event.client_disconnected.transport = transport;
					ssh_server->server_callback(ssh_server, &event, ssh_server->callback_user_data);

					zsock_close(transport->sock);
					ssh_transport_close(transport);
					fds[i].fd = -1;
				}
			}
		}

		// Update the transport
		for (int i = 0; i < ARRAY_SIZE(ssh_server->transport); i++) {
			struct ssh_transport *transport = &ssh_server->transport[i];
			if (!transport->running) {
				continue;
			}
			res = ssh_transport_update(transport);
			if (res != 0) {
				struct ssh_server_event event;
				event.type = SSH_SERVER_EVENT_CLIENT_DISCONNECTED;
				event.client_disconnected.transport = transport;
				ssh_server->server_callback(ssh_server, &event, ssh_server->callback_user_data);

				zsock_close(transport->sock);
				ssh_transport_close(transport);
				fds[i+2].fd = -1;
			}
		}
	}

	for (int i = 0; i < ARRAY_SIZE(ssh_server->transport); i++) {
		struct ssh_transport *transport = &ssh_server->transport[i];
		if (!transport->running) {
			continue;
		}

		struct ssh_server_event event;
		event.type = SSH_SERVER_EVENT_CLIENT_DISCONNECTED;
		event.client_disconnected.transport = transport;
		ssh_server->server_callback(ssh_server, &event, ssh_server->callback_user_data);

		zsock_close(transport->sock);
		ssh_transport_close(transport);
	}
	zsock_close(ssh_server->sock);
	zsock_close(ssh_server->eventfd);

	ssh_server->running = false;

	return res;
}

int ssh_server_stop(struct ssh_server *ssh_server)
{
	if (!ssh_server->running) {
		return -EALREADY;
	}
	ssh_server->stopping = true;
	// Wake up the thread
	zvfs_eventfd_t value = 1;
	int res = zvfs_eventfd_write(ssh_server->eventfd, value);
	if (res == 0) {
		(void)k_thread_join(&ssh_server->thread, K_FOREVER);
	}
	return res;
}
