/*
* Copyright (c) 2024 Grant Ramsay <grant.ramsay@hotmail.com>
*
* SPDX-License-Identifier: Apache-2.0
*/
#include <zephyr/net/ssh/client.h>

#include "ssh_auth.h"
#include "ssh_connection.h"
#include "ssh_transport.h"

#include <zephyr/zvfs/eventfd.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(ssh, CONFIG_NET_SSH_LOG_LEVEL);

static void ssh_client_thread_entry(void *p1, void *p2, void *p3);
static int ssh_client_thread_run(struct ssh_client *ssh_client);

static struct ssh_client ssh_client_instances[CONFIG_SSH_CLIENT_MAX_CLIENTS];

struct ssh_client *ssh_client_instance(int instance)
{
	if (instance < ARRAY_SIZE(ssh_client_instances)) {
		return &ssh_client_instances[instance];
	}

	return NULL;
}

int ssh_client_start(struct ssh_client *ssh_client, const char *user_name,
		     const struct sockaddr_in *addr, int host_key_index,
		     ssh_transport_event_callback_t callback, void *user_data)
{
	if (ssh_client == NULL || user_name == NULL || addr == NULL || callback == NULL) {
		return -EINVAL;
	}
	if (ssh_client->running) {
		return -EALREADY;
	}

	*ssh_client = (struct ssh_client) {
		.addr = *addr,
		.host_key_index = host_key_index,
		.callback = callback,
		.callback_user_data = user_data
	};
	size_t user_name_len = strlen(user_name);
	if (user_name_len + 1 >= ARRAY_SIZE(ssh_client->user_name)) {
		return -EINVAL;
	}
	memcpy(ssh_client->user_name, user_name, user_name_len + 1);

	k_thread_create(&ssh_client->thread, ssh_client->thread_stack,
			K_KERNEL_STACK_SIZEOF(ssh_client->thread_stack),
			ssh_client_thread_entry, ssh_client, NULL, NULL,
			5, 0, K_FOREVER);
	k_thread_name_set(&ssh_client->thread, "ssh_client");
	k_thread_start(&ssh_client->thread);

	return 0;
}

static void ssh_client_thread_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	struct ssh_client *ssh_client = p1;
	int res = ssh_client_thread_run(ssh_client);
	ARG_UNUSED(res);
}

static int ssh_client_thread_run(struct ssh_client *ssh_client)
{
	int res;
	const struct sockaddr_in *addr = &ssh_client->addr;
	struct ssh_transport *transport = &ssh_client->transport;

	LOG_INF("Starting SSH Client");

	ssh_client->eventfd = zvfs_eventfd(0, 0);
	if (ssh_client->eventfd < 0) {
		LOG_ERR("Failed to create eventfd: %d", errno);
		return -1;
	}

	ssh_client->sock = zsock_socket(addr->sin_family, SOCK_STREAM, IPPROTO_TCP);
	if (ssh_client->sock < 0) {
		LOG_ERR("Failed to create TCP socket: %d", errno);
		zsock_close(ssh_client->eventfd);
		return -1;
	}

	res = zsock_connect(ssh_client->sock, (struct sockaddr *)addr, sizeof(*addr));
	if (res < 0) {
		LOG_WRN("Failed to connect TCP socket: %d", errno);
		zsock_close(ssh_client->sock);
		zsock_close(ssh_client->eventfd);
		return -1;
	}

	res = ssh_transport_start(transport, false, ssh_client, ssh_client->sock, addr, -1,
				  ssh_client->callback, ssh_client->callback_user_data);
	if (res == 0) {
//		LOG_INF("Connected %s:%d", str,
//			htons(client_addr.sin_port));
	} else {
//		LOG_WRN("Failed to init connection %s:%d", str,
//			htons(client_addr.sin_port));
		ssh_transport_close(transport);
		zsock_close(ssh_client->sock);
		zsock_close(ssh_client->eventfd);
		return -1;
	}

	struct zsock_pollfd fds[2] = {
		{.fd = ssh_client->sock, .events = ZSOCK_POLLIN},
		{.fd = ssh_client->eventfd, .events = ZSOCK_POLLIN}
	};
	// Wake up every 10 seconds to check timeouts
	const int timeout = 10000;

	ssh_client->running = true;

	while (true) {
		res = zsock_poll(fds, ARRAY_SIZE(fds), timeout);
		if (res < 0) {
			LOG_ERR("Poll error (%d)", errno);
			res = -errno;
			break;
		}

		if (fds[0].revents) {
			res = ssh_transport_input(transport);
			if (res < 0) {
				break;
			}
		}
		if (fds[1].revents) {
			zvfs_eventfd_t value;
			zvfs_eventfd_read(ssh_client->eventfd, &value);
			if (ssh_client->stopping) {
				// Requested stop
				res = 0;
				break;
			}
		}

		// Update the transport
		res = ssh_transport_update(transport);
		if (res != 0) {
			break;
		}
	}

	ssh_transport_close(transport);
	zsock_close(ssh_client->sock);
	zsock_close(ssh_client->eventfd);

	ssh_client->running = false;

	return res;
}

int ssh_client_stop(struct ssh_client *ssh_client)
{
	if (!ssh_client->running) {
		return -EALREADY;
	}
	ssh_client->stopping = true;
	// Wake up the thread
	zvfs_eventfd_t value = 1;
	int res = zvfs_eventfd_write(ssh_client->eventfd, value);
	if (res == 0) {
		(void)k_thread_join(&ssh_client->thread, K_FOREVER);
	}
	return res;
}
