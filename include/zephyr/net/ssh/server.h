/*
* Copyright (c) 2024 Grant Ramsay <grant.ramsay@hotmail.com>
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef ZEPHYR_INCLUDE_NET_SSH_SERVER_H_
#define ZEPHYR_INCLUDE_NET_SSH_SERVER_H_

/**
* @file server.h
*
* @brief SSH server API
*
* @defgroup ssh_server SSH server API
* @ingroup networking
* @{
*/

#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/ssh/common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ssh_server;

// typedef int (*ssh_server_channel_request_callback_t)(
//	struct ssh_server *ssh_server, struct ssh_channel *channel,
//	enum ssh_channel_request_type type, struct ssh_channel_callbacks *channel_callbacks,
//	void **channel_callback_user_data, void *user_data);

struct ssh_server_event {
	enum ssh_server_event_type {
		SSH_SERVER_EVENT_CLOSED,
		SSH_SERVER_EVENT_CLIENT_CONNECTED,
		SSH_SERVER_EVENT_CLIENT_DISCONNECTED
	} type;
	union {
		struct ssh_server_event_client_connected {
			struct ssh_transport *transport;
		} client_connected;
		struct ssh_server_event_client_disconnected {
			struct ssh_transport *transport;
		} client_disconnected;
	};
};

typedef int (*ssh_server_event_callback_t)(struct ssh_server *ssh_server, const struct ssh_server_event *event, void *user_data);

struct ssh_server *ssh_server_instance(int instance);

// Set password to NULL or empty string to disable password auth
int ssh_server_start(struct ssh_server *ssh_server, const struct sockaddr_in *bind_addr,
		     int host_key_index, const char *password,
		     const int *authorized_keys, size_t authorized_keys_len,
		     ssh_server_event_callback_t server_callback,
		     ssh_transport_event_callback_t transport_callback, void *user_data);

int ssh_server_stop(struct ssh_server *ssh_server);


#ifdef __cplusplus
}
#endif

/**
* @}
*/

#endif
