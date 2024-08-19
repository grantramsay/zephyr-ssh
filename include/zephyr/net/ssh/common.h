/*
* Copyright (c) 2024 Grant Ramsay <grant.ramsay@hotmail.com>
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef ZEPHYR_INCLUDE_NET_SSH_COMMON_H_
#define ZEPHYR_INCLUDE_NET_SSH_COMMON_H_

/**
* @file common.h
*
* @brief SSH client/server common API
*
* @defgroup ssh_common SSH client/server common API
* @ingroup networking
* @{
*/

#include <zephyr/kernel.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ssh_transport;
struct ssh_channel;

enum ssh_auth_type {
	SSH_AUTH_NONE,
	SSH_AUTH_PASSWORD,
	SSH_AUTH_PUBKEY
};

enum ssh_channel_request_type {
	SSH_CHANNEL_REQUEST_UNKNOWN,
	SSH_CHANNEL_REQUEST_PSEUDO_TERMINAL,
	SSH_CHANNEL_REQUEST_X11_FORWARD,
	SSH_CHANNEL_REQUEST_ENV_VAR,
	SSH_CHANNEL_REQUEST_SHELL,
	SSH_CHANNEL_REQUEST_EXEC,
	SSH_CHANNEL_REQUEST_SUBSYSTEM,
	SSH_CHANNEL_REQUEST_WINDOW_CHANGE,
	SSH_CHANNEL_REQUEST_FLOW_CONTROL,
	SSH_CHANNEL_REQUEST_SIGNAL,
	SSH_CHANNEL_REQUEST_EXIT_STATUS,
	SSH_CHANNEL_REQUEST_EXIT_SIGNAL
};

//typedef int (*ssh_channel_opened_callback_t)(struct ssh_channel *channel, void *user_data);
//typedef int (*ssh_channel_data_ready_callback_t)(struct ssh_channel *channel);
//typedef int (*ssh_channel_ext_data_ready_callback_t)(struct ssh_channel *channel);
//typedef int (*ssh_channel_eof_callback_t)(struct ssh_channel *channel, void *user_data);
//typedef void (*ssh_channel_closed_callback_t)(struct ssh_channel *channel, void *user_data);
//
//struct ssh_channel_callbacks {
//	ssh_channel_opened_callback_t opened;
//	ssh_channel_data_ready_callback_t data_ready;
//	ssh_channel_ext_data_ready_callback_t data_ready;
//	ssh_channel_eof_callback_t eof;
//	ssh_channel_closed_callback_t closed;
//};

struct ssh_channel_event {
	enum ssh_channel_event_type {
		SSH_CHANNEL_EVENT_OPEN_RESULT,		// Client only
		SSH_CHANNEL_EVENT_REQUEST,		// Server only
		SSH_CHANNEL_EVENT_REQUEST_RESULT,	// Client only
		SSH_CHANNEL_EVENT_RX_DATA_READY,
		SSH_CHANNEL_EVENT_TX_DATA_READY,
		SSH_CHANNEL_EVENT_RX_STDERR_DATA_READY,
		SSH_CHANNEL_EVENT_EOF,
		SSH_CHANNEL_EVENT_CLOSED
	} type;
	union {
		struct ssh_channel_event_channel_request {
			enum ssh_channel_request_type type;
			bool want_reply;
			// TODO: Union of request type data
		} channel_request;
		struct ssh_channel_event_channel_request_result {
			bool success;
		} channel_request_result;
	};
};
typedef int (*ssh_channel_event_callback_t)(struct ssh_channel *channel, const struct ssh_channel_event *event, void *user_data);

struct ssh_transport_event {
	enum ssh_transport_event_type {
		SSH_TRANSPORT_EVENT_CLOSED,
		SSH_TRANSPORT_EVENT_SERVICE_ACCEPTED,		// Client only
//		SSH_TRANSPORT_EVENT_AUTHENTICATE_REQUEST,	// Server only
		SSH_TRANSPORT_EVENT_AUTHENTICATE_RESULT,	// Client only
		SSH_TRANSPORT_EVENT_CHANNEL_OPEN,		// Server only
	} type;
	union {
//		struct ssh_transport_event_authenticate_attempt {
//			bool success;
//		} authenticate_attempt;
		struct ssh_transport_event_authenticate_result {
			bool success;
		} authenticate_result;
		struct ssh_transport_event_channel_open {
			struct ssh_channel *channel;
		} channel_open;
	};
};

typedef int (*ssh_transport_event_callback_t)(struct ssh_transport *transport, const struct ssh_transport_event *event, void *user_data);

#define SSH_EXTENDED_DATA_STDERR 1

#ifdef CONFIG_SSH_CLIENT
const char *ssh_transport_client_user_name(struct ssh_transport *transport);
int ssh_transport_auth_password(struct ssh_transport *transport, const char *user_name, const char *password);
int ssh_transport_channel_open(struct ssh_transport *transport, ssh_channel_event_callback_t callback, void *user_data);
#endif

#ifdef CONFIG_SSH_SERVER
int ssh_channel_open_result(struct ssh_channel *channel, bool success,
			    ssh_channel_event_callback_t callback, void *user_data);
#endif
int ssh_channel_request_result(struct ssh_channel *channel, bool success);

#ifdef CONFIG_SSH_CLIENT
int ssh_channel_request_shell(struct ssh_channel *channel);
#endif

int ssh_channel_read(struct ssh_channel *channel, void *data, uint32_t len);
int ssh_channel_write(struct ssh_channel *channel, const void *data, uint32_t len);
int ssh_channel_read_stderr(struct ssh_channel *channel, void *data, uint32_t len);
int ssh_channel_write_stderr(struct ssh_channel *channel, const void *data, uint32_t len);
int ssh_channel_eof(struct ssh_channel *channel); // i.e. shutdown(SHUT_WR)
int ssh_channel_close(struct ssh_channel *channel);

#ifdef __cplusplus
}
#endif

/**
* @}
*/

#endif
