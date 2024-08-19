/*
* Copyright (c) 2024 Grant Ramsay <grant.ramsay@hotmail.com>
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef ZEPHYR_INCLUDE_NET_SSH_CLIENT_H_
#define ZEPHYR_INCLUDE_NET_SSH_CLIENT_H_

/**
* @file client.h
*
* @brief SSH client API
*
* @defgroup ssh_client SSH client API
* @ingroup networking
* @{
*/

#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/ssh/common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ssh_client;

struct ssh_client *ssh_client_instance(int instance);

int ssh_client_start(struct ssh_client *ssh_client, const char *user_name,
		     const struct sockaddr_in *addr, int host_key_index,
		     ssh_transport_event_callback_t callback, void *user_data);

int ssh_client_stop(struct ssh_client *ssh_client);

int ssh_client_write_channel_data(struct ssh_client *ssh_client, uint32_t channel_number, const void *data, uint32_t len);

#ifdef __cplusplus
}
#endif

/**
* @}
*/

#endif
