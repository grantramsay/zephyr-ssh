/*
* Copyright (c) 2024 Grant Ramsay <grant.ramsay@hotmail.com>
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef ZEPHYR_INCLUDE_NET_SSH_KEYGEN_H_
#define ZEPHYR_INCLUDE_NET_SSH_KEYGEN_H_

/**
* @file server.h
*
* @brief SSH keygen API
*
* @defgroup ssh_keygen SSH keygen API
* @ingroup networking
* @{
*/

#include <zephyr/kernel.h>

#ifdef __cplusplus
extern "C" {
#endif

enum ssh_host_key_type {
#ifdef CONFIG_SSH_HOST_KEY_RSA
	SSH_HOST_KEY_TYPE_RSA,
#endif
};

enum ssh_host_key_format {
	SSH_HOST_KEY_FORMAT_DER,
	SSH_HOST_KEY_FORMAT_PEM,
};

int ssh_keygen(int key_index, enum ssh_host_key_type key_type, size_t key_size_bits);

int ssh_keygen_export(int key_index, bool private_key, enum ssh_host_key_format fmt, void *buf, size_t buf_len);
int ssh_keygen_import(int key_index, bool private_key, enum ssh_host_key_format fmt, const void *buf, size_t buf_len);

// Be careful that the key is not in use...
int ssh_keygen_free(int key_index);

int ssh_keygen_import_pubkey_openssh(int key_index, const uint8_t *key, size_t key_len);

#ifdef __cplusplus
}
#endif

/**
* @}
*/

#endif
