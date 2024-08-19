/*
* Copyright (c) 2024 Grant Ramsay <grant.ramsay@hotmail.com>
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <zephyr/kernel.h>
#include <zephyr/net/ssh/keygen.h>
#include <zephyr/shell/shell.h>
#include <zephyr/settings/settings.h>

#include <stdio.h>
#include <stdlib.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(ssh_sample, LOG_LEVEL_INF);

#define CTRL_C 0x03

struct key_load_param {
	void *data;
	size_t len; // Max len in, actual len out
};

static uint8_t key_buf[2048];
static int pubkey_import_key_id;
static size_t pubkey_import_len;

static int settings_load_key_cb(
	const char      *key,
	size_t           len,
	settings_read_cb read_cb,
	void            *cb_arg,
	void            *param)
{
	struct key_load_param *load_param = param;
	ssize_t read = read_cb(cb_arg, load_param->data, load_param->len);
	if (read < 0) {
		return (int)read;
	}
	load_param->len = read;
	return 0;
}

static int sample_keygen_init(void)
{
	int res = settings_subsys_init();
	if (res != 0) {
		LOG_ERR("Failed to init settings subsys: %d", res);
	}
	return res;
}

static int cmd_key_gen(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	int res;
	int key_id = strtol(argv[1], NULL, 10);
	const char *key_type_str = argv[2];
	int key_bits = strtol(argv[3], NULL, 10);
	enum ssh_host_key_type key_type;

	if (strcmp(key_type_str, "rsa") == 0) {
		key_type = SSH_HOST_KEY_TYPE_RSA;
	} else {
		shell_error(sh, "Unsupported key type: \"%s\"", key_type_str);
		return -EINVAL;
	}

	res = ssh_keygen(key_id, key_type, key_bits);
	if (res != 0) {
		shell_error(sh, "Failed to generate ssh key");
	}

	return res;
}

static int cmd_key_free(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	int key_id = strtol(argv[1], NULL, 10);

	int res = ssh_keygen_free(key_id);
	if (res != 0) {
		shell_error(sh, "Failed to free ssh key");
	}

	return res;
}

static int cmd_key_save(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	int res;
	int key_id = strtol(argv[1], NULL, 10);
	const char *key_type = argv[2];
	const char *key_name = argv[3];
	char setting_name[64];

	if (snprintf(setting_name, sizeof(setting_name), "ssh/keys/%s", key_name) >= sizeof(setting_name)) {
		return -EINVAL;
	}

	bool private_key;
	if (strcmp(key_type, "pub") == 0) {
		private_key = false;
	} else if (strcmp(key_type, "priv") == 0) {
		private_key = true;
	} else {
		shell_error(sh, "Invalid key type");
		return -EINVAL;
	}
	res = ssh_keygen_export(key_id, private_key, SSH_HOST_KEY_FORMAT_DER, key_buf, sizeof(key_buf));
	if (res < 0) {
		shell_error(sh, "Key export failed: %d", res);
		return res;
	}

	res = settings_save_one(setting_name, key_buf, res);
	if (res != 0) {
		LOG_ERR("Save setting failed: %d", res);
		return res;
	}
	LOG_INF("Saved %s key: %s (#%d)", key_type, key_name, key_id);

	return 0;
}

static int cmd_key_load(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	int res;
	int key_id = strtol(argv[1], NULL, 10);
	const char *key_type = argv[2];
	const char *key_name = argv[3];
	char setting_name[64];

	if (snprintf(setting_name, sizeof(setting_name), "ssh/keys/%s", key_name) >= sizeof(setting_name)) {
		return -EINVAL;
	}

	struct key_load_param load_param = {
		.data = key_buf,
		.len = sizeof(key_buf)
	};
	res = settings_load_subtree_direct(setting_name, settings_load_key_cb, &load_param);
	if (res != 0) {
		LOG_ERR("Load setting failed: %d", res);
	}

	bool private_key;
	if (strcmp(key_type, "pub") == 0) {
		private_key = false;
	} else if (strcmp(key_type, "priv") == 0) {
		private_key = true;
	} else {
		shell_error(sh, "Invalid key type");
		return -EINVAL;
	}
	res = ssh_keygen_import(key_id, private_key, SSH_HOST_KEY_FORMAT_DER, key_buf, load_param.len);
	if (res < 0) {
		shell_error(sh, "Key import failed: %d", res);
		return res;
	}
	LOG_INF("Loaded %s key: %s (#%d)", key_type, key_name, key_id);

	return 0;
}

static int cmd_pubkey_export(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	int res;
	int key_id = strtol(argv[1], NULL, 10);

	res = ssh_keygen_export(key_id, false, SSH_HOST_KEY_FORMAT_PEM, key_buf, sizeof(key_buf));
	if (res != 0) {
		shell_error(sh, "Key export failed: %d", res);
		return res;
	}

	shell_print(sh, "%s", key_buf);

	return 0;
}

static void shell_bypass_pubkey_import(const struct shell *sh, uint8_t *data, size_t len)
{
	shell_fprintf(sh, SHELL_NORMAL, "%.*s", len, data);

	if (pubkey_import_len + len >= sizeof(key_buf)) {
		shell_error(sh, "Key too big");
		shell_set_bypass(sh, NULL);
		return;
	}

	memcpy(&key_buf[pubkey_import_len], data, len);
	pubkey_import_len += len;

	if (key_buf[pubkey_import_len - 1] == CTRL_C) {
		key_buf[pubkey_import_len - 1] = '\0';
		int res = ssh_keygen_import(pubkey_import_key_id, false, SSH_HOST_KEY_FORMAT_PEM, key_buf, pubkey_import_len);
		if (res == 0) {
			shell_info(sh, "\nKey import success");
		} else {
			shell_error(sh, "\nKey import failed: %d", res);
		}
		shell_set_bypass(sh, NULL);
	}
}

static int cmd_pubkey_import(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	int key_id = strtol(argv[1], NULL, 10);

	pubkey_import_key_id = key_id;
	pubkey_import_len = 0;

	shell_set_bypass(sh, shell_bypass_pubkey_import);
	shell_info(sh, "Enter public key in PEM format followed by Ctrl+C:");

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	sub_ssh_key_pub,
	SHELL_CMD_ARG(export, NULL, "<key-id>", cmd_pubkey_export, 2, 0),
	SHELL_CMD_ARG(import, NULL, "<key-id>", cmd_pubkey_import, 2, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(
	sub_ssh_key,
	SHELL_CMD_ARG(gen, NULL, "<key-id> <type> <bits>", cmd_key_gen, 4, 0),
	SHELL_CMD_ARG(free, NULL, "<key-id>", cmd_key_free, 2, 0),
	SHELL_CMD_ARG(save, NULL, "<key-id> <pub|priv> <key-name>", cmd_key_save, 4, 0),
	SHELL_CMD_ARG(load, NULL, "<key-id> <pub|priv> <key-name>", cmd_key_load, 4, 0),
	SHELL_CMD(pub, &sub_ssh_key_pub, "SSH public key commands", NULL),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(ssh_key, &sub_ssh_key, "SSH keygen commands", NULL);

SYS_INIT(sample_keygen_init, APPLICATION, 0);
