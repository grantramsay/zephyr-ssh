/*
* Copyright (c) 2024 Grant Ramsay <grant.ramsay@hotmail.com>
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <zephyr/kernel.h>

#include <zephyr/shell/shell_uart.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ssh_sample, LOG_LEVEL_INF);


int main(void)
{
	LOG_INF("SSH sample %s", CONFIG_BOARD_TARGET);

#if 0 // Testing/development code to autorun some commands
	int res;
	const struct shell *sh = shell_backend_uart_get_ptr();

	res = shell_execute_cmd(sh, "ssh_key load 0 priv id_rsa");
	if (res != 0) {
		LOG_WRN("Could not load host key, generating new key pair...");
		res = shell_execute_cmd(sh, "ssh_key gen 0 rsa 2048");
		if (res != 0) {
			LOG_ERR("Failed to generate host key");
			return res;
		}
		(void)shell_execute_cmd(sh, "ssh_key save 0 priv id_rsa");
	}
	(void)shell_execute_cmd(sh, "ssh_key pub export 0");

	res = shell_execute_cmd(sh, "ssh_key load 1 pub authorized_key_0");
	if (res == 0) {
		(void)shell_execute_cmd(sh, "sshd start 0 192.0.2.1 0 password1 22 1");
	} else {
		(void)shell_execute_cmd(sh, "sshd start 0 192.0.2.1 0 password1");
	}

//	(void)shell_execute_cmd(sh, "ssh start 0 test-user@192.0.2.2");
	(void)shell_execute_cmd(sh, "ssh start 0 test-user@192.0.2.2 0 22");
#endif

	while (true) {
		k_sleep(K_FOREVER);
	}

	return 0;
}
