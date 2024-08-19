#include "ssh_core.h"

#include <zephyr/random/random.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ssh, CONFIG_NET_SSH_LOG_LEVEL);

// TODO: Merge this tiny file into something else?

int ssh_mbedtls_rand(void *rng_state, unsigned char *output, size_t len)
{
	ARG_UNUSED(rng_state);
	return sys_csrand_get(output, len);
}
