#include <zephyr/net/ssh/keygen.h>

#include "ssh_host_key.h"

#include <zephyr/sys/byteorder.h>

#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(ssh, CONFIG_NET_SSH_LOG_LEVEL);

struct ssh_host_key {
	bool in_use;
	enum ssh_host_key_type key_type;
	mbedtls_pk_context key;
};

struct host_key_alg_info {
	struct ssh_string signature_type_string;
	mbedtls_md_type_t mbedtls_md_type;
};

static int import_pubkey_blob(struct ssh_host_key *host_key, const struct ssh_string *pubkey_blob);
static void free_host_key(struct ssh_host_key *host_key);

static struct ssh_host_key ssh_host_key[CONFIG_SSH_MAX_HOST_KEYS];

static const struct host_key_alg_info host_key_alg_info[] = {
#ifdef CONFIG_SSH_HOST_KEY_ALG_RSA_SHA2_256
	[SSH_HOST_KEY_ALG_RSA_SHA2_256] = {
		.signature_type_string = SSH_STRING_LITERAL("rsa-sha2-256"),
		.mbedtls_md_type = MBEDTLS_MD_SHA256
	},
#endif
#ifdef CONFIG_SSH_HOST_KEY_ALG_RSA_SHA2_512
	[SSH_HOST_KEY_ALG_RSA_SHA2_512] = {
		.signature_type_string = SSH_STRING_LITERAL("rsa-sha2-512"),
		.mbedtls_md_type = MBEDTLS_MD_SHA512
	},
#endif
};

#define SSH_RSA_EXPONENT 65537

static const struct host_key_alg_info *get_host_key_alg_info(enum ssh_host_key_alg alg)
{
	switch (alg) {
#ifdef CONFIG_SSH_HOST_KEY_ALG_RSA_SHA2_256
	case SSH_HOST_KEY_ALG_RSA_SHA2_256:
#endif
#ifdef CONFIG_SSH_HOST_KEY_ALG_RSA_SHA2_512
	case SSH_HOST_KEY_ALG_RSA_SHA2_512:
#endif
		return &host_key_alg_info[alg];
	default:
		return NULL;
	}
}

static int signature_type_str_to_id(const struct ssh_string *signature_type)
{
	for (int i = 0; i < ARRAY_SIZE(host_key_alg_info); i++) {
		if (ssh_strings_equal(&host_key_alg_info[i].signature_type_string, signature_type)) {
			return i;
		}
	}
	return -ENOTSUP;
}

int ssh_keygen(int key_index, enum ssh_host_key_type key_type, size_t key_size_bits)
{
	int res;

	if (key_index < 0 || key_index >= ARRAY_SIZE(ssh_host_key) ||
	    key_size_bits < 1024 || key_size_bits > MBEDTLS_MPI_MAX_BITS) {
		return -EINVAL;
	}

	struct ssh_host_key *host_key = &ssh_host_key[key_index];
	if (host_key->in_use) {
		return -EALREADY;
	}

	switch (key_type) {
#ifdef CONFIG_SSH_HOST_KEY_RSA
	case SSH_HOST_KEY_TYPE_RSA:
#endif
		break;
	default:
		return -ENOTSUP;
	}

	mbedtls_pk_init(&host_key->key);

	res = mbedtls_pk_setup(&host_key->key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	if (res != 0) {
		LOG_ERR("RSA host key setup failed: %d", res);
		mbedtls_pk_free(&host_key->key);
		return -EIO;
	}
	res = mbedtls_rsa_gen_key(mbedtls_pk_rsa(host_key->key), ssh_mbedtls_rand, NULL, key_size_bits, SSH_RSA_EXPONENT);
	if (res != 0) {
		LOG_ERR("RSA host key gen failed: %d", res);
		mbedtls_pk_free(&host_key->key);
		return -EIO;
	}

	host_key->in_use = true;
	host_key->key_type = key_type;

	return 0;
}

int ssh_keygen_free(int key_index)
{
	if (key_index < 0 || key_index >= ARRAY_SIZE(ssh_host_key)) {
		return -EINVAL;
	}

	struct ssh_host_key *host_key = &ssh_host_key[key_index];
	if (!host_key->in_use) {
		return -EALREADY;
	}
	host_key->in_use = false;
	free_host_key(host_key);

	return 0;
}

int ssh_keygen_export(int key_index, bool private_key, enum ssh_host_key_format fmt, void *buf, size_t buf_len)
{
	int res;

	if (key_index < 0 || key_index >= ARRAY_SIZE(ssh_host_key)) {
		return -EINVAL;
	}

	struct ssh_host_key *host_key = &ssh_host_key[key_index];
	if (!host_key->in_use) {
		return -EINVAL;
	}

	if (fmt == SSH_HOST_KEY_FORMAT_DER) {
		if (private_key) {
			res = mbedtls_pk_write_key_der(&host_key->key, buf, buf_len);
		} else {
			res = mbedtls_pk_write_pubkey_der(&host_key->key, buf, buf_len);
		}
		if (res > 0) {
			// MBEDTLS writes to the end of the buffer, shift it back to the start
			memmove(buf, (uint8_t *)buf + buf_len - res, res);
		}
	} else if (fmt == SSH_HOST_KEY_FORMAT_PEM) {
		if (private_key) {
			res = mbedtls_pk_write_key_pem(&host_key->key, buf, buf_len);
		} else {
			res = mbedtls_pk_write_pubkey_pem(&host_key->key, buf, buf_len);
		}
	} else {
		return -EINVAL;
	}
	if (res < 0) {
		return -EIO;
	}

	return res;
}

int ssh_keygen_import(int key_index, bool private_key, enum ssh_host_key_format fmt, const void *buf, size_t buf_len)
{
	int res;
	// mbedtls_pk_parse_key parses either PEM or DER
	ARG_UNUSED(fmt);

	if (key_index < 0 || key_index >= ARRAY_SIZE(ssh_host_key)) {
		return -EINVAL;
	}

	struct ssh_host_key *host_key = &ssh_host_key[key_index];
	if (host_key->in_use) {
		return -EALREADY;
	}

	mbedtls_pk_init(&host_key->key);

	if (private_key) {
		res = mbedtls_pk_parse_key(&host_key->key, buf, buf_len, NULL, 0, ssh_mbedtls_rand, NULL);
	} else {
		res = mbedtls_pk_parse_public_key(&host_key->key, buf, buf_len);
	}
	if (res < 0) {
		mbedtls_pk_free(&host_key->key);
		return -EIO;
	}

	host_key->in_use = true;

	return 0;
}

int ssh_host_key_write_pub_key(struct ssh_payload *payload, int host_key_index)
{
	if (host_key_index < 0 || host_key_index >= ARRAY_SIZE(ssh_host_key)) {
		return -EINVAL;
	}

	struct ssh_host_key *host_key = &ssh_host_key[host_key_index];
	if (!host_key->in_use) {
		return -EINVAL;
	}

	switch (host_key->key_type) {
#ifdef CONFIG_SSH_HOST_KEY_RSA
	case SSH_HOST_KEY_TYPE_RSA:
#endif
		break;
	default:
		return -ENOTSUP;
	}

	static const struct ssh_string type_string = SSH_STRING_LITERAL("ssh-rsa");
	mbedtls_rsa_context *rsa_host_key = mbedtls_pk_rsa(host_key->key);

	// Skip the length field, write it at the end once it is known
	uint32_t start_offset = payload->len;

	if (!ssh_payload_skip_bytes(payload, 4)) {
		return -ENOBUFS;
	}

	if (!ssh_payload_write_string(payload, &type_string)) {
		return -ENOBUFS;
	}
	uint8_t E[4]; // exponent 65537 (0x010001) requires at least 3 bytes
	uint8_t N[MBEDTLS_MPI_MAX_SIZE];
	int res = mbedtls_rsa_export_raw(rsa_host_key, N, sizeof(N), NULL,
					 0, NULL, 0, NULL, 0, E, sizeof(E));
	if (res != 0) {
		LOG_ERR("Failed to write pubkey: %d", res);
		return -EIO;
	}

	if (!ssh_payload_write_mpint(payload, E, sizeof(E), false)) {
		return -ENOBUFS;
	}
	if (!ssh_payload_write_mpint(payload, N, sizeof(N), false)) {
		return -ENOBUFS;
	}

	if (payload->data != NULL) {
		uint32_t string_len = payload->len - start_offset - 4;
		sys_put_be32(string_len, &payload->data[start_offset]);
	}

	return 0;
}

int ssh_host_key_write_signature(struct ssh_payload *payload, int host_key_index,
				 enum ssh_host_key_alg host_key_alg,
				 const void *data, uint32_t data_len)
{
	int res;

	if (host_key_index < 0 || host_key_index >= ARRAY_SIZE(ssh_host_key)) {
		return -EINVAL;
	}

	struct ssh_host_key *host_key = &ssh_host_key[host_key_index];
	if (!host_key->in_use) {
		return -EINVAL;
	}

	const struct host_key_alg_info *alg_info = get_host_key_alg_info(host_key_alg);
	if (alg_info == NULL) {
		return -ENOTSUP;
	}

	mbedtls_rsa_context *rsa_host_key = mbedtls_pk_rsa(host_key->key);

	// Hash the data
	uint8_t hash[MBEDTLS_MD_MAX_SIZE];
	uint8_t hash_len;
	switch (host_key_alg) {
#ifdef CONFIG_SSH_HOST_KEY_ALG_RSA_SHA2_256
	case SSH_HOST_KEY_ALG_RSA_SHA2_256: {
		hash_len = 32;
		int is224 = 0;
		res = mbedtls_sha256(data, data_len, hash, is224);
		break;
	}
#endif
#ifdef CONFIG_SSH_HOST_KEY_ALG_RSA_SHA2_512
	case SSH_HOST_KEY_ALG_RSA_SHA2_512: {
		hash_len = 64;
		int is384 = 0;
		res = mbedtls_sha512(data, data_len, hash, is384);
		break;
	}
#endif
	default:
		return -ENOTSUP;
	}
	if (res != 0) {
		return -EIO;
	}

	// Skip the length field, write it at the end once it is known
	uint32_t signature_start_offset = payload->len;
	if (!ssh_payload_skip_bytes(payload, 4)) {
		return -ENOBUFS;
	}

	if (!ssh_payload_write_string(payload, &alg_info->signature_type_string)) {
		return -ENOBUFS;
	}

	uint8_t signature_buff[MBEDTLS_MPI_MAX_SIZE];
	res = mbedtls_rsa_rsassa_pkcs1_v15_sign(
		rsa_host_key, ssh_mbedtls_rand, NULL,
		alg_info->mbedtls_md_type, hash_len, hash, signature_buff);
	if (res != 0) {
		LOG_ERR("Failed to sign hash: %d", res);
		return -EIO;
	}
	struct ssh_string signature = {
		.len = mbedtls_rsa_get_len(rsa_host_key),
		.data = signature_buff
	};
	if (!ssh_payload_write_string(payload, &signature)) {
		return -ENOBUFS;
	}

	uint32_t string_len = payload->len - signature_start_offset - 4;
	sys_put_be32(string_len, &payload->data[signature_start_offset]);

	return 0;
}

int ssh_host_key_verify_signature(const enum ssh_host_key_alg *host_key_alg,
				  const struct ssh_string *pubkey_blob,
				  const struct ssh_string *signature,
				  const void *data, uint32_t data_len)
{
	int res;

	struct ssh_payload signature_payload = {
		.size = signature->len,
		.data = (void *)signature->data
	};
	struct ssh_string signature_type, signature_raw;
	if (!ssh_payload_read_string(&signature_payload, &signature_type) ||
	    !ssh_payload_read_string(&signature_payload, &signature_raw) ||
	    !ssh_payload_read_complete(&signature_payload)) {
		LOG_ERR("Length error");
		return -1;
	}

	enum ssh_host_key_alg host_key_alg_tmp;
	if (host_key_alg == NULL) {
		// Any supported alg
		res = signature_type_str_to_id(&signature_type);
		if (res < 0) {
			return res;
		}
		host_key_alg_tmp = res;
		host_key_alg = &host_key_alg_tmp;
	}

	const struct host_key_alg_info *alg_info = get_host_key_alg_info(*host_key_alg);
	if (alg_info == NULL) {
		return -ENOTSUP;
	}

	if (!ssh_strings_equal(&signature_type, &alg_info->signature_type_string)) {
		LOG_WRN("Incorrect signature type");
		return -1;
	}

	// Hash the data
	uint8_t hash[MBEDTLS_MD_MAX_SIZE];
	uint8_t hash_len;
	switch (*host_key_alg) {
#ifdef CONFIG_SSH_HOST_KEY_ALG_RSA_SHA2_256
	case SSH_HOST_KEY_ALG_RSA_SHA2_256: {
		hash_len = 32;
		int is224 = 0;
		res = mbedtls_sha256(data, data_len, hash, is224);
		break;
	}
#endif
#ifdef CONFIG_SSH_HOST_KEY_ALG_RSA_SHA2_512
	case SSH_HOST_KEY_ALG_RSA_SHA2_512: {
		hash_len = 64;
		int is384 = 0;
		res = mbedtls_sha512(data, data_len, hash, is384);
		break;
	}
#endif
	default:
		return -ENOTSUP;
	}
	if (res != 0) {
		return -EIO;
	}

	// Import the host key
	struct ssh_host_key host_key;
	res = import_pubkey_blob(&host_key, pubkey_blob);
	if (res != 0) {
		LOG_ERR("Failed to import pubkey");
		return res;
	}

	mbedtls_rsa_context *rsa_host_key = mbedtls_pk_rsa(host_key.key);

	// TODO:
	//mbedtls_pk_get_len();
	//mbedtls_pk_verify()
	//mbedtls_pk_sign()

	// Verify signature length
	if (signature_raw.len != mbedtls_rsa_get_len(rsa_host_key)) {
		LOG_WRN("Incorrect signature length");
		res = -1;
		goto exit;
	}

	// Verify signature
	res = mbedtls_rsa_rsassa_pkcs1_v15_verify(rsa_host_key, alg_info->mbedtls_md_type, hash_len, hash, signature_raw.data);
	if (res != 0) {
		LOG_WRN("Incorrect signature");
		res = -1;
		goto exit;
	}

exit:
	free_host_key(&host_key);

	return res;
}

static int import_pubkey_blob(struct ssh_host_key *host_key, const struct ssh_string *pubkey_blob)
{
	int res;
	struct ssh_payload host_key_payload = {
		.size = pubkey_blob->len,
		.data = (void *)pubkey_blob->data
	};

	struct ssh_string host_key_type, host_key_E, host_key_N;
	if (!ssh_payload_read_string(&host_key_payload, &host_key_type)) {
		LOG_ERR("Length error");
		return -1;
	}
	static const struct ssh_string supported_host_key_type = SSH_STRING_LITERAL("ssh-rsa");
	if (!ssh_strings_equal(&host_key_type, &supported_host_key_type)) {
		LOG_WRN("Unsupported host key type");
		return -1;
	}
	if (!ssh_payload_read_string(&host_key_payload, &host_key_E) ||
	    !ssh_payload_read_string(&host_key_payload, &host_key_N) ||
	    !ssh_payload_read_complete(&host_key_payload)) {
		LOG_ERR("Length error");
		return -1;
	}

	// Import the host key
	mbedtls_pk_init(&host_key->key);

	res = mbedtls_pk_setup(&host_key->key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	if (res != 0) {
		LOG_ERR("RSA host key setup failed: %d", res);
		res = -EIO;
		goto err_free;
	}

	res = mbedtls_rsa_import_raw(
		mbedtls_pk_rsa(host_key->key), host_key_N.data, host_key_N.len, NULL,
		0, NULL, 0, NULL, 0, host_key_E.data, host_key_E.len);
	if (res != 0) {
		LOG_WRN("Failed to import RSA pub key");
		res = -EIO;
		goto err_free;
	}

	return 0;

err_free:
	mbedtls_pk_free(&host_key->key);
	return res;
}

static void free_host_key(struct ssh_host_key *host_key)
{
	mbedtls_pk_free(&host_key->key);
}
