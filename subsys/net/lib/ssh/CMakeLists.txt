# SPDX-License-Identifier: Apache-2.0

zephyr_library()

#zephyr_include_directories(${ZEPHYR_BASE}/subsys/net/ip)

zephyr_library_sources_ifdef(CONFIG_SSH
        ssh_core.c
        ssh_transport.c
        ssh_kex.c
        ssh_auth.c
        ssh_connection.c
        ssh_pkt.c
        ssh_host_key.c)
zephyr_library_sources_ifdef(CONFIG_SSH ssh_kex_ecdh.c)
zephyr_library_sources_ifdef(CONFIG_SSH_SERVER ssh_server.c)
zephyr_library_sources_ifdef(CONFIG_SSH_CLIENT ssh_client.c)

zephyr_library_link_libraries_ifdef(CONFIG_MBEDTLS mbedTLS)
