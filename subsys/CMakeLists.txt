# SPDX-License-Identifier: Apache-2.0

add_compile_options($<TARGET_PROPERTY:compiler,warning_shadow_variables>)

add_subdirectory_ifdef(CONFIG_NETWORKING net)
