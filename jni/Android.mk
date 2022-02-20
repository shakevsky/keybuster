LOCAL_PATH := $(call my-dir)

define keybuster_exe
	include $(CLEAR_VARS)

	LOCAL_MODULE := $1
	LOCAL_SRC_FILES := $2
	LOCAL_CFLAGS := -std=c99 -Wall -fPIE -fPIC -D_GNU_SOURCE $3
	LOCAL_LDLIBS := -llog -ldl
	LOCAL_C_INCLUDES := $4

	$(info "flags are '$(LOCAL_CFLAGS)'")
	$(info "1 is '$1'")
	$(info "2 is '$2'")
	$(info "3 is '$3'")
	$(info "4 is '$4'")

	include $(BUILD_EXECUTABLE)
endef

# The default is to use libkeymaster_helper.so as-is -> the default binary is keybuster
# If we want to use a client that we implemented (e.g. to avoid input checks), we can specify
# the define DKEYMASTER_HELPER_SELF_IMPLEMENTATION and the appropriate TZOS
# this leads to variants such as keybuster_mod_TEEGRIS
DEFAULT_SRC := $(wildcard core/*.c) $(wildcard keymaster_helper_lib/*.c)
DEFAULT_INCLUDES := core/
DEFAULT_CFLAGS :=

$(eval $(call keybuster_exe, "keybuster", $(DEFAULT_SRC), $(DEFAULT_CFLAGS), $(DEFAULT_INCLUDES)))

# CORE_S := $(wildcard core/*.c)
# CORE_I := core/

# MOD_S := $(wildcard keymaster_helper_mod/*.c)
# MOD_I := keymaster_helper_mod/

# TEEC_S := $(wildcard keymaster_helper_mod/teec/*.c)
# TEEC_I := keymaster_helper_mod/teec

# TEEGRIS_S := $(wildcard keymaster_helper_mod/teegris/*.c)
# TEEGRIS_I := keymaster_helper_mod/teegris

# TEEGRIS_MOD_SRC := $(CORE_S) $(MOD_S) $(TEEC_S) $(TEEGRIS_S)
# TEEGRIS_MOD_CFLAGS := -DKEYMASTER_HELPER_SELF_IMPLEMENTATION -DTZOS_TEEGRIS
# TEEGRIS_MOD_INCLUDES := $(CORE_I) $(MOD_I) $(TEEC_I) $(TEEGRIS_I)

# $(eval $(call keybuster_exe, "keybuster_mod_TEEGRIS", $(TEEGRIS_MOD_SRC), $(TEEGRIS_MOD_CFLAGS), $(TEEGRIS_MOD_INCLUDES)))

# # the Kinibi client mod is still unfinished, use the normal keybuster (with original client)
# KINIBI_S := $(wildcard keymaster_helper_mod/kinibi/*.c)
# KINIBI_I := keymaster_helper_mod/kinibi

# KINIBI_MOD_SRC := $(CORE_S) $(MOD_S) $(KINIBI_S)
# KINIBI_MOD_CFLAGS :=-DKEYMASTER_HELPER_SELF_IMPLEMENTATION -DTZOS_KINIBI
# KINIBI_MOD_INCLUDES := $(CORE_I) $(MOD_I) $(KINIBI_I)

# $(eval $(call keybuster_exe, "keybuster_mod_KINIBI", $(KINIBI_MOD_SRC), $(KINIBI_MOD_CFLAGS), $(KINIBI_MOD_INCLUDES)))

TEST_SRC := $(wildcard core/*.c) $(wildcard keymaster_helper_lib/*.c)
TEST_SRC := $(filter-out core/main.c, $(TEST_SRC)) $(wildcard test/*.c)
TEST_INCLUDES := core/ test/
TEST_CFLAGS :=

$(eval $(call keybuster_exe, "keybuster_test", $(TEST_SRC), $(TEST_CFLAGS), $(TEST_INCLUDES)))
