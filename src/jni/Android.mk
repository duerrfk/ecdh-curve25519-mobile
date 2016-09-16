LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := ecdhcurve25519

LOCAL_SRC_FILES := bigint.c curve25519.c ecdh_curve25519.c fe25519.c de_frank_durr_ecdh_curve25519_ECDHCurve25519.cc

include $(BUILD_SHARED_LIBRARY)

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_CFLAGS += -std=c99

