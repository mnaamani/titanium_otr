LOCAL_PATH := $(call my-dir)
CMOSS_BIN_DROID := /home/mokhtar/projects/cmoss/bin/droid

include $(CLEAR_VARS)
LOCAL_MODULE     := otr
LOCAL_SRC_FILES  := libs/libotr.a
LOCAL_C_INCLUDES := $(CRYPTO_LIB_PATH)/include
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE     := gcrypt
LOCAL_SRC_FILES  := libs/libgcrypt.a
LOCAL_C_INCLUDES := $(CRYPTO_LIB_PATH)/include
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE     := gpg-error
LOCAL_SRC_FILES  := libs/libgpg-error.a
LOCAL_C_INCLUDES := $(CRYPTO_LIB_PATH)/include
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE    := otrjni
LOCAL_SRC_FILES := otrjni.c

LOCAL_C_INCLUDES += ${NDK_ROOT}/platforms/android-14/arch-arm/usr/includes
LOCAL_C_INCLUDES += ${NDK_ROOT}/sources/cxx-stl/gnu-libstdc++/include 
LOCAL_C_INCLUDES += ${NDK_ROOT}/sources/cxx-stl/gnu-libstdc++/libs/armeabi-v7a/include 
LOCAL_C_INCLUDES += $(CMOSS_BIN_DROID)/include 

LOCAL_CFLAGS += -DUNIX -DLOG_LEVEL_TRACE
LOCAL_CPPFLAGS += -frtti -fexceptions

#LOCAL_LDFLAGS += ${NDK_ROOT}/platforms/android-14/arch-arm/usr/lib/crtbegin_so.o
#LOCAL_LDFLAGS += -Os -nostdlib -Wl,-rpath-link=${NDK_ROOT}/platforms/android-14/arch-arm/usr/lib
LOCAL_LDFLAGS += -Os -Wl,-rpath-link=${NDK_ROOT}/platforms/android-14/arch-arm/usr/lib
LOCAL_LDLIBS += -lc -ldl -llog
#LOCAL_LDLIBS += -L. -lgpg-error -lgcrypt -lotr
LOCAL_STATIC_LIBRARIES := otr gcrypt gpg-error

include $(BUILD_SHARED_LIBRARY)
