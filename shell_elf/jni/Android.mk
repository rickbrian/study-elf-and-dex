LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := foo
LOCAL_SRC_FILES := foo.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# include $(CLEAR_VARS)
# LOCAL_MODULE := foo
# LOCAL_SRC_FILES := load_elf.cpp
# #LOCAL_LDFLAGS += -Wl,-soname=libfoo.so
# include $(BUILD_SHARED_LIBRARY)

# include $(CLEAR_VARS)
# LOCAL_MODULE := main
# LOCAL_SRC_FILES := main.c
# LOCAL_LDFLAGS += -Wl,-rpath=/data/local/tmp
# include $(BUILD_EXECUTABLE)