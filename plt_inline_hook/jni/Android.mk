LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := hook
LOCAL_SRC_FILES := inlHook.c inline.s
include $(BUILD_SHARED_LIBRARY)

# include $(CLEAR_VARS)
# LOCAL_MODULE := foo
# LOCAL_SRC_FILES := foo.cpp
# include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := main
LOCAL_SRC_FILES := main.c
LOCAL_SHARED_LIBRARIES := hook
LOCAL_LDFLAGS += -Wl,-rpath=/data/local/tmp
include $(BUILD_EXECUTABLE)