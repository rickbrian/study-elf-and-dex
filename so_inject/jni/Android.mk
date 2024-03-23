LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := hook
LOCAL_SRC_FILES := foo.cpp
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)
LOCAL_MODULE := soinject
LOCAL_SRC_FILES := so_inject.cpp
LOCAL_SHARED_LIBRARIES := hook
LOCAL_LDFLAGS += -Wl,-rpath=/data/local/tmp
include $(BUILD_EXECUTABLE)