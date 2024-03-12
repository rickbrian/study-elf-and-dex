LOCAL_PATH := $(call my-dir)



include $(CLEAR_VARS)
LOCAL_MODULE := load_elf
LOCAL_SRC_FILES := load_elf.cpp
include $(BUILD_EXECUTABLE)