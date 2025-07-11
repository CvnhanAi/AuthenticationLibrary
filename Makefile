TARGET := iphone:clang:latest:9.0
ARCHS = arm64 arm64e

export CFLAGS = -Wno-error=objc-property-no-attribute
export OBJCFLAGS = -Wno-error=objc-property-no-attribute

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = xztime
xztime_LINKAGE_TYPE = static
xztime_CFLAGS =  -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-value
xztime_FILES = xztime.mm UICKeyChainStore/UICKeyChainStore.m FCUUID/FCUUID.m
xztime_FRAMEWORKS = UIKit Foundation

include $(THEOS_MAKE_PATH)/library.mk
