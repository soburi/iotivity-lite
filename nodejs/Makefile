SWIG = swig
HEADER_FILE = -I../ -I../include -I../port -I../util/ -I../deps/tinycbor/src/ -I../security -I../cloud

HEADERS = *.h

ifeq ($(DEBUG),1)
	EXTRA_FLAG += -DOC_DEBUG -g -O0
endif

ifeq ($(CLOUD),1)
	TCP=1
	EXTRA_FLAG += -DOC_CLOUD
	CLOUD_OBJ_DIR = $(PORT_OBJ_DIR)cloud/*.o
endif

ifneq ($(SECURE),0)
	EXTRA_FLAG += -DOC_SECURITY
endif

ifeq ($(IDD), 1)
	EXTRA_FLAG += -DOC_IDD_API
endif

ifneq ($(PKI),0)
	EXTRA_FLAG += -DOC_PKI
endif

ifeq ($(TCP),1)
	EXTRA_FLAG += -DOC_TCP
	SWIG_CFLAG += -DOC_TCP
endif

ifeq ($(SWUPDATE),1)
	EXTRA_FLAG += -DOC_SOFTWARE_UPDATE
	SWIG_CFLAG += -DOC_SOFTWARE_UPDATE
endif

SRC = iotivity_lite

# Swig interfaces source
SWIG_INTERFACE_SRC = $(addsuffix .i, $(SRC))
WRAPPER_SRC = $(addsuffix _wrap.cxx, $(SRC))

ifeq ($(OS),linux)
	EXTRA_HEADER_FILE = -I"$(JAVA_HOME)/include/" -I"$(JAVA_HOME)/include/linux/"
	PORT_OBJ_DIR = ../port/linux/obj/
	SWIG_CFLAG += -D__linux__
	EXTRA_FLAG += -fno-strict-aliasing
	HEADER_FILE += -I../port/linux
	LDFLAG += -lpthread -lrt
endif
ifeq ($(OS),android)
	EXTRA_HEADER_FILE = -I"$(ANDROID_BASE)/sysroot/usr/include/"
	PORT_OBJ_DIR = ../port/android/${ANDROID_HOST}obj/
	SWIG_CFLAG += -D__linux__
	HEADER_FILE += -I../port/android
	LDFLAG += -llog
	INSTALL_ANDROID_LIBS = install_android_libs
ifeq ($(ANDROID_API),)
	EXTRA_FLAG += -D__ANDROID_API__=23
else
	EXTRA_FLAG += -D__ANDROID_API__=$(ANDROID_API)
endif
endif

JAVA_LANG_OBJ_DIR += $(PORT_OBJ_DIR)swig/

all: clean node-gyp

.PHONY: clean

%_wrap.cxx: %.i $(HEADERS)
	$(SWIG) -javascript -node -c++ -I. $(SWIG_CFLAG) $(HEADER_FILE) -o $@ $*.i

node-gyp: $(WRAPPER_SRC)
	node-gyp configure build


clean:
	node-gyp clean
