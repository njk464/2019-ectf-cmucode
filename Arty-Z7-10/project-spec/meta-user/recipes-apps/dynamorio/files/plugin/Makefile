CMAKE=cmake
DYNAMORIO_DIR=/home/ubuntu/dynamorio_bin/HOTPATCH/build_arm
CFIPLUGIN_OPT=-DDynamoRIO_DIR=$(DYNAMORIO_DIR)/cmake
CFIPLUGIN_DIR=../.
BUILD_DIR=build

default: all

all: cfiplugin

cfiplugin:
	cd $(BUILD_DIR); \
	$(CMAKE) $(CFIPLUGIN_OPT) $(CFIPLUGIN_DIR); \
	make;

clean:
	rm -rf $(BUILD_DIR)/*
