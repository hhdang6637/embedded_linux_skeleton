# CC       = gcc
# CFLAGS += -Wall -g
BOOTSTRAP_CSS := bootstrap-4.0.0-dist/css
BOOTSTRAP_JS  := bootstrap-4.0.0-dist/js
HTML          := html
JS            := js
CSS           := css

$(BIN):
	@echo "nothing to build"

install:
	@mkdir -p $(ROOTFS_DIR)/var/www/hiawatha/css
	@mkdir -p $(ROOTFS_DIR)/var/www/hiawatha/js

	@cp -aLr $(BOOTSTRAP_CSS)/*   $(ROOTFS_DIR)/var/www/hiawatha/css
	@cp -aLr $(BOOTSTRAP_JS)/*    $(ROOTFS_DIR)/var/www/hiawatha/js
	@cp -aLr $(CSS)/*             $(ROOTFS_DIR)/var/www/hiawatha/css
	@cp -aLr $(JS)/*              $(ROOTFS_DIR)/var/www/hiawatha/js
	@cp -aLr $(HTML)/*            $(ROOTFS_DIR)/var/www/hiawatha

all: $(BIN) install
	@$(MAKE) -C src clean all

clean:
	@$(MAKE) -C src clean
