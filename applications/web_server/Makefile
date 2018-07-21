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

	@cp  $(BOOTSTRAP_CSS)/*   $(ROOTFS_DIR)/var/www/hiawatha/css
	@cp  $(BOOTSTRAP_JS)/*    $(ROOTFS_DIR)/var/www/hiawatha/js
	@cp  $(CSS)/*             $(ROOTFS_DIR)/var/www/hiawatha/css
	@cp  $(JS)/*              $(ROOTFS_DIR)/var/www/hiawatha/js
	@cp  $(HTML)/*            $(ROOTFS_DIR)/var/www/hiawatha

all: $(BIN) install
	@$(MAKE) -C src clean all

clean:
	@$(MAKE) -C src clean
