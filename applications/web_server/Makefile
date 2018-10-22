# CC       = gcc
# CFLAGS += -Wall -g
BOOTSTRAP_CSS := bootstrap-4.0.0-dist/css
BOOTSTRAP_JS  := bootstrap-4.0.0-dist/js
HTML          := html
JS            := js
CSS           := css

PUBLIC_DIR    := $(ROOTFS_DIR)/var/www/hiawatha/public
PRIVATE_DIR   := $(ROOTFS_DIR)/var/www/hiawatha/private
CSS_DIR       := $(PUBLIC_DIR)/css
JS_DIR        := $(PUBLIC_DIR)/js

$(BIN):
	@echo "nothing to build"

install:
	@echo "copy html, css, js to " $(ROOTFS_DIR)/var/www/hiawatha
	mkdir -p $(CSS_DIR)
	mkdir -p $(JS_DIR)
	mkdir -p $(PRIVATE_DIR)

	cp -aLr $(BOOTSTRAP_CSS)/*   $(CSS_DIR)
	cp -aLr $(BOOTSTRAP_JS)/*    $(JS_DIR)
	cp -aLr $(CSS)/*             $(CSS_DIR)
	cp -aLr $(JS)/*              $(JS_DIR)
	cp -aLr $(HTML)/*            $(PRIVATE_DIR)
	if [ -e $(PRIVATE_DIR)/navbar_$(MODEL).html ] ; then  cp $(PRIVATE_DIR)/navbar_$(MODEL).html $(PRIVATE_DIR)/navbar.html; fi
	if [ -e $(PRIVATE_DIR)/html_mapping_$(MODEL).txt ] ; then  cp -f $(PRIVATE_DIR)/html_mapping_$(MODEL).txt $(PRIVATE_DIR)/html_mapping.txt; fi

all: $(BIN) install
	@echo "build web_server"
	@$(MAKE) -C src clean all

clean:
	@rm -rf $(CSS_DIR)
	@rm -rf $(JS_DIR)
	@rm -rf $(PRIVATE_DIR)
	@$(MAKE) -C src clean
