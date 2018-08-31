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
	@mkdir -p $(CSS_DIR)
	@mkdir -p $(JS_DIR)
	@mkdir -p $(PRIVATE_DIR)

	@cp -aLr $(BOOTSTRAP_CSS)/*   $(CSS_DIR)
	@cp -aLr $(BOOTSTRAP_JS)/*    $(JS_DIR)
	@cp -aLr $(CSS)/*             $(CSS_DIR)
	@cp -aLr $(JS)/*              $(JS_DIR)
	@cp -aLr $(HTML)/*            $(PRIVATE_DIR)
ifneq ("$(wildcard $(PRIVATE_DIR)/navbar_$(MODEL).html)","")
	@cp $(PRIVATE_DIR)/navbar_$(MODEL).html $(PRIVATE_DIR)/navbar.html
endif
ifneq ("$(wildcard $(PRIVATE_DIR)/html_mapping_$(MODEL).txt)","")
	@cp $(PRIVATE_DIR)/html_mapping_$(MODEL).txt $(PRIVATE_DIR)/html_mapping.txt
endif

all: $(BIN) install
	@$(MAKE) -C src clean all

clean:
	@rm -rf $(CSS_DIR)
	@rm -rf $(JS_DIR)
	@rm -rf $(PRIVATE_DIR)
	@$(MAKE) -C src clean
