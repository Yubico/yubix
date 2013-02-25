# Copyright (c) 2009-2013 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials provided
#     with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

VERSION = 0.5.0
PACKAGE = rlm_yubikey
CODE = Makefile COPYING rlm_yubikey.pl ykrlm-config.cfg ykmapping \
	dictionary

all:
	@echo "Try 'make install' or 'make symlink'."
	@echo "Info: https://github.com/Yubico/rlm-yubikey/"
	@exit 1

# Installation rules.

etcprefix = /etc/yubico/rlm
usrprefix = /usr/share/rlm_yubikey

install:
	install -D rlm_yubikey.pl $(DESTDIR)$(usrprefix)/rlm_yubikey.pl
	install -D dictionary $(DESTDIR)$(usrprefix)/dictionary
	install -D --backup --mode 600 ykrlm-config.cfg $(DESTDIR)$(etcprefix)/ykrlm-config.cfg
	install -D --backup --mode 600 ykmapping $(DESTDIR)$(etcprefix)/ykmapping

$(PACKAGE)-$(VERSION).tar.gz: $(FILES)
	mkdir $(PACKAGE)-$(VERSION)
	cp $(CODE) $(PACKAGE)-$(VERSION)/
	git2cl > $(PACKAGE)-$(VERSION)/ChangeLog
	tar cfz $(PACKAGE)-$(VERSION).tar.gz $(PACKAGE)-$(VERSION)
	rm -rf $(PACKAGE)-$(VERSION)

dist: $(PACKAGE)-$(VERSION).tar.gz
