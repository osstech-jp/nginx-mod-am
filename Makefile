
NGINX_URI=http://nginx.org/download/
NGINX_VER=1.6.2
NGINX_SRC=nginx-$(NGINX_VER).tar.gz

DESTDIR=./nginx_agent/

CFLAGS=-g
LDFLAGS=-Wl,-rpath,'\$$\$$ORIGIN/../lib'

all: dist

$(NGINX_SRC):
	wget $(NGINX_URI)$(NGINX_SRC)

build: $(NGINX_SRC) extlib
	tar xzf $(NGINX_SRC)
	mv nginx-$(NGINX_VER) build
	touch build

build/Makefile: build
	cd build && \
	./configure \
		--with-cc-opt="$(CFLAGS)" \
		--with-ld-opt="$(LDFLAGS)" \
		--prefix=./ \
		--sbin-path=./bin/nginx \
		--add-module=../ \
		--with-http_ssl_module \
		--with-pcre

build/bin/nginx: build/Makefile
	make -C build

dist: build/bin/nginx
	rm -rf $(DESTDIR)
	make -C build install DESTDIR="../$(DESTDIR)"
	cp -rp extlib/lib $(DESTDIR)
	cp -rp conf $(DESTDIR)
	mv $(DESTDIR)/conf/agentadmin.sh $(DESTDIR)/bin/
	install -m 755 extlib/bin/crypt_util $(DESTDIR)/bin/
	install -m 644 README.md $(DESTDIR)

clean:
	rm -rf build/Makefile build/objs/

distclean:
	rm -rf build/

