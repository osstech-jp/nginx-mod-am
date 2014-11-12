
NGINX_URI=http://nginx.org/download/
NGINX_VER=1.6.2
NGINX_SRC=nginx-$(NGINX_VER).tar.gz

DESTDIR=../nginx_agent/

CFLAGS=-g
LDFLAGS=-Wl,-rpath,'\$$\$$ORIGIN/../lib'

all: install

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

install: build/bin/nginx
	make -C build install DESTDIR="$(DESTDIR)"

clean:
	rm -rf build/Makefile build/objs/

distclean:
	rm -rf build/

