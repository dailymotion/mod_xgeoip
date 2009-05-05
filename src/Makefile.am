APXS=@APXS@
APACHECTL=@APACHECTL@
LIBS=-Wl,"@LIBS@"
CFLAGS=-Wc,"@CFLAGS@"

all: mod_xgeoip.la

mod_xgeoip.la: @srcdir@/mod_xgeoip.c
	$(APXS) -c $(CFLAGS) $(LIBS) @srcdir@/mod_xgeoip.c

install: all
	$(APXS) -i -a mod_xgeoip.la 

clean:
	rm -rf *.o *.so *.loT .deps/ *.la *.lo *.slo .libs/

reload: install restart

start:
	$(APACHECTL) start

restart:
	$(APACHECTL) restart

stop:
	$(APACHECTL) stop

mostlyclean: clean
distclean: clean
maintainer-clean: clean
	rm -f Makefile

Makefile: @srcdir@/Makefile.in
	(cd .. && ./config.status )

.PHONY: all install clean reload start restart stop mostlyclean distclean maintainer-clean distdir
