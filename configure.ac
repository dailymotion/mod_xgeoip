AC_PREREQ(2.59)
AC_INIT([mod_xgeoip],[1.10],[pyke (at) dailymotion (dot) com])
AC_CONFIG_SRCDIR([src/mod_xgeoip.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign 1.9 -Wall])

AC_SUBST(PACKAGE_URL, [http://wiki.dailymotion.com/display/dev/XGeoIP+Apache2+Module])

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_MAKE_SET

test_gcc_flag() {
    AC_LANG_CONFTEST([int main() {}])
    $CC -c conftest.c $CFLAGS $@ > /dev/null 2> /dev/null
    ret=$?
    rm -f conftest.o
    return $ret
}

# If using GCC specify some additional parameters
if test "x$GCC" = "xyes" ; then

#    DESIRED_FLAGS="-Wall -W -Wextra -pedantic -pipe -Wformat -Wold-style-definition -Wdeclaration-after-statement -Wfloat-equal -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls -Wmissing-noreturn -Wshadow -Wendif-labels -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings -Winline"
     DESIRED_FLAGS=""

    for flag in $DESIRED_FLAGS ; do
        AC_MSG_CHECKING([whether $CC accepts $flag])
        if test_gcc_flag $flag ; then 
           CFLAGS="$CFLAGS $flag"
           AC_MSG_RESULT([yes])
        else
           AC_MSG_RESULT([no])
        fi
    done 
fi

AC_ARG_WITH(apxs,
    AS_HELP_STRING(--with-apxs=PATH,/path/to/apxs),
    [ AC_PATH_PROGS(APXS, [apxs2 apxs], "notfound", "$withval:$PATH") ], 
    [ AC_PATH_PROGS(APXS, [apxs2 apxs], "notfound", "/usr/local/apache/bin:/usr/local/bin:/usr/sbin:$PATH")])

if test "x$APXS" = "xnotfound" ; then
    AC_MSG_ERROR([*** Sorry, could not find apxs ***])
fi

AC_ARG_WITH(apachectl,
    AS_HELP_STRING(--with-apachectl=PATH,/path/to/apachectl),
    [ AC_PATH_PROGS(APACHECTL, [apache2ctl apachectl], "notfound", "$withval:$PATH") ], 
    [ AC_PATH_PROGS(APACHECTL, [apache2ctl apachectl], "notfound", "/usr/local/apache/bin:/usr/local/bin:/usr/sbin:$PATH")])

#
# Checking that we have Apache version 2
#

# saving current CFLAGS
CFLAGS_SAVED=$CFLAGS
CFLAGS="$CFLAGS -I`${APXS} -q INCLUDEDIR`"

AC_MSG_CHECKING([for Apache 2])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
	#include <ap_release.h>
]], [[
        char *version = AP_SERVER_BASEREVISION;
]])],[
        APACHE_2="yes"
],[
        APACHE_2="no"
])

AC_MSG_RESULT($APACHE_2)

if test "x$APACHE_2" = "xno" ; then
    AC_MSG_ERROR([*** Sorry, you need apache 2 ***])
fi

# restoring CFLAGS
CFLAGS=$CFLAGS_SAVED

AC_CONFIG_FILES([src/Makefile Makefile])
AC_OUTPUT
