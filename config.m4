dnl $Id$
dnl config.m4 for extension courierauth

PHP_ARG_WITH(courierauth, for courierauth support,
	[  --with-courierauth-config
                          Path to courierauthconfig script])
PHP_ARG_WITH(courierauth-security-risk, whether to enable passwd security risk,
	[  --with-courierauth-security-risk
                          Enable passwd security risk], no, no)

if test "$PHP_COURIERAUTH" != "no"; then
	AC_MSG_CHECKING(for courierauthconfig)
	COURIERAUTHCONFIG=
	for i in "$PHP_COURIERAUTH_CONFIG" /usr/local/bin/courierauthconfig /usr/bin/courierauthconfig "`which courierauthconfig`"; do
		if test -x "$i"; then
			COURIERAUTHCONFIG="$i"
			break
		fi
	done
	if test -z "$COURIERAUTHCONFIG"; then
		AC_MSG_ERROR(not found)
	else
		AC_MSG_RESULT($COURIERAUTHCONFIG)
	fi
	
	AC_MSG_CHECKING(for courierauth ldflags)
	COURIERAUTH_LIBS="`$COURIERAUTHCONFIG --ldflags`"
	AC_MSG_RESULT("$COURIERAUTH_LIBS -lcourierauth")
	if test -z "$COURIERAUTH_LIBS"; then
		PHP_ADD_LIBRARY(courierauth, COURIERAUTH_SHARED_LIBADD)
	else
		PHP_EVAL_LIBLINE("$COURIERAUTH_LIBS -lcourierauth", COURIERAUTH_SHARED_LIBADD)
	fi
	
	AC_MSG_CHECKING(for courierauth includes)
	COURIERAUTH_INCS="`$COURIERAUTHCONFIG --cppflags`"
	if test -z "$COURIERAUTH_INCS"; then
		for i in /usr/local/include /usr/include; do
			if test -f $i/courierauth.h; then
				COURIERAUTH_INCS="-I$i"
				PHP_ADD_INCLUDE($i)
				break
			fi
		done
	else
		PHP_EVAL_INCLINE("$COURIERAUTH_INCS")
	fi
	AC_MSG_RESULT("$COURIERAUTH_INCS")
	
	if test "$PHP_COURIERAUTH_SECURITY_RISK" = "yes"; then
		AC_DEFINE(PHP_COURIERAUTH_SECURITY_RISK, 1, [passwd security risk])
	else
		AC_DEFINE(PHP_COURIERAUTH_SECURITY_RISK, 0, [passwd security risk])
	fi
	
	PHP_SUBST(COURIERAUTH_SHARED_LIBADD)
	
	PHP_NEW_EXTENSION(courierauth, courierauth.c, $ext_shared)
fi
