#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([lpass], [0.3.1], [https://github.com/lastpass/lastpass-cli/issues])
AC_CONFIG_SRCDIR([src/agent.h])
AC_CONFIG_HEADERS([notconfig.h])
#AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([crypto], [SHA256_Init],, AC_ERROR([Missing libcrypto]))
AC_CHECK_LIB([curl], [curl_easy_init],, AC_ERROR([Missing libcurl]))
AC_CHECK_LIB([ssl], [SSL_CTX_set_cert_store],, AC_ERROR([Missing openssl]))
PKG_CHECK_MODULES([LIBXML2], [libxml-2.0 >= 2.6.26])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stddef.h stdint.h stdlib.h string.h strings.h sys/socket.h termios.h unistd.h utime.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([alarm atexit dup2 memset mkdir rmdir setenv socket strcasecmp strchr strdup strerror strndup strrchr strstr strtoul strtoull uname utime])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
