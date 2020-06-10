#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(main, 1.0, xx@xx.com)
AC_CONFIG_SRCDIR([src/main.cpp])
#AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
# AC_PROG_RANLIB
LT_INIT

# Checks for libraries.

# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([float.h inttypes.h limits.h malloc.h netinet/in.h stddef.h stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_STRTOD
AC_CHECK_FUNCS([memchr memmove memset strerror])

AC_CONFIG_FILES([Makefile
                 asn/Makefile])
AC_OUTPUT
