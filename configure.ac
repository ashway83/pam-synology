# configure.ac - process this file with autoconf to produce a configure script
#
# Copyright (C) 2021 Andriy Sharandakov
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
# USA

AC_PREREQ([2.69])
AC_INIT([pam-synology], [0.1.0], [ash.ashway@gmail.com])
AC_CONFIG_SRCDIR([src/pam.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/config.h])

AC_CANONICAL_HOST

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_PROG_AR

LT_INIT([disable-static])
AC_ENABLE_STATIC([no])
AC_ENABLE_SHARED([yes])

# PAM modules directory
AC_MSG_CHECKING([PAM modules directory])
AC_ARG_WITH(pam-modules-dir,
            AS_HELP_STRING([--with-pam-modules-dir=DIR],
                           [PAM modules directory @<:@auto@:>@]),
            [PAM_MODULES_DIR=$with_pam_modules_dir],
            [PAM_MODULES_DIR="auto"])
if test "x$PAM_MODULES_DIR" = "xauto"
then
  case "$host_os" in
    darwin*)
      PAM_MODULES_DIR="/usr/local/lib/pam" ;;
    linux*)
      PAM_MODULES_DIR="/lib/security" ;;
    *)
      PAM_MODULES_DIR=$libdir ;;
  esac
fi
AC_MSG_RESULT($PAM_MODULES_DIR)
AC_SUBST(PAM_MODULES_DIR)

# Checks for programs.
AC_PROG_CC

AC_CACHE_CHECK([if ld supports -Wl,--version-script],
  [_cv_supports_ld_version_script],
  [_cv_supports_ld_version_script="no"
  save_LDFLAGS=$LDFLAGS
  LDFLAGS="$LDFLAGS -Wl,--version-script=conftest.map"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
    [],
    [cat > conftest.map <<EOF
VERS_1 {
        global: sym;
};
VERS_2 {
        global: sym;
} VERS_1;
EOF
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
      [_cv_supports_ld_version_script="yes"])])
  rm -f conftest.map
  LDFLAGS=$save_LDFLAGS])

AM_CONDITIONAL([HAVE_LD_VERSION_SCRIPT],
  [test "$_cv_supports_ld_version_script" = "yes"])

# Checks for libraries.
AC_SEARCH_LIBS([pam_get_item], [pam], [], AC_MSG_ERROR([PAM library not found]))

# Checks for header files.
AC_CHECK_HEADERS([security/pam_appl.h])
AC_CHECK_HEADERS([security/pam_ext.h])
AC_CHECK_HEADERS([security/pam_modules.h], [], [AC_MSG_ERROR([PAM header files not found])])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS(pam_syslog)

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
