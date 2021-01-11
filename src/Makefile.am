## Makefile.am - use automake to generate Makefile.in
##
## Copyright (C) 2021 Andriy Sharandakov
##
## This library is free software; you can redistribute it and/or
## modify it under the terms of the GNU Lesser General Public
## License as published by the Free Software Foundation; either
## version 2.1 of the License, or (at your option) any later version.
##
## This library is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## Lesser General Public License for more details.
##
## You should have received a copy of the GNU Lesser General Public
## License along with this library; if not, write to the Free Software
## Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
## USA

AM_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_LD_VERSION_SCRIPT
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/module.map
else
  AM_LDFLAGS += -export-symbols $(srcdir)/module.sym
endif

pammodulesdir = $(PAM_MODULES_DIR)

pammodules_LTLIBRARIES = pam_synology.la

pam_synology_la_SOURCES = pam.c
