ASN_ROOT = ./asn
SRC_ROOT = ./src

SUBDIRS = asn
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I$(ASN_ROOT) -I$(SRC_ROOT)
AM_CXXFLAGS = -I$(ASN_ROOT) -I$(SRC_ROOT)
LDADD = ./asn/.libs/libsomething.a

bin_PROGRAMS = main
main_CFLAGS = $(AM_CFLAGS)
main_CXXFLAGS = $(AM_CXXFLAGS)
main_SOURCES = src/main.cpp
