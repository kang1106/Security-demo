ROOT = ./
ASN_ROOT = ./asn
SRC_ROOT = ./src
INCLUDE_ROOT = ./include

LIB = -L./lib/openssl -lssl -lcrypto -L./lib/glog -lglog

SUBDIRS = asn
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I$(ASN_ROOT) -I$(SRC_ROOT) -I$(INCLUDE_ROOT) -I$(ROOT)
AM_CXXFLAGS = -I$(ASN_ROOT) -I$(SRC_ROOT) -I$(INCLUDE_ROOT) -I$(ROOT) -std=c++11 -Wl,--no-as-needed -ldl
LDADD = ./asn/.libs/libasn.a $(LIB) -lpthread

bin_PROGRAMS = sec_v2xd
sec_v2xd_CFLAGS = $(AM_CFLAGS)
sec_v2xd_CXXFLAGS = $(AM_CXXFLAGS)
sec_v2xd_SOURCES = src/main.cpp
