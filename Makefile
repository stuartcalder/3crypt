CC = g++
CXXFLAGS = -std=c++17 -pipe -fPIC -fno-exceptions
DEBUGFLAGS = -Og
OPTFLAGS   = -O3
LINKFLAGS  = -lncurses -lssc
prefix     = /usr/

debug:
	$(CC) $(CXXFLAGS) $(DEBUGFLAGS)\
		-o 3crypt\
		main.cc \
		3crypt.cc \
		$(LINKFLAGS)
		# \
		#include/files/files.cc \
		#include/general/print.cc \
		#include/general/arg_mapping.cc \
		#include/crypto/sspkdf.cc \
		#include/crypto/operations.cc \
		#include/interface/terminal.cc
3crypt:
	$(CC) $(CXXFLAGS) $(OPTFLAGS)\
		-o 3crypt\
		main.cc \
		3crypt.cc \
		$(LINKFLAGS)
		# \
		#include/files/files.cc \
		#include/general/print.cc \
		#include/general/arg_mapping.cc \
		#include/crypto/sspkdf.cc \
		#include/crypto/operations.cc \
		#include/interface/terminal.cc
install: 3crypt
	install -s -m 0755 3crypt $(prefix)/bin
clean:
	$(RM) 3crypt 
