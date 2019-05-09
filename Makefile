CC = g++
CXXFLAGS = -std=c++17 -pipe -fPIC -fno-exceptions
DEBUGFLAGS = -Og
OPTFLAGS   = -O3 -march=native

debug:
	$(CC) $(CXXFLAGS) $(DEBUGFLAGS)\
		-o 3crypt\
		main.cc \
		3crypt.cc \
		include/files/files.cc \
		include/general/print.cc \
		include/general/arg_mapping.cc \
		include/crypto/sspkdf.cc \
		include/crypto/operations.cc
release:
	$(CC) $(CXXFLAGS) $(OPTFLAGS)\
 	  -o 3crypt\
		main.cc \
		3crypt.cc \
		include/files/files.cc \
		include/general/print.cc \
		include/general/arg_mapping.cc \
		include/crypto/sspkdf.cc \
		include/crypto/operations.cc
clean:
	$(RM) 3crypt 
