CC = g++
CXXFLAGS = -std=c++17 -O3 -march=native -pipe -fPIC -fno-exceptions

3crypt:
	$(CC) $(CXXFLAGS) -o 3crypt\
		main.cc \
		3crypt.cc \
		include/files/files.cc \
		include/general/print.cc \
		include/general/arg_mapping.cc \
		include/crypto/sspkdf.cc \
		include/crypto/operations.cc
clean:
	$(RM) 3crypt 
