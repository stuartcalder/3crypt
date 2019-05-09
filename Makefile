CC = g++
CXXFLAGS = -std=c++17 -O3 -march=native -pipe -fPIC -fno-exceptions

main:
	$(CC) $(CXXFLAGS) -o vgp\
		main.cc \
		vgp.cc \
		include/files/files.cc \
		include/general/print.cc \
		include/general/arg_mapping.cc \
		include/crypto/sspkdf.cc \
		include/crypto/operations.cc
clean:
	$(RM) main
