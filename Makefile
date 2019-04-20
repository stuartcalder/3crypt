CC = g++
CXXFLAGS = -std=c++17 -O2 -march=native -pipe -fPIC -fno-exceptions

main:
	$(CC) $(CXXFLAGS) -o main main.cpp vgp.cpp include/files/files.cpp include/general/print.cpp include/general/arg_mapping.cpp
clean:
	$(RM) main
