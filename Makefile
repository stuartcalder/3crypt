CC = g++
CXXFLAGS = -std=c++17 -pipe -fno-exceptions
OPTFLAGS   = -O3
LINKFLAGS  = -lssc -lncurses
prefix     = /usr

main.o:
	$(CC) $(CXXFLAGS) -c $(OPTFLAGS) \
		main.cc
3crypt.o:
	$(CC) $(CXXFLAGS) -c $(OPTFLAGS) \
		3crypt.cc
cbc_v1.o:
	$(CC) $(CXXFLAGS) -c $(OPTFLAGS) \
		cbc_v1.cc
cbc_v2.o:
	$(CC) $(CXXFLAGS) -c $(OPTFLAGS) \
		cbc_v2.cc
determine_decrypt_method.o:
	$(CC) $(CXXFLAGS) -c $(OPTFLAGS) \
		determine_decrypt_method.cc
3crypt: main.o 3crypt.o cbc_v1.o cbc_v2.o determine_decrypt_method.o
	$(CC) $(CXXFLAGS) $(OPTFLAGS) \
		-o $@ \
		main.o \
		3crypt.o \
		cbc_v1.o \
		cbc_v2.o \
		determine_decrypt_method.o \
		$(LINKFLAGS)
install: 3crypt
	install -s -m 0755 3crypt $(prefix)/bin
clean:
	$(RM) 3crypt *.o
