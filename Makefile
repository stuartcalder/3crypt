CC = g++
CXXFLAGS = -std=c++17 -pipe -fPIC -fno-exceptions
OPTFLAGS   = -O3
LINKFLAGS  = -lssc -lncurses
prefix     = /usr

3crypt:
	$(CC) $(CXXFLAGS) $(OPTFLAGS)\
		-o 3crypt\
		main.cc \
		3crypt.cc \
		cbc_v1.cc \
		$(LINKFLAGS)
install: 3crypt
	install -s -m 0755 3crypt $(prefix)/bin
clean:
	$(RM) 3crypt 
