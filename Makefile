CC = g++
CXXFLAGS = -std=c++17 -pipe -fPIC -fno-exceptions
DEBUGFLAGS = -Og
OPTFLAGS   = -O3
LINKFLAGS  = -lssc -lncurses
prefix     = /usr/local

debug:
	$(CC) $(CXXFLAGS) $(DEBUGFLAGS)\
		-o 3crypt\
		main.cc \
		3crypt.cc \
		$(LINKFLAGS)
3crypt:
	$(CC) $(CXXFLAGS) $(OPTFLAGS)\
		-o 3crypt\
		main.cc \
		3crypt.cc \
		$(LINKFLAGS)
install: 3crypt
	install -s -m 0755 3crypt $(prefix)/bin
clean:
	$(RM) 3crypt 
