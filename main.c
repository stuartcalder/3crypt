#include "threecrypt.h"

int
main (int argc, char ** argv) {
	SHIM_OPENBSD_UNVEIL ("/usr", "r");
	SHIM_OPENBSD_PLEDGE ("stdio unveil rpath wpath cpath tty", NULL);
	threecrypt( argc, argv );
	return EXIT_SUCCESS;
}
