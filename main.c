#include "threecrypt.h"

int
main (int const argc, char const *argv[])
{
	SHIM_OPENBSD_PLEDGE ("stdio unveil rpath wpath cpath tty", NULL);
	SHIM_OPENBSD_UNVEIL ("/usr", "rx");
	threecrypt( argc, argv );
	return EXIT_SUCCESS;
}
