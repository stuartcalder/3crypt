#include "Threecrypt.h"

int main(int argc, char* argv[])
{
  SSC_OPENBSD_UNVEIL("/usr", "r");
  SSC_OPENBSD_PLEDGE("stdio unveil rpath wpath cpath tty", NULL);
  threecrypt(argc, argv);
  return EXIT_SUCCESS;
}
