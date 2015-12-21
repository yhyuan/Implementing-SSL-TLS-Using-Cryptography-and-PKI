#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "file.h"
#ifdef WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
