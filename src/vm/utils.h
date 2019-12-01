//
// Created by Raghav Khanna on 1/12/19.
//

#include "lib/stdbool.h"

#ifndef UTILS
#define UTILS
#define MAX_STACK_SIZE 10485760  /* 10 MiB hard maximum for stack*/


bool verify_stack_access(const void *ptr, void *esp);

#endif
