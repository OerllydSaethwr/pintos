//
// Created by Raghav Khanna on 1/12/19.
//

#include "utils.h"
#include "userprog/pagedir.h"
#include <stdio.h>


bool verify_stack_access(const void *ptr, void *esp)
{

  printf("Verifying\n");
  /* Valid pointer if it's above  esp or 4 below (PUSH) or 32 below (PUSHA) */
  return (ptr >= (const void *) PHYS_BASE - MAX_STACK_SIZE && ptr < PHYS_BASE)
         && (ptr >= esp || ptr == esp - 4 || ptr == esp - 32);
}