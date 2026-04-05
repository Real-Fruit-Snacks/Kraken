/*
 * hello.c - Simple test BOF
 * Outputs "Hello from BOF!" to verify the loader works
 */

#include <windows.h>
#include "beacon.h"

void go(char* args, int len) {
    BeaconPrintf(CALLBACK_OUTPUT, "Hello from BOF!");
    BeaconPrintf(CALLBACK_OUTPUT, "Args length: %d", len);
}
