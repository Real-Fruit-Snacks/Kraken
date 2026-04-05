/*
 * simple.c - Simplest BOF test with no format arguments
 */

#include <windows.h>
#include "beacon.h"

void go(char* args, int len) {
    // Use BeaconOutput instead of BeaconPrintf to avoid varargs
    char msg[] = "Hello from BOF!\n";
    BeaconOutput(CALLBACK_OUTPUT, msg, sizeof(msg) - 1);
}
