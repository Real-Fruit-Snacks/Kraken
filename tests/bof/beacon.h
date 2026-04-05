/*
 * Beacon Object File API Header
 * Minimal definitions for BOF development
 */

#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

/* Output types */
#define CALLBACK_OUTPUT      0x00
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d

/* Data parser */
typedef struct {
    char* original;
    char* buffer;
    int length;
    int size;
} datap;

/* Beacon API declarations */
void BeaconPrintf(int type, const char* fmt, ...);
void BeaconOutput(int type, char* data, int len);

void BeaconDataParse(datap* parser, char* buffer, int size);
int BeaconDataInt(datap* parser);
short BeaconDataShort(datap* parser);
int BeaconDataLength(datap* parser);
char* BeaconDataExtract(datap* parser, int* size);

/* Dynamic function resolution macros */
#define DECLSPEC_IMPORT __declspec(dllimport)

/* Common Win32 imports */
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetComputerNameA(LPSTR, LPDWORD);

#endif /* BEACON_H */
