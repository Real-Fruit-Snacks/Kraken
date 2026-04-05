/*
 * noop.c - Minimal BOF that does nothing
 * Tests if the loader can call an entry point at all
 */

void go(char* args, int len) {
    // Do absolutely nothing
    (void)args;
    (void)len;
}
