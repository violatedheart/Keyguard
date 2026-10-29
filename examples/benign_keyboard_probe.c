/* Static-import fixture: call once, discard the result, then wait.
 * No hooks, input logging, files, network, or persistence.
 * Build in an MSVC Developer Command Prompt:
 * cl /nologo /W4 /Od benign_keyboard_probe.c user32.lib /Fe:benign_keyboard_probe.exe
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

/** Run a single benign modifier query and remain visible for five minutes. */
int main(void) {
    (void)GetAsyncKeyState(VK_SHIFT);
    printf("Benign static-import probe PID: %lu. No input retained. Ctrl+C to exit.\n",
           (unsigned long)GetCurrentProcessId());
    fflush(stdout);
    Sleep(300000);
    return 0;
}
