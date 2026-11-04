#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "crypto.h"
#include "chip.h"
#include "session.h"
#include "app.h"

static void enable_dpi_awareness(void)
{
    HMODULE user = GetModuleHandleW(L"user32.dll");
    typedef BOOL (WINAPI *dpi_context_fn)(HANDLE);
    typedef BOOL (WINAPI *dpi_aware_fn)(void);
    dpi_context_fn set_context = NULL;
    dpi_aware_fn set_aware = NULL;
    FARPROC context_proc = user ? GetProcAddress(user, "SetProcessDpiAwarenessContext") : NULL;
    FARPROC aware_proc = user ? GetProcAddress(user, "SetProcessDPIAware") : NULL;
    if (context_proc) memcpy(&set_context, &context_proc, sizeof(set_context));
    if (aware_proc) memcpy(&set_aware, &aware_proc, sizeof(set_aware));
    if (set_context) set_context((HANDLE)(INT_PTR)-4);
    else if (set_aware) set_aware();
}

int main(int argc,char **argv)
{
    enable_dpi_awareness();
    (void)argc;(void)argv;
    if(argc>1 && !strcmp(argv[1],"--gui-smoke"))return lc_gui_smoke();
    if(argc>1 && !strcmp(argv[1],"--self-test")) {
        char err[LC_ERR_MAX]={0};
        if(!lc_crypto_selftest(err)||!lc_hw_selftest(err)||!lc_session_selftest(err)) {
            fprintf(stderr,"FAIL: %s\n",err);return 1;
        }
        puts("PASS: crypto vectors, LC01 framing, authenticated records and rejection paths");return 0;
    }
    return lc_gui_run(GetModuleHandleW(NULL),SW_SHOWNORMAL);
}
