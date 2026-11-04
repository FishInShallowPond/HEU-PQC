#ifndef LC_APP_H
#define LC_APP_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
/* Entry points owned by main.c; neither opens a console or handles CLI options. */
int lc_gui_run(HINSTANCE instance, int show);
/* No hardware/network operations, no interactive dialogs; returns zero on success. */
int lc_gui_smoke(void);
#endif
