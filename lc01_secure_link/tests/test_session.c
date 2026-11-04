#include "session.h"
#include <stdio.h>
int main(void) { char err[LC_ERR_MAX]={0}; if(!lc_session_selftest(err)) {
 fprintf(stderr,"session tests failed: %s\n",err); return 1; }
 puts("session tests passed");return 0; }
