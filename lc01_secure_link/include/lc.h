#ifndef LC_H
#define LC_H
#include <stddef.h>
#include <stdint.h>
#define LC_VERSION "v0"
#define LC_BLOCK 4096u
#define LC_FRAME_MAX 16384u
/* v0 has two fixed profiles; size for those profiles, not hypothetical ones. */
#define LC_PK_MAX 1312u
#define LC_SK_MAX 2528u
#define LC_SIG_MAX 2420u
#define LC_CT_MAX 768u
#define LC_ERR_MAX 256u
#define LC_SESSION_BYTES (64u*1024u*1024u)
#define LC_MAX_FILE (16u*1024u*1024u)
enum { LC_HARDWARE=1, LC_SOFTWARE=2 };
typedef int (*lc_cancel_fn)(void *ctx);
typedef void (*lc_log_fn)(void *ctx, const char *text);
typedef struct { lc_cancel_fn cancelled; lc_log_fn log; void *ctx; } lc_hooks;
void lc_zero(void *p,size_t n);
void lc_hex(const uint8_t *p,size_t n,char *out);
int lc_unhex(const char *p,uint8_t *out,size_t n);
void lc_put32(uint8_t *p,uint32_t v);
void lc_put64(uint8_t *p,uint64_t v);
uint32_t lc_get32(const uint8_t *p);
uint64_t lc_get64(const uint8_t *p);
int lc_error(char *err,const char *message);
#endif
