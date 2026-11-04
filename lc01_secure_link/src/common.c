#include "lc.h"
#include <string.h>

void lc_zero(void *p, size_t n)
{
    volatile unsigned char *b = p;
    if (b) while (n--) *b++ = 0;
}

void lc_hex(const uint8_t *p, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;
    if (!out) return;
    if ((!p && n) || n > (SIZE_MAX-1)/2) { out[0] = '\0'; return; }
    for (i = 0; i < n; ++i) {
        out[2*i] = digits[p[i] >> 4];
        out[2*i+1] = digits[p[i] & 15];
    }
    out[2*n] = '\0';
}

static int nibble(unsigned char c)
{
    if (c >= '0' && c <= '9') return c-'0';
    if (c >= 'a' && c <= 'f') return c-'a'+10;
    if (c >= 'A' && c <= 'F') return c-'A'+10;
    return -1;
}

int lc_unhex(const char *p, uint8_t *out, size_t n)
{
    size_t i;
    if (!p || (!out && n) || n > (SIZE_MAX-1)/2) return 0;
    /* Validate first: malformed input never publishes a partial field. */
    for (i = 0; i < 2*n; ++i) if (nibble((unsigned char)p[i]) < 0) return 0;
    if (p[2*n] != '\0') return 0;
    for (i = 0; i < n; ++i)
        out[i] = (uint8_t)((nibble((unsigned char)p[2*i]) << 4) |
                          nibble((unsigned char)p[2*i+1]));
    return 1;
}

void lc_put32(uint8_t *p, uint32_t v)
{
    unsigned i;
    for (i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (24-8*i));
}

void lc_put64(uint8_t *p, uint64_t v)
{
    unsigned i;
    for (i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (56-8*i));
}

uint32_t lc_get32(const uint8_t *p)
{
    uint32_t v = 0;
    unsigned i;
    for (i = 0; i < 4; ++i) v = (v << 8) | p[i];
    return v;
}

uint64_t lc_get64(const uint8_t *p)
{
    uint64_t v = 0;
    unsigned i;
    for (i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

int lc_error(char *err, const char *message)
{
    char text[LC_ERR_MAX] = {0};
    size_t i;
    if (!err) return 0;
    if (!message) message = "Unknown error";
    for (i = 0; i < LC_ERR_MAX-1 && message[i]; ++i) {
        unsigned char c = (unsigned char)message[i];
        text[i] = c >= 32 && c <= 126 ? (char)c : '?';
    }
    memcpy(err, text, sizeof(text));
    return 0;
}
