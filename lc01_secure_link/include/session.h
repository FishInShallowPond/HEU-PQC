#ifndef LC_SESSION_H
#define LC_SESSION_H
#include "chip.h"
/* IO callback transfers all requested bytes or fails, including partial transfer/EOF/cancel. */
typedef struct { void *ctx; int (*read)(void *,uint8_t *,size_t,char *);
 int (*write)(void *,const uint8_t *,size_t,char *); } lc_io;
typedef struct {
 uint8_t sid[16],tx_key[32],rx_key[32],tx_prefix[4],rx_prefix[4];
 uint8_t transcript[32],local_k[32];
 uint64_t tx_sequence,rx_sequence,tx_bytes,rx_bytes;
 int role,ready,confirmed,mode;
 char fingerprint[65];
} lc_session;
/* role: 0=A listener/KEM owner, 1=B connector/encapsulator. Does not grant business ready until confirm. */
int lc_handshake(lc_session *s,lc_device *d,lc_io *io,int role,lc_hooks hooks,char *err);
int lc_session_confirm(lc_session *s,lc_io *io,int accept,char *err);
void lc_session_close(lc_session *s);
enum { LC_TEXT=1,LC_ACK=2,LC_FILE_BEGIN=3,LC_FILE_CHUNK=4,LC_FILE_END=5,
 LC_REKEY_REQUEST=6,LC_REKEY_START=7,LC_CLOSE=8 };
int lc_record_send(lc_session *s,lc_io *io,uint8_t type,const uint8_t *data,size_t n,char *err);
int lc_record_receive(lc_session *s,lc_io *io,uint8_t *type,uint8_t *data,size_t cap,size_t *n,char *err);
int lc_session_selftest(char *err);
#endif
