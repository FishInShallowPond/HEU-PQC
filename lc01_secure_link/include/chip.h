#ifndef LC_CHIP_H
#define LC_CHIP_H
#include "lc.h"
typedef struct lc_device lc_device;
typedef struct { int mode; const char *port; uint32_t baud;
 uint32_t timeout_ms,interval_ms; lc_hooks hooks; } lc_device_config;
lc_device *lc_device_open(const lc_device_config *config,char *err);
void lc_device_close(lc_device *dev);
int lc_device_mode(const lc_device *dev);
const char *lc_device_algorithms(const lc_device *dev);
/* Public network fields use normal whole-field byte order. Secret keys stay in backend. */
int lc_device_sign_keygen(lc_device *dev,uint8_t *pk,size_t *pn,char *err);
int lc_device_sign(lc_device *dev,const uint8_t message[33],uint8_t *sig,size_t *sn,char *err);
int lc_device_verify(lc_device *dev,const uint8_t *pk,size_t pn,
 const uint8_t message[33],const uint8_t *sig,size_t sn,char *err);
int lc_device_kem_keygen(lc_device *dev,uint8_t *pk,size_t *pn,char *err);
int lc_device_encaps(lc_device *dev,const uint8_t *pk,size_t pn,
 uint8_t *ct,size_t *cn,uint8_t key[32],char *err);
int lc_device_decaps(lc_device *dev,const uint8_t *ct,size_t cn,uint8_t key[32],char *err);
/* Internal backend contract, implemented independently. */
lc_device *lc_hw_open(const lc_device_config *config,char *err);
lc_device *lc_sw_open(const lc_device_config *config,char *err);
typedef struct {
 void (*close)(lc_device *);
 int (*sign_keygen)(lc_device *,uint8_t *,size_t *,char *);
 int (*sign)(lc_device *,const uint8_t *,uint8_t *,size_t *,char *);
 int (*verify)(lc_device *,const uint8_t *,size_t,const uint8_t *,const uint8_t *,size_t,char *);
 int (*kem_keygen)(lc_device *,uint8_t *,size_t *,char *);
 int (*encaps)(lc_device *,const uint8_t *,size_t,uint8_t *,size_t *,uint8_t *,char *);
 int (*decaps)(lc_device *,const uint8_t *,size_t,uint8_t *,char *);
} lc_device_ops;
struct lc_device { const lc_device_ops *ops; int mode; };
/* Pure LC01 protocol helpers, tests use these without opening a COM port. */
size_t lc_hw_frame(uint8_t head,uint8_t opcode,const uint8_t *payload,size_t n,uint8_t *out,size_t cap);
int lc_hw_validate(uint8_t head,uint8_t opcode,const uint8_t *frame,size_t n,
 size_t expected,int ack,uint8_t *out,size_t cap,size_t *out_n,char *err);
size_t lc_hw_message(const uint8_t *message,size_t n,uint8_t *out,size_t cap);
int lc_hw_selftest(char *err);
#endif
