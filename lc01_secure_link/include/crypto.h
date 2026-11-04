#ifndef LC_CRYPTO_H
#define LC_CRYPTO_H
#include "lc.h"
int lc_random(uint8_t *out,size_t n);
int lc_sha256(const void *data,size_t n,uint8_t out[32]);
void *lc_hash_new(void);
int lc_hash_update(void *hash,const void *data,size_t n);
int lc_hash_final(void *hash,uint8_t out[32]); /* consumes hash */
void lc_hash_free(void *hash);
int lc_hmac(const uint8_t *key,size_t kn,const void *data,size_t n,uint8_t out[32]);
int lc_hkdf(const uint8_t *secret,size_t sn,const uint8_t *salt,size_t salt_n,
            const uint8_t *info,size_t info_n,uint8_t *out,size_t n);
int lc_aead_seal(const uint8_t key[32],const uint8_t nonce[12],const uint8_t *aad,size_t an,
                 const uint8_t *plain,size_t n,uint8_t *cipher,uint8_t tag[16]);
int lc_aead_open(const uint8_t key[32],const uint8_t nonce[12],const uint8_t *aad,size_t an,
                 const uint8_t *cipher,size_t n,const uint8_t tag[16],uint8_t *plain);
int lc_equal(const void *a,const void *b,size_t n);
int lc_crypto_selftest(char *err);
#endif
