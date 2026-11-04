#include "chip.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#define SW_SIGN_PK 1312u
#define SW_SIGN_SIG 2420u
#define SW_KEM_PK 800u
#define SW_KEM_CT 768u

typedef struct {
    lc_device base;
    EVP_PKEY *sign_key;
    EVP_PKEY *kem_key;
} sw_device;

static void sw_close(lc_device *dev)
{
    sw_device *sw = (sw_device *)dev;
    EVP_PKEY_free(sw->sign_key);
    EVP_PKEY_free(sw->kem_key);
    lc_zero(sw, sizeof(*sw));
    free(sw);
}

static EVP_PKEY *sw_import(const char *algorithm, const uint8_t *pk, size_t pn,
                           size_t expected)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2];
    if (!pk || pn != expected || pn > LC_PK_MAX) return NULL;
    ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm, NULL);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pk, pn);
    params[1] = OSSL_PARAM_construct_end();
    if (!ctx || EVP_PKEY_fromdata_init(ctx) != 1 ||
        EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int sw_keygen(EVP_PKEY **slot, const char *algorithm, size_t expected,
                     uint8_t *pk, size_t *pn, char *err)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *candidate = NULL;
    uint8_t public_key[LC_PK_MAX];
    size_t written = 0, cap = pn ? *pn : 0;
    int ok = 0;
    if (pn) *pn = 0;
    if (!pk || !pn || expected > LC_PK_MAX || cap < expected)
        return lc_error(err, "Public key output buffer too small");
    ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) != 1 ||
        EVP_PKEY_generate(ctx, &candidate) != 1 ||
        EVP_PKEY_get_octet_string_param(candidate, OSSL_PKEY_PARAM_PUB_KEY,
                                         public_key, sizeof(public_key), &written) != 1 ||
        written != expected) goto done;
    memcpy(pk, public_key, written);
    *pn = written;
    EVP_PKEY_free(*slot);
    *slot = candidate;
    candidate = NULL;
    ok = 1;
done:
    EVP_PKEY_free(candidate);
    EVP_PKEY_CTX_free(ctx);
    if (!ok) return lc_error(err, "OpenSSL PQC key generation failed");
    return 1;
}

static int sw_sign_keygen(lc_device *dev, uint8_t *pk, size_t *pn, char *err)
{
    return sw_keygen(&((sw_device *)dev)->sign_key, "ML-DSA-44", SW_SIGN_PK, pk, pn, err);
}

static int sw_kem_keygen(lc_device *dev, uint8_t *pk, size_t *pn, char *err)
{
    return sw_keygen(&((sw_device *)dev)->kem_key, "ML-KEM-512", SW_KEM_PK, pk, pn, err);
}

static int sw_sign(lc_device *dev, const uint8_t *message, uint8_t *sig, size_t *sn, char *err)
{
    sw_device *sw = (sw_device *)dev;
    EVP_MD_CTX *ctx = NULL;
    uint8_t signature[SW_SIGN_SIG];
    size_t written = sizeof(signature), cap = sn ? *sn : 0;
    int ok = 0;
    if (sn) *sn = 0;
    if (!sw->sign_key || !message || !sig || !sn || cap < sizeof(signature))
        return lc_error(err, "Signing key missing or invalid signature buffer");
    ctx = EVP_MD_CTX_new();
    /* Pure ML-DSA: the caller's exact 33-byte message, no external prehash. */
    if (!ctx || EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, sw->sign_key, NULL) != 1 ||
        EVP_DigestSign(ctx, signature, &written, message, 33) != 1 ||
        written != SW_SIGN_SIG || written > LC_SIG_MAX) goto done;
    memcpy(sig, signature, written);
    *sn = written;
    ok = 1;
done:
    EVP_MD_CTX_free(ctx);
    if (!ok) return lc_error(err, "OpenSSL ML-DSA-44 signing failed");
    return 1;
}

static int sw_verify(lc_device *dev, const uint8_t *pk, size_t pn,
                     const uint8_t *message, const uint8_t *sig, size_t sn, char *err)
{
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ok = 0;
    (void)dev;
    if (!message || !sig || sn != SW_SIGN_SIG || sn > LC_SIG_MAX) goto done;
    key = sw_import("ML-DSA-44", pk, pn, SW_SIGN_PK);
    ctx = EVP_MD_CTX_new();
    if (!key || !ctx || EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, key, NULL) != 1)
        goto done;
    ok = EVP_DigestVerify(ctx, sig, sn, message, 33) == 1;
done:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    if (!ok) return lc_error(err, "ML-DSA-44 signature verification failed");
    return 1;
}

static int sw_encaps(lc_device *dev, const uint8_t *pk, size_t pn,
                     uint8_t *ct, size_t *cn, uint8_t *key, char *err)
{
    EVP_PKEY *public_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    uint8_t ciphertext[SW_KEM_CT], secret[32] = {0};
    size_t ct_n = sizeof(ciphertext), key_n = sizeof(secret), cap = cn ? *cn : 0;
    int ok = 0;
    (void)dev;
    if (cn) *cn = 0;
    if (!ct || !cn || !key || cap < sizeof(ciphertext)) goto done;
    public_key = sw_import("ML-KEM-512", pk, pn, SW_KEM_PK);
    if (!public_key) goto done;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, public_key, NULL);
    if (!ctx || EVP_PKEY_encapsulate_init(ctx, NULL) != 1 ||
        EVP_PKEY_encapsulate(ctx, ciphertext, &ct_n, secret, &key_n) != 1 ||
        ct_n != SW_KEM_CT || ct_n > LC_CT_MAX || key_n != 32) goto done;
    memcpy(ct, ciphertext, ct_n);
    memcpy(key, secret, sizeof(secret));
    *cn = ct_n;
    ok = 1;
done:
    lc_zero(secret, sizeof(secret));
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    if (!ok) {
        if (key) lc_zero(key, 32);
        return lc_error(err, "ML-KEM-512 encapsulation failed");
    }
    return 1;
}

static int sw_decaps(lc_device *dev, const uint8_t *ct, size_t cn, uint8_t *key, char *err)
{
    sw_device *sw = (sw_device *)dev;
    EVP_PKEY_CTX *ctx = NULL;
    uint8_t secret[32] = {0};
    size_t key_n = sizeof(secret);
    int ok = 0;
    if (!sw->kem_key || !key || !ct || cn != SW_KEM_CT || cn > LC_CT_MAX) goto done;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, sw->kem_key, NULL);
    if (!ctx || EVP_PKEY_decapsulate_init(ctx, NULL) != 1 ||
        EVP_PKEY_decapsulate(ctx, secret, &key_n, ct, cn) != 1 || key_n != 32) goto done;
    /* Full-length invalid ciphertexts use ML-KEM's standard implicit rejection.
       The protocol authenticates the resulting key with key confirmation. */
    memcpy(key, secret, sizeof(secret));
    ok = 1;
done:
    lc_zero(secret, sizeof(secret));
    EVP_PKEY_CTX_free(ctx);
    if (!ok) {
        if (key) lc_zero(key, 32);
        return lc_error(err, "ML-KEM-512 decapsulation failed");
    }
    return 1;
}

static const lc_device_ops sw_ops = {
    sw_close, sw_sign_keygen, sw_sign, sw_verify, sw_kem_keygen, sw_encaps, sw_decaps
};

lc_device *lc_sw_open(const lc_device_config *config, char *err)
{
    sw_device *sw;
    EVP_PKEY_CTX *sign_ctx, *kem_ctx;
    int available;
    if (!config || config->mode != LC_SOFTWARE) {
        lc_error(err, "Invalid software device configuration");
        return NULL;
    }
    sign_ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-44", NULL);
    kem_ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-512", NULL);
    available = sign_ctx && kem_ctx;
    EVP_PKEY_CTX_free(sign_ctx);
    EVP_PKEY_CTX_free(kem_ctx);
    if (!available) {
        lc_error(err, "OpenSSL ML-DSA-44 and ML-KEM-512 are required");
        return NULL;
    }
    sw = calloc(1, sizeof(*sw));
    if (!sw) {
        lc_error(err, "Software device allocation failed");
        return NULL;
    }
    sw->base.ops = &sw_ops;
    sw->base.mode = LC_SOFTWARE;
    return &sw->base;
}

lc_device *lc_device_open(const lc_device_config *config, char *err)
{
    if (config) {
        if (config->mode == LC_SOFTWARE) return lc_sw_open(config, err);
        if (config->mode == LC_HARDWARE) return lc_hw_open(config, err);
    }
    lc_error(err, "Invalid device mode or configuration");
    return NULL;
}

void lc_device_close(lc_device *dev)
{
    if (dev && dev->ops && dev->ops->close) dev->ops->close(dev);
}

int lc_device_mode(const lc_device *dev)
{
    return dev ? dev->mode : 0;
}

const char *lc_device_algorithms(const lc_device *dev)
{
    if (dev && dev->mode == LC_SOFTWARE) return "ML-DSA-44/ML-KEM-512";
    if (dev && dev->mode == LC_HARDWARE) return "Dilithium2/Kyber512";
    return "unavailable";
}

int lc_device_sign_keygen(lc_device *dev, uint8_t *pk, size_t *pn, char *err)
{
    if (!dev || !dev->ops || !dev->ops->sign_keygen) return lc_error(err, "Invalid signing device");
    return dev->ops->sign_keygen(dev, pk, pn, err);
}

int lc_device_sign(lc_device *dev, const uint8_t message[33], uint8_t *sig, size_t *sn, char *err)
{
    if (!dev || !dev->ops || !dev->ops->sign) return lc_error(err, "Invalid signing device");
    return dev->ops->sign(dev, message, sig, sn, err);
}

int lc_device_verify(lc_device *dev, const uint8_t *pk, size_t pn,
                      const uint8_t message[33], const uint8_t *sig, size_t sn, char *err)
{
    if (!dev || !dev->ops || !dev->ops->verify) return lc_error(err, "Invalid verification device");
    return dev->ops->verify(dev, pk, pn, message, sig, sn, err);
}

int lc_device_kem_keygen(lc_device *dev, uint8_t *pk, size_t *pn, char *err)
{
    if (!dev || !dev->ops || !dev->ops->kem_keygen) return lc_error(err, "Invalid KEM device");
    return dev->ops->kem_keygen(dev, pk, pn, err);
}

int lc_device_encaps(lc_device *dev, const uint8_t *pk, size_t pn,
                      uint8_t *ct, size_t *cn, uint8_t key[32], char *err)
{
    if (!dev || !dev->ops || !dev->ops->encaps) {
        if (key) lc_zero(key, 32);
        return lc_error(err, "Invalid KEM device");
    }
    return dev->ops->encaps(dev, pk, pn, ct, cn, key, err);
}

int lc_device_decaps(lc_device *dev, const uint8_t *ct, size_t cn, uint8_t key[32], char *err)
{
    if (!dev || !dev->ops || !dev->ops->decaps) {
        if (key) lc_zero(key, 32);
        return lc_error(err, "Invalid KEM device");
    }
    return dev->ops->decaps(dev, ct, cn, key, err);
}
