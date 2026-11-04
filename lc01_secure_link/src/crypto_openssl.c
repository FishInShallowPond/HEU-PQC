#include "crypto.h"
#include "chip.h"
#include <limits.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

int lc_random(uint8_t *out, size_t n)
{
    if (!n) return 1;
    if (!out) return 0;
    if (RAND_bytes_ex(NULL, out, n, 0) == 1) return 1;
    lc_zero(out, n);
    return 0;
}

void *lc_hash_new(void)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx && EVP_DigestInit_ex2(ctx, EVP_sha256(), NULL) == 1) return ctx;
    EVP_MD_CTX_free(ctx);
    return NULL;
}

int lc_hash_update(void *hash, const void *data, size_t n)
{
    if (!hash || (!data && n)) return 0;
    return !n || EVP_DigestUpdate(hash, data, n) == 1;
}

int lc_hash_final(void *hash, uint8_t out[32])
{
    unsigned int n = 0;
    int ok = hash && out && EVP_DigestFinal_ex(hash, out, &n) == 1 && n == 32;
    EVP_MD_CTX_free(hash);
    if (!ok && out) lc_zero(out, 32);
    return ok;
}

void lc_hash_free(void *hash)
{
    EVP_MD_CTX_free(hash);
}

int lc_sha256(const void *data, size_t n, uint8_t out[32])
{
    void *ctx = lc_hash_new();
    if (!out || !lc_hash_update(ctx, data, n)) {
        lc_hash_free(ctx);
        if (out) lc_zero(out, 32);
        return 0;
    }
    return lc_hash_final(ctx, out);
}

int lc_hmac(const uint8_t *key, size_t kn, const void *data, size_t n, uint8_t out[32])
{
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    unsigned char empty = 0;
    size_t written = 0;
    int ok = 0;
    if (!out || (!key && kn) || (!data && n)) goto done;
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac || !(ctx = EVP_MAC_CTX_new(mac))) goto done;
    if (EVP_MAC_init(ctx, key ? key : &empty, kn, params) != 1 ||
        (n && EVP_MAC_update(ctx, data, n) != 1) ||
        EVP_MAC_final(ctx, out, &written, 32) != 1 || written != 32) goto done;
    ok = 1;
done:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    if (!ok && out) lc_zero(out, 32);
    return ok;
}

int lc_hkdf(const uint8_t *secret, size_t sn, const uint8_t *salt, size_t salt_n,
            const uint8_t *info, size_t info_n, uint8_t *out, size_t n)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[6];
    unsigned char empty = 0;
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    int ok = 0;
    /* RFC 5869's expand bound for SHA-256. Reject before allocating. */
    if (n > 255u*32u) return 0;
    if ((!out && n) || (!secret && sn) || (!salt && salt_n) || (!info && info_n)) goto done;
    if (!n) return 1;
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                (void *)(secret ? secret : &empty), sn);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                (void *)(salt ? salt : &empty), salt_n);
    params[4] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                (void *)(info ? info : &empty), info_n);
    params[5] = OSSL_PARAM_construct_end();
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf || !(ctx = EVP_KDF_CTX_new(kdf))) goto done;
    ok = EVP_KDF_derive(ctx, out, n, params) == 1;
done:
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    if (!ok && out) lc_zero(out, n);
    return ok;
}

static int gcm(int encrypt, const uint8_t key[32], const uint8_t nonce[12],
               const uint8_t *aad, size_t an, const uint8_t *in, size_t n,
               uint8_t *out, const uint8_t *input_tag, uint8_t *output_tag)
{
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t tail[16] = {0};
    int written = 0, final_n = 0, ok = 0;
    /* EVP update takes int lengths; never narrow an unchecked size_t. */
    if (n > INT_MAX) return 0;
    if (an > INT_MAX || !key || !nonce || (!aad && an) || (!in && n) ||
        (!out && n) || (encrypt ? !output_tag : !input_tag)) goto done;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_CipherInit_ex2(ctx, EVP_aes_256_gcm(), key, nonce, encrypt, NULL) != 1)
        goto done;
    if (an && EVP_CipherUpdate(ctx, NULL, &written, aad, (int)an) != 1) goto done;
    if (n && (EVP_CipherUpdate(ctx, out, &written, in, (int)n) != 1 ||
              written != (int)n)) goto done;
    if (!encrypt && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)input_tag) != 1)
        goto done;
    if (EVP_CipherFinal_ex(ctx, tail, &final_n) != 1 || final_n != 0) goto done;
    if (encrypt && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, output_tag) != 1)
        goto done;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    lc_zero(tail, sizeof(tail));
    if (!ok) {
        if (out) lc_zero(out, n);
        if (output_tag) lc_zero(output_tag, 16);
    }
    return ok;
}

int lc_aead_seal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t an,
                 const uint8_t *plain, size_t n, uint8_t *cipher, uint8_t tag[16])
{
    return gcm(1, key, nonce, aad, an, plain, n, cipher, NULL, tag);
}

int lc_aead_open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t an,
                 const uint8_t *cipher, size_t n, const uint8_t tag[16], uint8_t *plain)
{
    return gcm(0, key, nonce, aad, an, cipher, n, plain, tag, NULL);
}

int lc_equal(const void *a, const void *b, size_t n)
{
    if (!n) return 1;
    return a && b && CRYPTO_memcmp(a, b, n) == 0;
}

static int kat_equal(const uint8_t *p, size_t n, const char *hex)
{
    uint8_t expected[64];
    return n <= sizeof(expected) && lc_unhex(hex, expected, n) && lc_equal(p, expected, n);
}

static int pqc_selftest(void)
{
    lc_device_config config;
    lc_device *a = NULL, *b = NULL;
    uint8_t pk[LC_PK_MAX], sig[LC_SIG_MAX], ct[LC_CT_MAX];
    uint8_t ka[32] = {0}, kb[32] = {0}, zero[32] = {0};
    uint8_t message[33] = {0x31};
    size_t pn = sizeof(pk), sn = sizeof(sig), cn = sizeof(ct);
    int ok = 0;
    memset(&config, 0, sizeof(config));
    config.mode = LC_SOFTWARE;
    a = lc_sw_open(&config, NULL);
    b = lc_sw_open(&config, NULL);
    if (!a || !b || !lc_device_sign_keygen(a, pk, &pn, NULL) ||
        !pn || pn > sizeof(pk) || !lc_device_sign(a, message, sig, &sn, NULL) ||
        !sn || sn > sizeof(sig) || !lc_device_verify(b, pk, pn, message, sig, sn, NULL))
        goto done;
    message[32] ^= 1;
    if (lc_device_verify(b, pk, pn, message, sig, sn, NULL)) goto done;
    message[32] ^= 1;
    sig[sn-1] ^= 1;
    if (lc_device_verify(b, pk, pn, message, sig, sn, NULL)) goto done;
    pn = sizeof(pk);
    if (!lc_device_kem_keygen(a, pk, &pn, NULL) || !pn || pn > sizeof(pk) ||
        !lc_device_encaps(b, pk, pn, ct, &cn, kb, NULL) || !cn || cn > sizeof(ct) ||
        !lc_device_decaps(a, ct, cn, ka, NULL) || !lc_equal(ka, kb, sizeof(ka))) goto done;
    ct[0] ^= 1;
    if (!lc_device_decaps(a, ct, cn, ka, NULL) || lc_equal(ka, kb, sizeof(ka))) goto done;
    memset(ka, 0xa5, sizeof(ka));
    if (lc_device_decaps(a, ct, cn-1, ka, NULL) || !lc_equal(ka, zero, sizeof(ka))) goto done;
    ok = 1;
done:
    lc_zero(ka, sizeof(ka));
    lc_zero(kb, sizeof(kb));
    lc_device_close(a);
    lc_device_close(b);
    return ok;
}

int lc_crypto_selftest(char *err)
{
    uint8_t out[64], ikm[22], salt[13], info[10], mac_key[20];
    uint8_t key[32] = {0}, nonce[12] = {0}, plain[16] = {0}, ct[16], tag[16];
    void *hash = NULL;
    const char *failure = "SHA-256 self-test failed";
    size_t i;
    int ok = 0;
    if (!lc_sha256("abc", 3, out) ||
        !kat_equal(out, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
        goto done;
    hash = lc_hash_new();
    if (!hash || !lc_hash_update(hash, "a", 1) || !lc_hash_update(hash, "bc", 2)) goto done;
    {
        int hash_ok = lc_hash_final(hash, out);
        hash = NULL;
        if (!hash_ok || !kat_equal(out, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
            goto done;
    }
    failure = "HMAC-SHA256 self-test failed";
    memset(mac_key, 0x0b, sizeof(mac_key));
    if (!lc_hmac(mac_key, sizeof(mac_key), "Hi There", 8, out) ||
        !kat_equal(out, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"))
        goto done;
    failure = "HKDF-SHA256 RFC5869 case 1 failed";
    memset(ikm, 0x0b, sizeof(ikm));
    for (i = 0; i < sizeof(salt); ++i) salt[i] = (uint8_t)i;
    for (i = 0; i < sizeof(info); ++i) info[i] = (uint8_t)(0xf0+i);
    if (!lc_hkdf(ikm, sizeof(ikm), salt, sizeof(salt), info, sizeof(info), out, 42) ||
        !kat_equal(out, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))
        goto done;
    failure = "AES-256-GCM known answer failed";
    if (!lc_aead_seal(key, nonce, NULL, 0, plain, sizeof(plain), ct, tag) ||
        !kat_equal(ct, 16, "cea7403d4d606b6e074ec5d3baf39d18") ||
        !kat_equal(tag, 16, "d0d1c8a799996bf0265b98b5d48ab919") ||
        !lc_aead_open(key, nonce, NULL, 0, ct, sizeof(ct), tag, out) ||
        !lc_equal(out, plain, sizeof(plain))) goto done;
    failure = "AES-256-GCM tamper rejection failed";
    tag[0] ^= 1;
    memset(out, 0xa5, 16);
    if (lc_aead_open(key, nonce, NULL, 0, ct, sizeof(ct), tag, out) ||
        !lc_equal(out, plain, 16)) goto done;
    failure = "Random generator self-test failed";
    if (!lc_random(out, sizeof(out))) goto done;
    failure = "Software ML-DSA-44 / ML-KEM-512 self-test failed";
    if (!pqc_selftest()) goto done;
    ok = 1;
done:
    lc_hash_free(hash);
    lc_zero(out, sizeof(out));
    lc_zero(ikm, sizeof(ikm));
    lc_zero(mac_key, sizeof(mac_key));
    if (!ok) return lc_error(err, failure);
    if (err) memset(err, 0, LC_ERR_MAX);
    return 1;
}
