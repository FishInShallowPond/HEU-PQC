#include "crypto.h"
#include "chip.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

static unsigned checks, failures;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); ++failures; \
} } while (0)

#ifdef LC_CRYPTO_TEST_FAULTS
/* Optional GNU linker injection: -Wl,--wrap=EVP_DigestFinal_ex.
   The regular build has no replacements for any cryptographic operation. */
static unsigned digest_fault_at, digest_final_calls;
static int pqc_unavailable;
EVP_PKEY_CTX *__real_EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *, const char *, const char *);
EVP_PKEY_CTX *__wrap_EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx,
                                              const char *name, const char *props)
{
    if (pqc_unavailable && strcmp(name, "ML-DSA-44") == 0) return NULL;
    return __real_EVP_PKEY_CTX_new_from_name(libctx, name, props);
}
int __real_EVP_DigestFinal_ex(EVP_MD_CTX *, unsigned char *, unsigned int *);
int __wrap_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *out, unsigned int *n)
{
    int rc = __real_EVP_DigestFinal_ex(ctx, out, n);
    ++digest_final_calls;
    if (digest_fault_at && digest_final_calls == digest_fault_at && rc == 1 && *n)
        out[0] ^= 1;
    return rc;
}
#endif

static int filled(const void *p, size_t n, unsigned char value)
{
    const unsigned char *b = p;
    size_t i;
    for (i = 0; i < n; ++i) if (b[i] != value) return 0;
    return 1;
}

static int matches(const uint8_t *p, size_t n, const char *hex)
{
    /* Decode the independent fixture without relying on lc_unhex. */
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; ++i) {
        if (hex[2*i] != digits[p[i] >> 4] ||
            hex[2*i+1] != digits[p[i] & 15]) return 0;
    }
    return hex[2*n] == '\0';
}

static void test_common(void)
{
    uint8_t b[8] = {0};
    char hex[17], long_text[300];
    struct { char before; char text[LC_ERR_MAX]; char after; } e;
    size_t i;
    lc_put64(b, UINT64_C(0x0123456789abcdef));
    CHECK(matches(b, 8, "0123456789abcdef"));
    CHECK(lc_get64(b) == UINT64_C(0x0123456789abcdef));
    lc_put32(b+1, UINT32_C(0x89abcdef));
    CHECK(matches(b+1, 4, "89abcdef"));
    CHECK(lc_get32(b+1) == UINT32_C(0x89abcdef));
    CHECK(lc_unhex("0123456789aBcDeF", b, 8));
    lc_hex(b, 8, hex);
    CHECK(strcmp(hex, "0123456789abcdef") == 0);
    CHECK(!lc_unhex("0123456789abcdef0", b, 8));
    CHECK(!lc_unhex("01", b, 8));
    CHECK(!lc_unhex("0123456789abcdeg", b, 8));
    CHECK(lc_unhex("", NULL, 0));
    lc_zero(b, sizeof(b));
    CHECK(filled(b, sizeof(b), 0));
    lc_zero(NULL, 0);
    memset(&e, 'X', sizeof(e));
    CHECK(lc_error(e.text, "bad\n\xff input") == 0);
    CHECK(e.before == 'X' && e.after == 'X');
    CHECK(e.text[LC_ERR_MAX-1] == '\0');
    for (i = 0; i < LC_ERR_MAX; ++i)
        CHECK(e.text[i] == 0 || (e.text[i] >= 32 && e.text[i] <= 126));
    memset(long_text, 'a', sizeof(long_text));
    long_text[sizeof(long_text)-1] = '\0';
    CHECK(!lc_error(e.text, long_text));
    CHECK(strlen(e.text) == LC_ERR_MAX-1);
    CHECK(e.before == 'X' && e.after == 'X');
    CHECK(!lc_error(NULL, "failure"));
}

static void test_hash_mac_kdf(void)
{
    uint8_t out[64], ikm[22], salt[13], info[10], key[20];
    void *h;
    size_t i;
    CHECK(lc_sha256("abc", 3, out));
    CHECK(matches(out, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK(lc_sha256(NULL, 0, out));
    CHECK(matches(out, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    h = lc_hash_new();
    CHECK(h != NULL);
    CHECK(lc_hash_update(h, "a", 1));
    CHECK(lc_hash_update(h, NULL, 0));
    CHECK(lc_hash_update(h, "bc", 2));
    CHECK(lc_hash_final(h, out));
    CHECK(matches(out, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    lc_hash_free(lc_hash_new());
    lc_hash_free(NULL);
    CHECK(!lc_hash_update(NULL, "x", 1));
    CHECK(!lc_hash_final(NULL, out));
    memset(out, 0xa5, 32);
    CHECK(!lc_sha256(NULL, 1, out));
    CHECK(filled(out, 32, 0));
    memset(key, 0x0b, sizeof(key));
    CHECK(lc_hmac(key, sizeof(key), "Hi There", 8, out));
    CHECK(matches(out, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    CHECK(lc_hmac(NULL, 0, NULL, 0, out));
    CHECK(matches(out, 32, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"));
    memset(out, 0xa5, 32);
    CHECK(!lc_hmac(NULL, 1, "message", 7, out));
    CHECK(filled(out, 32, 0));
    memset(ikm, 0x0b, sizeof(ikm));
    for (i = 0; i < sizeof(salt); ++i) salt[i] = (uint8_t)i;
    for (i = 0; i < sizeof(info); ++i) info[i] = (uint8_t)(0xf0+i);
    CHECK(lc_hkdf(ikm, sizeof(ikm), salt, sizeof(salt), info, sizeof(info), out, 42));
    CHECK(matches(out, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    CHECK(lc_hkdf(ikm, sizeof(ikm), NULL, 0, NULL, 0, out, 42));
    CHECK(matches(out, 42, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"));
    CHECK(!lc_hkdf(NULL, 1, salt, sizeof(salt), info, sizeof(info), out, 42));
    CHECK(filled(out, 42, 0));
    CHECK(lc_hkdf(ikm, sizeof(ikm), NULL, 0, NULL, 0, NULL, 0));
    CHECK(lc_random(out, sizeof(out)));
    CHECK(lc_random(NULL, 0));
    CHECK(!lc_random(NULL, 1));
    CHECK(lc_equal(out, out, sizeof(out)));
    memcpy(out+32, out, 32);
    out[63] ^= 1;
    CHECK(!lc_equal(out, out+32, 32));
    out[63] ^= 1;
    out[32] ^= 1;
    CHECK(!lc_equal(out, out+32, 32));
    CHECK(lc_equal(NULL, NULL, 0));
    CHECK(!lc_equal(NULL, out, 1));
}

static void test_gcm(void)
{
    uint8_t key[32] = {0}, iv[12] = {0}, plain[16] = {0};
    uint8_t ct[16], tag[16], out[16], aad[1] = {7};
    CHECK(lc_aead_seal(key, iv, NULL, 0, plain, sizeof(plain), ct, tag));
    CHECK(matches(ct, 16, "cea7403d4d606b6e074ec5d3baf39d18"));
    CHECK(matches(tag, 16, "d0d1c8a799996bf0265b98b5d48ab919"));
    CHECK(lc_aead_open(key, iv, NULL, 0, ct, sizeof(ct), tag, out));
    CHECK(filled(out, sizeof(out), 0));
    tag[0] ^= 1;
    memset(out, 0xa5, sizeof(out));
    CHECK(!lc_aead_open(key, iv, NULL, 0, ct, sizeof(ct), tag, out));
    CHECK(filled(out, sizeof(out), 0));
    tag[0] ^= 1;
    ct[15] ^= 1;
    memset(out, 0xa5, sizeof(out));
    CHECK(!lc_aead_open(key, iv, NULL, 0, ct, sizeof(ct), tag, out));
    CHECK(filled(out, sizeof(out), 0));
    ct[15] ^= 1;
    CHECK(lc_aead_seal(key, iv, aad, 1, plain, sizeof(plain), ct, tag));
    aad[0] ^= 1;
    memset(out, 0xa5, sizeof(out));
    CHECK(!lc_aead_open(key, iv, aad, 1, ct, sizeof(ct), tag, out));
    CHECK(filled(out, sizeof(out), 0));
    aad[0] ^= 1;
    CHECK(lc_aead_open(key, iv, aad, 1, ct, sizeof(ct), tag, ct));
    CHECK(filled(ct, sizeof(ct), 0));
    CHECK(lc_aead_seal(key, iv, NULL, 0, NULL, 0, NULL, tag));
    CHECK(matches(tag, 16, "530f8afbc74536b9a963b4f1c4cb738b"));
    CHECK(lc_aead_open(key, iv, NULL, 0, NULL, 0, tag, NULL));
    tag[0] ^= 1;
    CHECK(!lc_aead_open(key, iv, NULL, 0, NULL, 0, tag, NULL));
    memset(out, 0xa5, sizeof(out));
    CHECK(!lc_aead_open(NULL, iv, NULL, 0, ct, sizeof(ct), tag, out));
    CHECK(filled(out, sizeof(out), 0));
    /* Reject lengths before narrowing to the EVP int update interface. */
    CHECK(!lc_aead_seal(key, iv, aad, (size_t)INT_MAX+1u, plain, 16, ct, tag));
}

static EVP_PKEY *import_pk(const char *name, uint8_t *pk, size_t pn)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pk, pn);
    params[1] = OSSL_PARAM_construct_end();
    if (!ctx || EVP_PKEY_fromdata_init(ctx) != 1 ||
        EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static void test_devices(void)
{
    lc_device_config config;
    lc_device *a, *b;
    char err[LC_ERR_MAX] = {0};
    uint8_t pk[LC_PK_MAX], other[LC_PK_MAX], kem_pk[LC_PK_MAX];
    uint8_t sig[LC_SIG_MAX], ct[LC_CT_MAX], ka[32], kb[32];
    uint8_t message[34] = {0};
    size_t pn = sizeof(pk), on = sizeof(other), kn = sizeof(kem_pk);
    size_t sn = sizeof(sig), cn = sizeof(ct), small, i;
    EVP_PKEY *external;
    EVP_MD_CTX *md;
    EVP_PKEY_CTX *kctx;
    memset(&config, 0, sizeof(config));
    config.mode = LC_SOFTWARE;
    a = lc_device_open(&config, err);
    b = lc_sw_open(&config, err);
    CHECK(a != NULL && b != NULL);
    if (!a || !b) { lc_device_close(a); lc_device_close(b); return; }
    CHECK(lc_device_mode(a) == LC_SOFTWARE);
    CHECK(strstr(lc_device_algorithms(a), "ML-DSA-44") != NULL);
    CHECK(strstr(lc_device_algorithms(a), "ML-KEM-512") != NULL);
    CHECK(!lc_device_sign(a, message, sig, &sn, err));
    CHECK(!lc_device_decaps(a, ct, 768, ka, err));
    CHECK(filled(ka, sizeof(ka), 0));
    small = 1;
    pk[0] = 0xa5;
    CHECK(!lc_device_sign_keygen(a, pk, &small, err));
    CHECK(pk[0] == 0xa5);
    CHECK(lc_device_sign_keygen(a, pk, &pn, err));
    CHECK(pn == 1312);
    CHECK(lc_device_sign_keygen(b, other, &on, err));
    CHECK(pn == on && !lc_equal(pk, other, pn));
    message[32] = 0x5a;
    sn = sizeof(sig);
    CHECK(lc_device_sign(a, message, sig, &sn, err));
    CHECK(sn == 2420);
    CHECK(lc_device_verify(b, pk, pn, message, sig, sn, err));
    for (i = 0; i < 33; ++i) {
        message[i] ^= 1;
        CHECK(!lc_device_verify(b, pk, pn, message, sig, sn, err));
        message[i] ^= 1;
    }
    message[33] ^= 1;
    CHECK(lc_device_verify(b, pk, pn, message, sig, sn, err));
    sig[sn-1] ^= 1;
    CHECK(!lc_device_verify(b, pk, pn, message, sig, sn, err));
    sig[sn-1] ^= 1;
    CHECK(!lc_device_verify(b, other, on, message, sig, sn, err));
    CHECK(!lc_device_verify(b, pk, pn-1, message, sig, sn, err));
    CHECK(!lc_device_verify(b, pk, LC_PK_MAX+1u, message, sig, sn, err));
    CHECK(!lc_device_verify(b, pk, pn, message, sig, sn-1, err));
    small = 1;
    CHECK(!lc_device_sign_keygen(a, other, &small, err));
    sn = sizeof(sig);
    CHECK(lc_device_sign(a, message, sig, &sn, err));
    CHECK(lc_device_verify(b, pk, pn, message, sig, sn, err));
    small = 1;
    sig[0] = 0xa5;
    CHECK(!lc_device_sign(a, message, sig, &small, err));
    CHECK(sig[0] == 0xa5);
    sn = sizeof(sig);
    CHECK(lc_device_sign(a, message, sig, &sn, err));
    /* Independent EVP verification catches prehash/simulation and wrong lengths. */
    external = import_pk("ML-DSA-44", pk, pn);
    md = EVP_MD_CTX_new();
    CHECK(external != NULL && md != NULL);
    if (external && md) {
        CHECK(EVP_DigestVerifyInit_ex(md, NULL, NULL, NULL, NULL, external, NULL) == 1);
        CHECK(EVP_DigestVerify(md, sig, sn, message, 33) == 1);
        CHECK(EVP_DigestVerify(md, sig, sn, message, 32) != 1);
        CHECK(EVP_DigestVerify(md, sig, sn, message, 34) != 1);
    }
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(external);
    on = sizeof(other);
    CHECK(lc_device_sign_keygen(a, other, &on, err));
    sn = sizeof(sig);
    CHECK(lc_device_sign(a, message, sig, &sn, err));
    CHECK(!lc_device_verify(b, pk, pn, message, sig, sn, err));
    CHECK(lc_device_verify(b, other, on, message, sig, sn, err));
    CHECK(lc_device_kem_keygen(a, kem_pk, &kn, err));
    CHECK(kn == 800);
    small = 1;
    ct[0] = 0xa5;
    memset(kb, 0xa5, sizeof(kb));
    CHECK(!lc_device_encaps(b, kem_pk, kn, ct, &small, kb, err));
    CHECK(ct[0] == 0xa5 && filled(kb, sizeof(kb), 0));
    CHECK(lc_device_encaps(b, kem_pk, kn, ct, &cn, kb, err));
    CHECK(cn == 768);
    CHECK(lc_device_decaps(a, ct, cn, ka, err));
    CHECK(lc_equal(ka, kb, 32));
    small = 1;
    CHECK(!lc_device_kem_keygen(a, other, &small, err));
    CHECK(lc_device_decaps(a, ct, cn, ka, err));
    CHECK(lc_equal(ka, kb, 32));
    CHECK(!lc_device_verify(b, kem_pk, kn, message, sig, sn, err));
    CHECK(!lc_device_encaps(b, pk, pn, ct, &cn, kb, err));
    CHECK(filled(kb, sizeof(kb), 0));
    /* Independent EVP encapsulation proves the wire key is genuine ML-KEM. */
    external = import_pk("ML-KEM-512", kem_pk, kn);
    kctx = external ? EVP_PKEY_CTX_new_from_pkey(NULL, external, NULL) : NULL;
    CHECK(kctx != NULL);
    if (kctx) {
        size_t key_n = sizeof(kb);
        cn = sizeof(ct);
        CHECK(EVP_PKEY_encapsulate_init(kctx, NULL) == 1);
        CHECK(EVP_PKEY_encapsulate(kctx, ct, &cn, kb, &key_n) == 1);
        CHECK(key_n == 32 && cn == 768);
        CHECK(lc_device_decaps(a, ct, cn, ka, err));
        CHECK(lc_equal(ka, kb, 32));
        ct[0] ^= 1;
        /* ML-KEM implicitly rejects a full-length altered CT with a different key. */
        CHECK(lc_device_decaps(a, ct, cn, ka, err));
        CHECK(!lc_equal(ka, kb, 32));
        CHECK(!lc_device_decaps(a, ct, cn-1, ka, err));
        CHECK(filled(ka, sizeof(ka), 0));
        ct[0] ^= 1;
        on = sizeof(other);
        CHECK(lc_device_kem_keygen(a, other, &on, err));
        CHECK(lc_device_decaps(a, ct, cn, ka, err));
        CHECK(!lc_equal(ka, kb, 32));
    }
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(external);
    lc_device_close(a);
    lc_device_close(b);
    lc_device_close(NULL);
    CHECK(!lc_device_open(NULL, err));
    config.mode = 99;
    CHECK(!lc_device_open(&config, err));
    CHECK(!lc_device_sign(NULL, message, sig, &sn, err));
}

static void test_fail_closed(void)
{
    lc_device_config config;
    lc_device *dev;
    char err[LC_ERR_MAX] = {0};
    memset(&config, 0, sizeof(config));
    config.mode = LC_SOFTWARE;
    /* A missing algorithm must fail, without a software simulation fallback. */
    CHECK(EVP_set_default_properties(NULL, "provider=lc-test-unavailable") == 1);
    dev = lc_device_open(&config, err);
    CHECK(dev == NULL);
    lc_device_close(dev);
    CHECK(!lc_crypto_selftest(err));
    CHECK(err[0] != '\0');
    CHECK(EVP_set_default_properties(NULL, "") == 1);
#ifdef LC_CRYPTO_TEST_FAULTS
    for (digest_fault_at = 1; digest_fault_at <= 2; ++digest_fault_at) {
        digest_final_calls = 0;
        CHECK(!lc_crypto_selftest(err));
        CHECK(err[0] != '\0');
    }
    digest_fault_at = 0;
    pqc_unavailable = 1;
    CHECK(!lc_crypto_selftest(err));
    CHECK(err[0] != '\0');
    pqc_unavailable = 0;
#endif
}

int main(void)
{
    char err[LC_ERR_MAX] = {0};
    test_common();
    test_hash_mac_kdf();
    test_gcm();
    test_devices();
    test_fail_closed();
    CHECK(lc_crypto_selftest(err));
    if (failures) fprintf(stderr, "%s\n", err);
    printf("crypto: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
