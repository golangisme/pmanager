#include "crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static_assert(NONCE_LEN == 12, "AES-GCM nonce must be 12 bytes");
static_assert(TAG_LEN   == 16, "AES-GCM tag must be 16 bytes");
static_assert(KEY_LEN   == 32, "AES-256 key must be 32 bytes");

static int rand_uniform(int n, int *out) {
    if (n <= 0) return CRYPTO_ERR_SIZE;

    int     limit = 256 - (256 % n);
    uint8_t r;

    for (int tries = 0; tries < 128; tries++) {
        if (RAND_bytes(&r, 1) != 1) return CRYPTO_ERR_RNG;
        if ((int)r < limit) {
            *out = (int)r % n;
            return CRYPTO_OK;
        }
    }
    return CRYPTO_ERR_RNG;
}

static int pick_one(const char *set, int slen, char *out) {
    int idx;
    int rc = rand_uniform(slen, &idx);
    if (rc != CRYPTO_OK) return rc;
    *out = set[idx];
    return CRYPTO_OK;
}

int random_bytes(uint8_t *buf, size_t len) {
    if (!buf || len == 0)        return CRYPTO_ERR_NULL;
    if (len > (size_t)INT_MAX)   return CRYPTO_ERR_SIZE;
    return RAND_bytes(buf, (int)len) == 1 ? CRYPTO_OK : CRYPTO_ERR_RNG;
}

int derive_key(const char *password, size_t pass_len,
               const uint8_t *salt, const KdfParams *kdf, uint8_t *key) {
    if (!password || !salt || !kdf || !key)          return CRYPTO_ERR_NULL;
    if (pass_len == 0 || pass_len > (size_t)INT_MAX) return CRYPTO_ERR_SIZE;

    switch (kdf->id) {
    case KDF_PBKDF2_SHA256: {
        int ok = PKCS5_PBKDF2_HMAC(
            password, (int)pass_len,
            salt,     SALT_LEN,
            (int)kdf->iterations,
            EVP_sha256(),
            KEY_LEN,  key
        );
        return ok == 1 ? CRYPTO_OK : CRYPTO_ERR;
    }
    default:
        return CRYPTO_ERR;
    }
}

int encrypt_data(const uint8_t *plain, size_t plain_len,
                 const uint8_t *key, const uint8_t *nonce,
                 uint8_t *cipher, uint8_t *tag) {
    if (!plain || !key || !nonce || !cipher || !tag)   return CRYPTO_ERR_NULL;
    if (plain_len == 0 || plain_len > (size_t)INT_MAX) return CRYPTO_ERR_SIZE;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return CRYPTO_ERR_MEM;

    int len, outlen = 0, rc = CRYPTO_ERR;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)       != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)                    != 1) goto done;
    if (EVP_EncryptUpdate(ctx, cipher, &len, plain, (int)plain_len)        != 1) goto done;
    outlen += len;
    if (EVP_EncryptFinal_ex(ctx, cipher + outlen, &len)                    != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)      != 1) goto done;
    rc = CRYPTO_OK;

done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int decrypt_data(const uint8_t *cipher, size_t cipher_len,
                 const uint8_t *key, const uint8_t *nonce,
                 const uint8_t *tag, uint8_t *plain) {
    if (!cipher || !key || !nonce || !tag || !plain)     return CRYPTO_ERR_NULL;
    if (cipher_len == 0 || cipher_len > (size_t)INT_MAX) return CRYPTO_ERR_SIZE;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return CRYPTO_ERR_MEM;

    int len, outlen = 0, rc = CRYPTO_ERR_AUTH;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)           != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL)     != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)                        != 1) goto done;
    if (EVP_DecryptUpdate(ctx, plain, &len, cipher, (int)cipher_len)           != 1) goto done;
    outlen += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag)  != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, plain + outlen, &len)                         != 1) goto done;
    rc = CRYPTO_OK;

done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

char *gen_password(int length, int with_symbols) {
    if (length < 4 || length > PWGEN_MAX_LEN) return NULL;

    static const char lower[]   = "abcdefghijklmnopqrstuvwxyz";
    static const char upper[]   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const char digits[]  = "0123456789";
    static const char special[] = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    const int n_lower   = (int)(sizeof(lower)   - 1);
    const int n_upper   = (int)(sizeof(upper)   - 1);
    const int n_digits  = (int)(sizeof(digits)  - 1);
    const int n_special = (int)(sizeof(special) - 1);

    char full[128];
    int  flen = 0;
    memcpy(full,        lower,   (size_t)n_lower);  flen += n_lower;
    memcpy(full + flen, upper,   (size_t)n_upper);  flen += n_upper;
    memcpy(full + flen, digits,  (size_t)n_digits); flen += n_digits;
    if (with_symbols) {
        memcpy(full + flen, special, (size_t)n_special);
        flen += n_special;
    }

    char *out = malloc((size_t)length + 1);
    if (!out) return NULL;

    int pos = 0;
    if (pick_one(lower,   n_lower,   &out[pos++]) != CRYPTO_OK) goto fail;
    if (pick_one(upper,   n_upper,   &out[pos++]) != CRYPTO_OK) goto fail;
    if (pick_one(digits,  n_digits,  &out[pos++]) != CRYPTO_OK) goto fail;
    if (with_symbols) {
        if (pick_one(special, n_special, &out[pos++]) != CRYPTO_OK) goto fail;
    }

    for (int i = pos; i < length; i++) {
        if (pick_one(full, flen, &out[i]) != CRYPTO_OK) goto fail;
    }

    for (int i = length - 1; i > 0; i--) {
        int j;
        if (rand_uniform(i + 1, &j) != CRYPTO_OK) goto fail;
        char tmp = out[i];
        out[i]   = out[j];
        out[j]   = tmp;
    }

    out[length] = '\0';
    return out;

fail:
    secure_zero(out, (size_t)length);
    free(out);
    return NULL;
}

void secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
    OPENSSL_cleanse(ptr, len);
}
