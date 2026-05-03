#pragma once

#include <stddef.h>
#include <stdint.h>

#define KEY_LEN       32
#define SALT_LEN      16
#define NONCE_LEN     12
#define TAG_LEN       16
#define PWGEN_MAX_LEN 128

typedef enum {
    CRYPTO_OK       =  0,
    CRYPTO_ERR      = -1,
    CRYPTO_ERR_NULL = -2,
    CRYPTO_ERR_SIZE = -3,
    CRYPTO_ERR_RNG  = -4,
    CRYPTO_ERR_AUTH = -5,
    CRYPTO_ERR_MEM  = -6,
} CryptoError;

#define KDF_PBKDF2_SHA256  0
#define KDF_ARGON2ID       1

typedef struct {
    uint8_t  id;
    uint32_t iterations;
    uint32_t memory_kb;
    uint8_t  parallelism;
} KdfParams;

/* OWASP recommended Argon2id params: 64MB memory, 3 passes, 4 threads */
#define KDF_DEFAULT ((KdfParams){ KDF_ARGON2ID, 3, 65536, 4 })

/* Kept for reading vaults created before the Argon2id migration */
#define KDF_PBKDF2_DEFAULT ((KdfParams){ KDF_PBKDF2_SHA256, 600000, 0, 0 })

/*
 * Vault file layout:
 *   magic(4) | version(1) | kdf_id(1) | iterations(4) | memory_kb(4) | parallelism(1)
 *   | salt(16) | nonce(12) | ciphertext_len(4) | ciphertext(N) | tag(16)
 */

int   random_bytes(uint8_t *buf, size_t len);
int   derive_key(const char *password, size_t pass_len,
                 const uint8_t *salt, const KdfParams *kdf, uint8_t *key);
int   encrypt_data(const uint8_t *plain, size_t plain_len,
                   const uint8_t *key, const uint8_t *nonce,
                   uint8_t *cipher, uint8_t *tag);
int   decrypt_data(const uint8_t *cipher, size_t cipher_len,
                   const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *tag, uint8_t *plain);
char *gen_password(int length, int with_symbols);
void  secure_zero(void *ptr, size_t len);
