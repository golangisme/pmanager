#include "vault.h"
#include "../libs/crypto.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC    "VULT"
#define VERSION  2

static uint8_t *serialize(const Vault *v, size_t *out_len) {
    size_t needed = 4;
    for (int i = 0; i < v->count; i++) {
        needed += 2 + strlen(v->entries[i].service);
        needed += 2 + strlen(v->entries[i].username);
        needed += 2 + strlen(v->entries[i].password);
    }

    uint8_t *buf = malloc(needed);
    if (!buf) return NULL;

    uint8_t *p = buf;
    uint32_t n = (uint32_t)v->count;
    memcpy(p, &n, 4);
    p += 4;

    for (int i = 0; i < v->count; i++) {
        const char *fields[3] = {
            v->entries[i].service,
            v->entries[i].username,
            v->entries[i].password,
        };
        for (int f = 0; f < 3; f++) {
            uint16_t flen = (uint16_t)strlen(fields[f]);
            memcpy(p, &flen, 2); p += 2;
            memcpy(p, fields[f], flen); p += flen;
        }
    }

    *out_len = needed;
    return buf;
}

static int deserialize(Vault *v, const uint8_t *buf, size_t buf_len) {
    if (buf_len < 4) return -1;

    const uint8_t *p = buf;
    uint32_t count;
    memcpy(&count, p, 4);
    p += 4;

    if (count > MAX_ENTRIES) return -1;

    for (uint32_t i = 0; i < count; i++) {
        char *fields[3] = {
            v->entries[i].service,
            v->entries[i].username,
            v->entries[i].password,
        };
        for (int f = 0; f < 3; f++) {
            if ((size_t)(p - buf) + 2 > buf_len) return -1;
            uint16_t flen;
            memcpy(&flen, p, 2);
            p += 2;
            if (flen >= FIELD_MAX) return -1;
            if ((size_t)(p - buf) + flen > buf_len) return -1;
            memcpy(fields[f], p, flen);
            fields[f][flen] = '\0';
            p += flen;
        }
    }

    v->count = (int)count;
    return 0;
}

Vault *vault_open(const char *path, const char *master) {
    if (!path || !master) return NULL;

    Vault *v = calloc(1, sizeof(*v));
    if (!v) return NULL;
    strncpy(v->path, path, sizeof(v->path) - 1);

    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errno != ENOENT) { perror(path); free(v); return NULL; }
        return v;
    }

    uint8_t   magic[4], ver;
    KdfParams kdf = {0};
    uint8_t   salt[SALT_LEN], nonce[NONCE_LEN];
    uint32_t  clen;

    if (fread(magic,            1, 4, f) != 4 || memcmp(magic, MAGIC, 4) != 0) goto corrupt;
    if (fread(&ver,             1, 1, f) != 1 || ver != VERSION)                goto corrupt;
    if (fread(&kdf.id,          1, 1, f) != 1)                                 goto corrupt;
    if (fread(&kdf.iterations,  4, 1, f) != 1)                                 goto corrupt;
    if (fread(&kdf.memory_kb,   4, 1, f) != 1)                                 goto corrupt;
    if (fread(&kdf.parallelism, 1, 1, f) != 1)                                 goto corrupt;
    if (fread(salt,  1, SALT_LEN,  f) != SALT_LEN)                             goto corrupt;
    if (fread(nonce, 1, NONCE_LEN, f) != NONCE_LEN)                            goto corrupt;
    if (fread(&clen, 4, 1,         f) != 1)                                    goto corrupt;

    uint8_t *cipher = malloc(clen);
    if (!cipher) goto corrupt;
    if (fread(cipher, 1, clen, f) != clen) { free(cipher); goto corrupt; }

    uint8_t tag[TAG_LEN];
    if (fread(tag, 1, TAG_LEN, f) != TAG_LEN) { free(cipher); goto corrupt; }
    fclose(f);

    uint8_t key[KEY_LEN];
    if (derive_key(master, strlen(master), salt, &kdf, key) != CRYPTO_OK) {
        free(cipher);
        free(v);
        return NULL;
    }

    uint8_t *plain = malloc(clen);
    if (!plain) {
        secure_zero(key, KEY_LEN);
        free(cipher);
        free(v);
        return NULL;
    }

    int rc = decrypt_data(cipher, clen, key, nonce, tag, plain);
    secure_zero(key, KEY_LEN);
    free(cipher);

    if (rc != CRYPTO_OK || deserialize(v, plain, clen) != 0) {
        secure_zero(plain, clen);
        free(plain);
        free(v);
        return NULL;
    }

    secure_zero(plain, clen);
    free(plain);
    return v;

corrupt:
    fclose(f);
    free(v);
    return NULL;
}

int vault_save(Vault *v, const char *master) {
    if (!v || !master) return -1;

    size_t   plain_len;
    uint8_t *plain = serialize(v, &plain_len);
    if (!plain) return -1;

    KdfParams kdf = KDF_DEFAULT;
    uint8_t   salt[SALT_LEN], nonce[NONCE_LEN], tag[TAG_LEN], key[KEY_LEN];

    if (random_bytes(salt,  SALT_LEN)  != CRYPTO_OK ||
        random_bytes(nonce, NONCE_LEN) != CRYPTO_OK) {
        secure_zero(plain, plain_len);
        free(plain);
        return -1;
    }

    if (derive_key(master, strlen(master), salt, &kdf, key) != CRYPTO_OK) {
        secure_zero(plain, plain_len);
        free(plain);
        return -1;
    }

    uint8_t *cipher = malloc(plain_len);
    if (!cipher) {
        secure_zero(key, KEY_LEN);
        secure_zero(plain, plain_len);
        free(plain);
        return -1;
    }

    int rc = encrypt_data(plain, plain_len, key, nonce, cipher, tag);
    secure_zero(key, KEY_LEN);
    secure_zero(plain, plain_len);
    free(plain);

    if (rc != CRYPTO_OK) { free(cipher); return -1; }

    FILE *f = fopen(v->path, "wb");
    if (!f) { free(cipher); return -1; }

    uint8_t  ver  = VERSION;
    uint32_t clen = (uint32_t)plain_len;

    int ok = 1;
    ok &= (fwrite(MAGIC,            1, 4,         f) == 4);
    ok &= (fwrite(&ver,             1, 1,         f) == 1);
    ok &= (fwrite(&kdf.id,          1, 1,         f) == 1);
    ok &= (fwrite(&kdf.iterations,  4, 1,         f) == 1);
    ok &= (fwrite(&kdf.memory_kb,   4, 1,         f) == 1);
    ok &= (fwrite(&kdf.parallelism, 1, 1,         f) == 1);
    ok &= (fwrite(salt,             1, SALT_LEN,  f) == SALT_LEN);
    ok &= (fwrite(nonce,            1, NONCE_LEN, f) == NONCE_LEN);
    ok &= (fwrite(&clen,            4, 1,         f) == 1);
    ok &= (fwrite(cipher,           1, plain_len, f) == plain_len);
    ok &= (fwrite(tag,              1, TAG_LEN,   f) == TAG_LEN);

    fclose(f);
    free(cipher);

    if (!ok) { remove(v->path); return -1; }
    return 0;
}

int vault_add(Vault *v, const char *service, const char *user, const char *pass) {
    if (!v || !service || !user || !pass) return -1;
    if (v->count >= MAX_ENTRIES) return -1;
    int i = v->count++;
    strncpy(v->entries[i].service,  service, FIELD_MAX - 1);
    strncpy(v->entries[i].username, user,    FIELD_MAX - 1);
    strncpy(v->entries[i].password, pass,    FIELD_MAX - 1);
    return i;
}

int vault_delete(Vault *v, int idx) {
    if (!v || idx < 0 || idx >= v->count) return -1;
    memmove(&v->entries[idx], &v->entries[idx + 1],
            (size_t)(v->count - idx - 1) * sizeof(Entry));
    v->count--;
    secure_zero(&v->entries[v->count], sizeof(Entry));
    return 0;
}

Entry *vault_find(Vault *v, const char *service) {
    if (!v || !service) return NULL;
    for (int i = 0; i < v->count; i++) {
        if (strcmp(v->entries[i].service, service) == 0)
            return &v->entries[i];
    }
    return NULL;
}

void vault_list(Vault *v) {
    if (!v || v->count == 0) { printf("No entries.\n"); return; }
    printf("%-4s  %-30s  %s\n", "#", "Service", "Username");
    printf("%-4s  %-30s  %s\n", "---", "------------------------------", "--------");
    for (int i = 0; i < v->count; i++) {
        printf("%-4d  %-30s  %s\n", i + 1,
               v->entries[i].service,
               v->entries[i].username);
    }
}

void vault_free(Vault *v) {
    if (!v) return;
    secure_zero(v->entries, sizeof(v->entries));
    free(v);
}
