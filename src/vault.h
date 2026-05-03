#pragma once

#include <stdint.h>

#define MAX_ENTRIES  1024
#define FIELD_MAX    256

typedef struct {
    char service[FIELD_MAX];
    char username[FIELD_MAX];
    char password[FIELD_MAX];
} Entry;

typedef struct {
    Entry entries[MAX_ENTRIES];
    int   count;
    char  path[512];
} Vault;

Vault *vault_open(const char *path, const char *master);
int    vault_save(Vault *vault, const char *master);
int    vault_add(Vault *vault, const char *service, const char *user, const char *pass);
int    vault_delete(Vault *vault, int index);
Entry *vault_find(Vault *vault, const char *service);
void   vault_list(Vault *vault);
void   vault_free(Vault *vault);
