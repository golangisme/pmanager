#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <termios.h>
#  include <unistd.h>
#endif

#include "vault.h"
#include "../libs/crypto.h"

#define DEFAULT_VAULT  "vault.dat"
#define MASTER_MAX     128

static void read_secret(const char *prompt, char *buf, int max) {
    printf("%s", prompt);
    fflush(stdout);

#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD  mode;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
    fgets(buf, max, stdin);
    SetConsoleMode(h, mode);
#else
    struct termios old, silent;
    tcgetattr(STDIN_FILENO, &old);
    silent = old;
    silent.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &silent);
    fgets(buf, max, stdin);
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
#endif

    printf("\n");
    buf[strcspn(buf, "\n")] = '\0';
}

static void usage(const char *prog) {
    printf("Usage: %s <command> [args]\n\n", prog);
    printf("  add    <service> <username>   Add a new entry\n");
    printf("  get    <service>              Show credentials for a service\n");
    printf("  list                          List all services\n");
    printf("  delete <service>              Remove an entry\n");
    printf("  gen    [length] [--symbols]   Generate a random password\n");
    printf("\nVault file: %s  (override with $VAULT)\n", DEFAULT_VAULT);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 1; }

    const char *cmd        = argv[1];
    const char *vault_path = getenv("VAULT");
    if (!vault_path) vault_path = DEFAULT_VAULT;

    if (strcmp(cmd, "gen") == 0) {
        int length  = (argc >= 3) ? atoi(argv[2]) : 20;
        int symbols = 0;
        for (int i = 2; i < argc; i++)
            if (strcmp(argv[i], "--symbols") == 0) symbols = 1;
        if (length < 4 || length > 128) {
            fprintf(stderr, "Length must be 4-128.\n");
            return 1;
        }
        char *p = gen_password(length, symbols);
        if (!p) { fprintf(stderr, "Password generation failed.\n"); return 1; }
        printf("%s\n", p);
        secure_zero(p, (size_t)length);
        free(p);
        return 0;
    }

    char master[MASTER_MAX] = {0};
    read_secret("Master password: ", master, sizeof(master));

    Vault *v = vault_open(vault_path, master);
    if (!v) {
        fprintf(stderr, "Wrong password or corrupt vault.\n");
        secure_zero(master, sizeof(master));
        return 1;
    }

    int status = 0;

    if (strcmp(cmd, "list") == 0) {
        vault_list(v);

    } else if (strcmp(cmd, "get") == 0) {
        if (argc < 3) { fprintf(stderr, "Usage: get <service>\n"); status = 1; goto done; }
        Entry *e = vault_find(v, argv[2]);
        if (!e) { fprintf(stderr, "No entry for '%s'.\n", argv[2]); status = 1; goto done; }
        printf("Username: %s\n", e->username);
        printf("Password: %s\n", e->password);

    } else if (strcmp(cmd, "add") == 0) {
        if (argc < 4) { fprintf(stderr, "Usage: add <service> <username>\n"); status = 1; goto done; }

        char pass[MASTER_MAX] = {0};
        read_secret("Password (blank to generate): ", pass, sizeof(pass));

        if (strlen(pass) == 0) {
            char *gen = gen_password(20, 1);
            if (!gen) { fprintf(stderr, "Password generation failed.\n"); status = 1; goto done; }
            printf("Generated: %s\n", gen);
            strncpy(pass, gen, sizeof(pass) - 1);
            secure_zero(gen, strlen(gen));
            free(gen);
        }

        if (vault_add(v, argv[2], argv[3], pass) < 0) {
            fprintf(stderr, "Vault is full.\n");
            status = 1;
        } else if (vault_save(v, master) != 0) {
            fprintf(stderr, "Failed to save vault.\n");
            status = 1;
        } else {
            printf("Saved '%s'.\n", argv[2]);
        }
        secure_zero(pass, sizeof(pass));

    } else if (strcmp(cmd, "delete") == 0) {
        if (argc < 3) { fprintf(stderr, "Usage: delete <service>\n"); status = 1; goto done; }
        Entry *e = vault_find(v, argv[2]);
        if (!e) { fprintf(stderr, "No entry for '%s'.\n", argv[2]); status = 1; goto done; }
        int idx = (int)(e - v->entries);
        vault_delete(v, idx);
        if (vault_save(v, master) != 0) {
            fprintf(stderr, "Failed to save vault.\n");
            status = 1;
        } else {
            printf("Deleted '%s'.\n", argv[2]);
        }

    } else {
        fprintf(stderr, "Unknown command: %s\n\n", cmd);
        usage(argv[0]);
        status = 1;
    }

done:
    secure_zero(master, sizeof(master));
    vault_free(v);
    return status;
}
