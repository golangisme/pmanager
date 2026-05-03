# pmanager

A minimal password manager written in C. Passwords live in a single encrypted file on your machine — no cloud, no daemon, no dependencies beyond OpenSSL.

## Building

**Linux / macOS**
```sh
gcc -Wall -O2 -std=c11 -Ilibs -Isrc \
  libs/crypto.c src/vault.c src/main.c \
  -o pmanager -lssl -lcrypto
```

**Windows (MSYS2 UCRT64)**
```sh
gcc -Wall -O2 -std=c11 -Ilibs -Isrc \
  libs/crypto.c src/vault.c src/main.c \
  -o pmanager.exe -static -lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32
```

Or just `make` on either platform if you have `make` installed.

**Dependencies**

| Platform | Package |
|---|---|
| Debian / Ubuntu | `sudo apt install libssl-dev` |
| Fedora / RHEL | `sudo dnf install openssl-devel` |
| macOS | `brew install openssl` |
| MSYS2 | `pacman -S mingw-w64-ucrt-x86_64-openssl` |

## Usage

```sh
# Add an entry — prompts for a password, or generates one if you leave it blank
pmanager add github myusername

# Show credentials
pmanager get github

# List everything
pmanager list

# Remove an entry
pmanager delete github

# Standalone password generator (doesn't touch the vault)
pmanager gen 24
pmanager gen 32 --symbols
```

The vault is saved to `vault.dat` in the current directory. Point it somewhere else with the `VAULT` env var:

```sh
VAULT=~/.local/share/pmanager/vault.dat pmanager list
```

## How it works

Every save generates a fresh random 16-byte salt and 12-byte nonce. The master password is run through PBKDF2-SHA256 (600,000 iterations) to produce a 256-bit key. The vault data is encrypted with AES-256-GCM and the authentication tag is written at the end of the file — so any corruption or tampering is caught the moment you try to open it.

The master password is never stored anywhere. Sensitive buffers (key material, plaintext) are zeroed with `OPENSSL_cleanse` before being freed so they don't linger in heap memory after use.

## Vault format

```
magic(4) | version(1) | kdf_id(1) | iterations(4) | memory_kb(4) | parallelism(1)
| salt(16) | nonce(12) | ciphertext_len(4) | ciphertext(N) | tag(16)
```

The KDF parameters are stored in the header so the file is self-describing. Bumping the iteration count or switching to Argon2id in the future won't break existing vaults — the reader just follows whatever the header says.

## Migrating to Argon2id

The groundwork is already there. To switch:

1. Link `libargon2` in your build.
2. Uncomment `KDF_ARGON2ID` in `libs/crypto.h`.
3. Add a `case KDF_ARGON2ID` branch in `derive_key()` in `libs/crypto.c`.
4. Re-encrypt existing vaults with a `rekey` command (see [TODO](TODO.md)).

Old vaults stay readable because the `kdf_id` field in the header tells the reader which algorithm was used.

## Project structure

```
libs/   crypto primitives (AES-256-GCM, PBKDF2, password generation)
src/    application code  (vault I/O, CLI)
```
