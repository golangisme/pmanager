# pmanager

A minimal password manager written in C. Passwords live in a single encrypted file on your machine — no cloud, no daemon, no dependencies beyond OpenSSL.

## Building

**Linux / macOS**
```sh
gcc -Wall -O2 -std=c11 -Ilibs -Isrc \
  libs/crypto.c src/vault.c src/main.c \
  -o pmanager -lssl -lcrypto -largon2
```

**Windows (MSYS2 UCRT64)**
```sh
gcc -Wall -O2 -std=c11 -Ilibs -Isrc \
  libs/crypto.c src/vault.c src/main.c \
  -o pmanager.exe -static -lssl -lcrypto -largon2 -lws2_32 -lgdi32 -lcrypt32
```

Or just `make` on either platform if you have `make` installed.

**Dependencies**

| Platform | Package |
|---|---|
| Debian / Ubuntu | `sudo apt install libssl-dev libargon2-dev` |
| Fedora / RHEL | `sudo dnf install openssl-devel libargon2-devel` |
| macOS | `brew install openssl argon2` |
| MSYS2 | `pacman -S mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-argon2` |

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

Every save generates a fresh random 16-byte salt and 12-byte nonce. The master password is stretched with Argon2id (64MB memory, 3 passes, 4 threads — OWASP recommended) to produce a 256-bit key. The vault data is encrypted with AES-256-GCM and the authentication tag is appended at the end of the file, so any tampering or corruption is caught the moment you try to open it.

The master password is never stored anywhere. Sensitive buffers are zeroed with `OPENSSL_cleanse` before being freed so they don't linger in heap memory.

Vaults created before the Argon2id migration (using PBKDF2-SHA256) still open fine — the KDF algorithm and parameters are stored in the vault header and the reader follows whatever it finds there.

## Vault format

```
magic(4) | version(1) | kdf_id(1) | iterations(4) | memory_kb(4) | parallelism(1)
| salt(16) | nonce(12) | ciphertext_len(4) | ciphertext(N) | tag(16)
```

The KDF parameters are stored in the header so the file is self-describing. Bumping the iteration count or switching to Argon2id in the future won't break existing vaults — the reader just follows whatever the header says.

## Project structure

```
libs/   crypto primitives (AES-256-GCM, PBKDF2, password generation)
src/    application code  (vault I/O, CLI)
```
