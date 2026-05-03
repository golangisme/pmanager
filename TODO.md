# TODO

Roughly in order of priority.

## Features

- [ ] `edit` command — update username or password for an existing entry without having to delete and re-add
- [ ] Clipboard support — `pmanager get github --copy` should pipe to `xclip` / `pbcopy` / `clip.exe` and clear after 30s
- [ ] `rekey` command — re-encrypt the vault under a new master password
- [ ] Confirmation prompt before `delete` (or a `--force` flag to skip it)
- [ ] Case-insensitive service name lookup

## Crypto

- [ ] Argon2id support — `KdfParams` already supports it, just needs `libargon2` linked and a `case KDF_ARGON2ID` in `derive_key()`
- [ ] Auto-tune iteration count on first run — benchmark the machine and pick a value that takes ~1 second
- [ ] Wipe vault plaintext from memory on SIGINT so Ctrl-C doesn't leave sensitive data behind

## UX

- [ ] Fuzzy search on `list` — partial matches instead of exact service name
- [ ] `--json` output flag for scripting and pipe-friendly workflows
- [ ] Password strength feedback on `add` when the user types their own password
- [ ] `VAULT_DIR` env var pointing at a directory so multiple named vaults are easier to manage

## Portability

- [ ] Test on macOS — should work but untested
- [ ] Verify behavior when the vault file is on a network share or NTFS with strict ACLs
- [ ] Set restrictive file permissions on the vault (0600) after write

## Maybe

- [ ] Import from Bitwarden / 1Password CSV export
- [ ] Write new vault to a `.tmp` file first, then rename — prevents data loss if the process dies mid-write
- [ ] Man page
