---
name: fast-file-search
description: For wide file-name searches across a home directory or the whole filesystem ("where is X.conf", "find every *.pem"), use plocate/locate (install it and build the index if missing) instead of find / ; fall back to fd or rg --files for searches inside a project. Not for searching file contents.
---

# fast-file-search

`find / -name foo` walks the entire disk (slow, noisy, hits permission errors, hammers network mounts). A prebuilt index answers in milliseconds. This skill is about **file names/paths**; for file contents use `rg`.

## Decision
1. Inside the current project or one known directory: `rg --files | rg -i 'pattern'` or `fd pattern [dir]` (Debian/Ubuntu binary may be `fdfind`).
2. Outside the project, or location unknown: plocate/locate.

## plocate (preferred) or mlocate/locate
Check what exists: `command -v plocate locate`.

**Query** (system index):
```sh
plocate -i -l 50 'nginx.conf'          # case-insensitive, 50 results
plocate -b '\.pem$' -r                 # regex on the base name (-r = regex)
```

**Missing? Install** (a named package install is the one sudo use the jev guard accepts; if a guard asks, confirm with the user):
```sh
sudo apt-get install -y plocate        # Debian/Ubuntu
sudo dnf install -y plocate            # Fedora/RHEL
sudo pacman -S --noconfirm plocate     # Arch
sudo updatedb                          # build the system index (needs root, takes a minute)
```
If `plocate` is unavailable but `mlocate`/`locate` exists, use `locate -i pattern` and `sudo updatedb`.

**No root? Use a per-user index** of your home directory:
```sh
mkdir -p ~/.cache/plocate
updatedb -l 0 -U "$HOME" -o ~/.cache/plocate/home.db     # rebuild when stale
plocate -d ~/.cache/plocate/home.db -i 'pattern'
```
(`-d` takes a colon-separated list, so `plocate -d /var/lib/plocate/plocate.db:$HOME/.cache/plocate/home.db ...` searches both.)

## Caveats
- The index is a snapshot (usually rebuilt daily). Files created today may be missing: if a result you expect is absent, run `updatedb` again or fall back to `fd`/`find` on the likely directory.
- Results can include files you may not be allowed to open, and deleted files; `plocate` skips unreadable ones for non-root users. Verify with `ls -l` before relying on a hit.
- Locating a secret-looking file (`.env`, `id_rsa`, `*.pem`) is fine; printing it is not. See jev-command-guard.
- Never fall back to an unbounded `find /`; bound it (`find /etc /opt /srv -maxdepth 4 -name ...`) and add `-xdev`.
