# phosh-pam-duress

**phosh-pam-duress** is a PAM module built for [Sirr OS](https://github.com/Sirr-os) — a privacy-first Linux distribution for the PinePhone Pro. It allows users to define a **duress password** that, when entered instead of the real password, grants authentication normally while silently executing scripts in the background.

Designed for Phosh on Sirr OS, this module fits naturally into a system built around user sovereignty and digital self-defense. If you are ever forced to unlock your device, you stay in control of what happens next.

---

## What It Does

When a duress password is used to unlock your PinePhone:

- Authentication succeeds — the person coercing you sees nothing unusual
- Your duress scripts execute silently in the background
- Scripts can wipe sensitive data, close network connections, send an alert, take a photo, stream audio, or anything else you define
- The module can even remove itself so no trace of duress capability remains

Scripts can be defined **per-user** (`~/.duress/`) or **globally** (`/etc/duress.d/`), giving both personal and system-level control.

---

## Installation on Sirr OS / Mobian (PinePhone)

Download the latest `.deb` from [Releases](https://github.com/Sirr-os/phosh-pam-duress/releases) and install:

```bash
sudo dpkg -i phosh-pam-duress_*_arm64.deb
```

---

## Build from Source

> Cross-compilation for `aarch64` is handled automatically via GitHub Actions.  
> To build locally on a Debian/Ubuntu host:

```bash
sudo apt-get install gcc-aarch64-linux-gnu libpam0g-dev:arm64 libssl-dev:arm64
make
sudo make install
```

### Debug Build

```bash
# Debug build logs detailed output to syslog
make clean
make debug
sudo make install
```

> **Note:** In debug builds, script output is **not** redirected to `/dev/null`. In production builds it is.

---

## Configuration

After installation, create the duress script directories:

```bash
mkdir -p ~/.duress          # User-level duress scripts
sudo mkdir -p /etc/duress.d # System-level duress scripts
```

Write your script, then sign it with a duress password:

```bash
duress_sign ~/.duress/wipe_keys.sh
# Password:
# Confirm:
# Reading /home/user/.duress/wipe_keys.sh, 33...
# Done
# 6B8B621EFB8050B83AAC734D56BF9165DC55D709CBAD530C6241E8A352587B3F

chmod -R 500 ~/.duress
```

> **Note:** Scripts will only execute with permission masks of `500`, `540`, or `550`.

> **Note:** User duress scripts only run when **that specific user** logs in with a matching duress password. Global scripts in `/etc/duress.d/` run for any user whose duress password matches.

---

## PAM Configuration

Edit `/etc/pam.d/common-auth`. Replace the default:

```
auth    [success=1 default=ignore]      pam_unix.so
auth    requisite                       pam_deny.so
```

With:

```
auth    [success=2 default=ignore]      pam_unix.so
auth    [success=1 default=ignore]      pam_duress.so
auth    requisite                       pam_deny.so
```

### How It Works

**Normal password:**
1. `pam_unix.so` validates the real password → returns `PAM_SUCCESS` → skips 2 past `pam_deny.so` → authenticated.

**Duress password:**
1. `pam_unix.so` fails (duress password ≠ real password) → `ignore`.
2. `pam_duress.so` takes over:
   - Scans `/etc/duress.d/` and `~/.duress/` for `.sha256` signed scripts
   - Hashes the provided password salted with each script's SHA256 and compares
   - On match, executes:
     - Global: `export PAMUSER=[USERNAME]; /bin/sh [FILE]` (runs as root)
     - User: `export PAMUSER=[USERNAME]; su - [USERNAME] -c "/bin/sh [FILE]"` (runs as user)
   - If any script ran → returns `PAM_SUCCESS` → skips past `pam_deny.so` → authenticated.
   - If no match → `PAM_IGNORE` → falls through to `pam_deny.so` → denied.

---

## Acknowledgements

phosh-pam-duress is based on [pam-duress](https://github.com/nuvious/pam-duress)
by [@nuvious](https://github.com/nuvious) and its contributors — a PAM duress module with
over 1.4k stars that provided the foundation for this port to PinePhone / Sirr OS.

The original project is licensed under [LGPL-3.0](https://github.com/nuvious/pam-duress/blob/main/LICENSE).
All credit for the core module design and implementation goes to the upstream authors.

---

## License

See [LICENSE](LICENSE).
