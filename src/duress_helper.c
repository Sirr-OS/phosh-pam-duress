/*
 * duress_helper.c - Setuid helper for pam_duress
 *
 * When pam_duress.so is called by a non-privileged process (e.g., phosh
 * running as sirr/uid=1000), it cannot read or execute scripts from
 * /etc/duress.d/ that belong to root. This helper has the setuid bit set,
 * so it always runs as root, validates the script's hash against the
 * provided password, and executes it if valid.
 *
 * Installation:
 *   sudo cp duress_helper /usr/local/lib/duress_helper
 *   sudo chown root:root /usr/local/lib/duress_helper
 *   sudo chmod 4755 /usr/local/lib/duress_helper
 *
 * Usage (called internally by pam_duress.so):
 *   duress_helper <username> <script_path> <password>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <syslog.h>
#include <openssl/sha.h>

#define DURESS_DIR        "/etc/duress.d"
#define MAX_PATH          512
#define SIGNATURE_EXT     ".sha256"

/* Same function as util.c: SHA256 with salt */
static unsigned char *sha_256_sum(const char *payload, size_t payload_size,
                                   const unsigned char *salt, size_t salt_size) {
    unsigned char salt_hash[SHA256_DIGEST_LENGTH];
    SHA256(salt, salt_size, salt_hash);

    unsigned char *payload_hash = malloc(SHA256_DIGEST_LENGTH);
    if (!payload_hash) return NULL;

    unsigned char *salted_pass = malloc(SHA256_DIGEST_LENGTH + payload_size);
    if (!salted_pass) {
        free(payload_hash);
        return NULL;
    }

    memcpy(salted_pass, salt_hash, SHA256_DIGEST_LENGTH);
    memcpy(salted_pass + SHA256_DIGEST_LENGTH, payload, payload_size);
    SHA256(salted_pass, SHA256_DIGEST_LENGTH + payload_size, payload_hash);
    free(salted_pass);
    return payload_hash;
}

/* Check permission and owner : root */
static int check_permissions(const char *path, mode_t required) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    if (st.st_uid != 0) return 0;
    if ((st.st_mode & 0777) != required) return 0;
    return 1;
}

/* Check if the script are regular file */
static int is_regular_file(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
}

/* Check hash of script and password */
static int verify_hash(const char *script_path, const char *password) {
    /* Construir path del .sha256 */
    char hash_path[MAX_PATH];
    snprintf(hash_path, sizeof(hash_path), "%s%s", script_path, SIGNATURE_EXT);

    /* Check permission .sha256: 400 root */
    if (!check_permissions(hash_path, 0400)) {
        syslog(LOG_ERR, "duress_helper: bad permissions on %s", hash_path);
        return 0;
    }

    /* Read stored hash */
    unsigned char stored_hash[SHA256_DIGEST_LENGTH];
    FILE *hf = fopen(hash_path, "rb");
    if (!hf) {
        syslog(LOG_ERR, "duress_helper: cannot open %s: %s", hash_path, strerror(errno));
        return 0;
    }
    size_t nread = fread(stored_hash, 1, SHA256_DIGEST_LENGTH, hf);
    fclose(hf);
    if (nread != SHA256_DIGEST_LENGTH) {
        syslog(LOG_ERR, "duress_helper: short read on hash file %s", hash_path);
        return 0;
    }

    /* Read script */
    struct stat st;
    if (stat(script_path, &st) != 0) return 0;

    FILE *sf = fopen(script_path, "rb");
    if (!sf) {
        syslog(LOG_ERR, "duress_helper: cannot open script %s: %s", script_path, strerror(errno));
        return 0;
    }
    unsigned char *file_bytes = malloc(st.st_size);
    if (!file_bytes) {
        fclose(sf);
        return 0;
    }
    fread(file_bytes, 1, st.st_size, sf);
    fclose(sf);

    /* Calculate hash: sha_256_sum(password, len, file_bytes, size)
     * Same signature as util.c: sha_256_sum(payload, payload_size, salt, salt_size)
     * where payload=password and salt=file_bytes */ 
    unsigned char *computed = sha_256_sum(password, strlen(password),
                                          file_bytes, st.st_size);
    free(file_bytes);

    if (!computed) return 0;

    int match = (memcmp(stored_hash, computed, SHA256_DIGEST_LENGTH) == 0);
    free(computed);

    if (!match)
        syslog(LOG_INFO, "duress_helper: hash mismatch for %s", script_path);

    return match;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: duress_helper <username> <script_path> <password>\n");
        return 1;
    }

    const char *pamuser  = argv[1];
    const char *script   = argv[2];
    const char *password = argv[3];

    openlog("duress_helper", LOG_PID, LOG_AUTH);

    /* Username check: only secure chars */
    for (const char *p = pamuser; *p; p++) {
        if (!(*p >= 'a' && *p <= 'z') &&
            !(*p >= 'A' && *p <= 'Z') &&
            !(*p >= '0' && *p <= '9') &&
            *p != '_' && *p != '-' && *p != '.') {
            syslog(LOG_ERR, "duress_helper: invalid username");
            return 1;
        }
    }

    /* Check the script are into the DURESS_DIR */
    if (strncmp(script, DURESS_DIR "/", strlen(DURESS_DIR) + 1) != 0) {
        syslog(LOG_ERR, "duress_helper: script not in %s", DURESS_DIR);
        return 1;
    }

    /* Refuse path traversal */
    if (strstr(script, "..") != NULL) {
        syslog(LOG_ERR, "duress_helper: path traversal detected");
        return 1;
    }

    /* Be  a root using setuid bit */
    if (setuid(0) != 0) {
        syslog(LOG_ERR, "duress_helper: setuid failed: %s", strerror(errno));
        return 1;
    }

    /* We are root: check permission of script */
    if (!is_regular_file(script)) {
        syslog(LOG_ERR, "duress_helper: not a regular file: %s", script);
        return 1;
    }

    if (!check_permissions(script, 0500)) {
        syslog(LOG_ERR, "duress_helper: bad permissions on %s", script);
        return 1;
    }

    /* Verify the hash with password */
    if (!verify_hash(script, password)) {
        syslog(LOG_INFO, "duress_helper: hash verification failed for %s", script);
        return 1;
    }

    syslog(LOG_INFO, "duress_helper: executing %s for user %s", script, pamuser);

    /* Etablished PAMUSER and execute */
    setenv("PAMUSER", pamuser, 1);
    char *args[] = {"/bin/sh", (char *)script, (char *)0};
    execv("/bin/sh", args);

    syslog(LOG_ERR, "duress_helper: execv failed: %s", strerror(errno));
    closelog();
    return 1;
}
