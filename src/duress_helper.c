/*
 * duress_helper.c - Setuid helper for pam_duress
 *
 * When pam_duress.so is called by a non-privileged process (e.g., phosh
 * running as sirr/uid=1000), it cannot read or execute scripts from
 * /etc/duress.d/ that belong to root. This helper has the setuid bit set,
 * so it always runs as root, validates the script's hash against the
 * provided password, and executes it if valid.
 *
 * Security mitigations:
 *  - Caller UID check: rejects calls from root (not needed) and from
 *    users other than the PAM user (prevents misuse by other processes)
 *  - lstat() instead of stat() to reject symlinks (TOCTOU prevention)
 *  - O_NOFOLLOW when opening files
 *  - Subdirectory traversal rejected
 *  - /etc/duress.d directory integrity check
 *  - setgroups(0, NULL) before exec
 *  - Clean environment (only PAMUSER and PATH passed to script)
 *  - All file descriptors closed before exec
 *
 * Installation:
 *   sudo cp duress_helper /usr/local/lib/duress_helper
 *   sudo chown root:<PAM_USER_GROUP> /usr/local/lib/duress_helper
 *   sudo chmod 4750 /usr/local/lib/duress_helper
 *
 * Usage (called internally by pam_duress.so):
 *   duress_helper <username> <script_path> <password>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <openssl/sha.h>

#define DURESS_DIR     "/etc/duress.d"
#define MAX_PATH       512
#define SIGNATURE_EXT  ".sha256"
#define SAFE_PATH      "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

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

/*
 * Use lstat() to detect symlinks — a symlink with 500 permissions pointing
 * to another file would bypass the permission check with stat().
 */
static int check_permissions_strict(const char *path, mode_t required) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    if (S_ISLNK(st.st_mode)) {
        syslog(LOG_ERR, "duress_helper: symlink rejected: %s", path);
        return 0;
    }
    if (st.st_uid != 0) {
        syslog(LOG_ERR, "duress_helper: not owned by root: %s", path);
        return 0;
    }
    if ((st.st_mode & 0777) != required) {
        syslog(LOG_ERR, "duress_helper: wrong permissions on %s (got %o, need %o)",
               path, (st.st_mode & 0777), required);
        return 0;
    }
    return 1;
}

/*
 * Verify that /etc/duress.d is not a symlink and is not writable
 * by anyone other than root.
 */
static int check_duress_dir(void) {
    struct stat st;
    if (lstat(DURESS_DIR, &st) != 0) {
        syslog(LOG_ERR, "duress_helper: cannot stat %s: %s", DURESS_DIR, strerror(errno));
        return 0;
    }
    if (S_ISLNK(st.st_mode)) {
        syslog(LOG_ERR, "duress_helper: %s is a symlink", DURESS_DIR);
        return 0;
    }
    if (st.st_uid != 0) {
        syslog(LOG_ERR, "duress_helper: %s not owned by root", DURESS_DIR);
        return 0;
    }
    if (st.st_mode & S_IWOTH) {
        syslog(LOG_ERR, "duress_helper: %s is world-writable", DURESS_DIR);
        return 0;
    }
    if (st.st_mode & S_IWGRP) {
        syslog(LOG_ERR, "duress_helper: %s is group-writable", DURESS_DIR);
        return 0;
    }
    return 1;
}

/*
 * Open files with O_NOFOLLOW to prevent race condition between
 * check_permissions_strict() and the actual open (TOCTOU).
 */
static int verify_hash(const char *script_path, const char *password) {
    char hash_path[MAX_PATH];
    snprintf(hash_path, sizeof(hash_path), "%s%s", script_path, SIGNATURE_EXT);

    if (!check_permissions_strict(hash_path, 0400)) {
        syslog(LOG_ERR, "duress_helper: bad permissions on %s", hash_path);
        return 0;
    }

    int hfd = open(hash_path, O_RDONLY | O_NOFOLLOW);
    if (hfd < 0) {
        syslog(LOG_ERR, "duress_helper: cannot open %s: %s", hash_path, strerror(errno));
        return 0;
    }
    unsigned char stored_hash[SHA256_DIGEST_LENGTH];
    ssize_t nread = read(hfd, stored_hash, SHA256_DIGEST_LENGTH);
    close(hfd);
    if (nread != SHA256_DIGEST_LENGTH) {
        syslog(LOG_ERR, "duress_helper: short read on %s", hash_path);
        return 0;
    }

    struct stat st;
    if (lstat(script_path, &st) != 0) return 0;

    int sfd = open(script_path, O_RDONLY | O_NOFOLLOW);
    if (sfd < 0) {
        syslog(LOG_ERR, "duress_helper: cannot open %s: %s", script_path, strerror(errno));
        return 0;
    }
    unsigned char *file_bytes = malloc(st.st_size);
    if (!file_bytes) {
        close(sfd);
        return 0;
    }
    read(sfd, file_bytes, st.st_size);
    close(sfd);

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

static void close_all_fds(void) {
    struct rlimit rl;
    int max_fd = 1024;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
        max_fd = (int)rl.rlim_cur;
    for (int fd = 3; fd < max_fd; fd++)
        close(fd);
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

    /*
     * Security mitigation: reject calls from root.
     * Root does not need this helper — pam_duress.so handles execution
     * directly when running as root. A call from root likely means misuse.
     */
    uid_t caller_uid = getuid();
    if (caller_uid == 0) {
        syslog(LOG_ERR, "duress_helper: rejected call from root");
        return 1;
    }

    /*
     * Security mitigation: verify the caller is the PAM user.
     * The helper is installed with chmod 4750 root:<user_group>, so only
     * members of that group can execute it. This check adds an extra layer
     * by ensuring the calling UID matches the claimed username.
     */
    struct passwd *caller_pw = getpwuid(caller_uid);
    if (!caller_pw || strcmp(caller_pw->pw_name, pamuser) != 0) {
        syslog(LOG_ERR, "duress_helper: caller uid %d does not match claimed user %s",
               caller_uid, pamuser);
        return 1;
    }

    /* Validate username: alphanumeric plus _ - . only */
    for (const char *p = pamuser; *p; p++) {
        if (!(*p >= 'a' && *p <= 'z') &&
            !(*p >= 'A' && *p <= 'Z') &&
            !(*p >= '0' && *p <= '9') &&
            *p != '_' && *p != '-' && *p != '.') {
            syslog(LOG_ERR, "duress_helper: invalid username");
            return 1;
        }
    }

    /* Script must be directly inside DURESS_DIR — no subdirectories */
    if (strncmp(script, DURESS_DIR "/", strlen(DURESS_DIR) + 1) != 0) {
        syslog(LOG_ERR, "duress_helper: script not in %s", DURESS_DIR);
        return 1;
    }
    if (strstr(script, "..") != NULL) {
        syslog(LOG_ERR, "duress_helper: path traversal detected");
        return 1;
    }
    const char *basename = script + strlen(DURESS_DIR) + 1;
    if (strchr(basename, '/') != NULL) {
        syslog(LOG_ERR, "duress_helper: subdirectory not allowed");
        return 1;
    }

    /* Escalate to root via setuid bit */
    if (setuid(0) != 0) {
        syslog(LOG_ERR, "duress_helper: setuid failed: %s", strerror(errno));
        return 1;
    }

    /* Drop supplementary groups inherited from the calling process */
    if (setgroups(0, NULL) != 0) {
        syslog(LOG_ERR, "duress_helper: setgroups failed: %s", strerror(errno));
        return 1;
    }

    /* Verify /etc/duress.d directory integrity */
    if (!check_duress_dir()) {
        syslog(LOG_ERR, "duress_helper: insecure duress directory");
        return 1;
    }

    /* Verify script permissions (lstat — rejects symlinks) */
    if (!check_permissions_strict(script, 0500)) {
        syslog(LOG_ERR, "duress_helper: bad permissions on %s", script);
        return 1;
    }

    /* Verify hash against the provided password */
    if (!verify_hash(script, password)) {
        syslog(LOG_INFO, "duress_helper: hash verification failed for %s", script);
        return 1;
    }

    syslog(LOG_INFO, "duress_helper: executing %s for user %s", script, pamuser);

    /* Close all file descriptors before exec to prevent descriptor leaks */
    close_all_fds();

    /* Clean environment: only PAMUSER and a known safe PATH */
    char pamuser_env[256];
    snprintf(pamuser_env, sizeof(pamuser_env), "PAMUSER=%s", pamuser);
    char *clean_env[] = {
        pamuser_env,
        "PATH=" SAFE_PATH,
        NULL
    };

    char *args[] = {"/bin/sh", (char *)script, (char *)0};
    execve("/bin/sh", args, clean_env);

    syslog(LOG_ERR, "duress_helper: execve failed: %s", strerror(errno));
    closelog();
    return 1;
}
