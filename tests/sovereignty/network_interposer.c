#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <resolv.h>
#include <spawn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifdef __APPLE__
#include <crt_externs.h>
#include <mach-o/dyld.h>
#include <sys/clonefile.h>
#else
extern char **environ;
#endif

#include "credential_environment_names.h"

/*
 * Runtime instrumentation for the OMNIS KEY V1 sovereignty gate.
 *
 * DNS and internet-family sockets are logged and denied. AF_UNIX is logged
 * but allowed so the receipt/demo checks can prove whether a local checkpoint
 * connection was attempted. Credential/account environment reads are logged
 * without their values. Selected filesystem entry points also flag access to
 * the synthetic operator sentinel used by the external harness.
 */

static __thread int recording;

#ifdef __APPLE__
#define INTERPOSED(name) omnis_##name
#define REAL_SYMBOL(name) name
#else
#define INTERPOSED(name) name
#define REAL_SYMBOL(name) dlsym(RTLD_NEXT, #name)
#endif

static char **process_environment(void) {
#ifdef __APPLE__
    return *_NSGetEnviron();
#else
    return environ;
#endif
}

/*
 * Avoid calling getenv from inside the interposer: getenv itself is one of the
 * observed entry points, and the recorder needs three harness-only variables.
 */
static char *lookup_environment(const char *name) {
    if (name == NULL || name[0] == '\0' || strchr(name, '=') != NULL) {
        return NULL;
    }
    size_t name_length = strlen(name);
    char **environment = process_environment();
    if (environment == NULL) {
        return NULL;
    }
    for (char **entry = environment; *entry != NULL; entry++) {
        if (strncmp(*entry, name, name_length) == 0
            && (*entry)[name_length] == '=') {
            return *entry + name_length + 1;
        }
    }
    return NULL;
}

static bool credential_or_account_environment(const char *name) {
#define OMNIS_CREDENTIAL_NAME(value) value,
    static const char *const names[] = {
        OMNIS_CREDENTIAL_ENVIRONMENT_NAMES(OMNIS_CREDENTIAL_NAME)
    };
#undef OMNIS_CREDENTIAL_NAME
    if (name == NULL) {
        return false;
    }
    for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        if (strcmp(name, names[index]) == 0) {
            return true;
        }
    }
    return false;
}

static bool credential_canary(const char *value) {
    return value != NULL && strstr(value, "credential-canary") != NULL;
}

static void append_event(const char *event) {
    if (recording) {
        return;
    }
    recording = 1;

    const char *path = lookup_environment("OMNIS_SOVEREIGNTY_LOG");
    if (path != NULL && path[0] != '\0') {
        int (*real_open)(const char *, int, ...) = REAL_SYMBOL(open);
        if (real_open != NULL) {
            int fd = real_open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
            if (fd >= 0) {
                char record[8192];
                int length = snprintf(
                    record,
                    sizeof(record),
                    "EV1|%ld|%s\n",
                    (long)getpid(),
                    event
                );
                if (length > 0 && (size_t)length < sizeof(record)) {
                    (void)write(fd, record, (size_t)length);
                }
                (void)close(fd);
            }
        }
    }

    recording = 0;
}

static void current_process_image(char *buffer, size_t size) {
    if (buffer == NULL || size == 0) {
        return;
    }
    buffer[0] = '\0';
#ifdef __APPLE__
    uint32_t required = (uint32_t)size;
    if (_NSGetExecutablePath(buffer, &required) != 0) {
        (void)snprintf(buffer, size, "<image-path-too-long>");
    }
#else
    ssize_t (*real_readlink)(const char *, char *, size_t) =
        REAL_SYMBOL(readlink);
    if (real_readlink == NULL) {
        (void)snprintf(buffer, size, "<image-path-unavailable>");
        return;
    }
    ssize_t length = real_readlink("/proc/self/exe", buffer, size - 1);
    if (length < 0) {
        (void)snprintf(buffer, size, "<image-path-unavailable>");
    } else {
        buffer[length] = '\0';
    }
#endif
    for (size_t index = 0; buffer[index] != '\0'; index++) {
        if (buffer[index] == '\n' || buffer[index] == '\r' || buffer[index] == '|') {
            buffer[index] = '?';
        }
    }
}

__attribute__((constructor))
static void record_process_start(void) {
    char image[PATH_MAX];
    char event[PATH_MAX + 32];
    current_process_image(image, sizeof(image));
    int written = snprintf(event, sizeof(event), "PROCESS_START|%s", image);
    if (written > 0 && (size_t)written < sizeof(event)) {
        append_event(event);
    } else {
        append_event("PROCESS_START|<format-error>");
    }
}

static void append_path_event(const char *operation, const char *path) {
    char event[4096];
    const char *display_path = path == NULL ? "<null>" : path;
    int written = snprintf(event, sizeof(event), "FS|%s|%s", operation, display_path);
    if (written < 0) {
        append_event("FS|format-error");
        return;
    }
    for (size_t index = 0; event[index] != '\0'; index++) {
        if (event[index] == '\n' || event[index] == '\r') {
            event[index] = '?';
        }
    }
    append_event(event);
}

static bool operator_path(const char *path) {
    if (path == NULL) {
        return false;
    }
    const char *root = lookup_environment("OMNIS_OPERATOR_SENTINEL");
    if (root != NULL && root[0] != '\0') {
        size_t length = strlen(root);
        if (strncmp(path, root, length) == 0) {
            return true;
        }
    }
    return strstr(path, "operator-sentinel") != NULL;
}

static bool filesystem_trace_enabled(void) {
    const char *value = lookup_environment("OMNIS_SOVEREIGNTY_FS_TRACE");
    return value != NULL
        && (strcmp(value, "1") == 0
            || strcmp(value, "true") == 0
            || strcmp(value, "yes") == 0);
}

static void inspect_resolved_path(const char *operation, const char *path) {
    if (filesystem_trace_enabled()) {
        append_path_event(operation, path);
    }
    if (operator_path(path)) {
        append_event("OPERATOR");
    }
}

static void inspect_at_path(const char *operation, int dirfd, const char *path) {
    if (path == NULL || path[0] == '/') {
        inspect_resolved_path(operation, path);
        return;
    }

    char directory[PATH_MAX];
    bool resolved = false;
    if (dirfd == AT_FDCWD) {
        resolved = getcwd(directory, sizeof(directory)) != NULL;
    } else {
#ifdef __APPLE__
        resolved = fcntl(dirfd, F_GETPATH, directory) == 0;
#else
        char descriptor[64];
        int length = snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", dirfd);
        ssize_t (*real_readlink)(const char *, char *, size_t) =
            REAL_SYMBOL(readlink);
        if (length > 0 && (size_t)length < sizeof(descriptor) && real_readlink != NULL) {
            ssize_t read = real_readlink(descriptor, directory, sizeof(directory) - 1);
            if (read >= 0) {
                directory[read] = '\0';
                resolved = true;
            }
        }
#endif
    }

    char absolute[PATH_MAX];
    if (resolved) {
        int written = snprintf(absolute, sizeof(absolute), "%s/%s", directory, path);
        if (written > 0 && (size_t)written < sizeof(absolute)) {
            inspect_resolved_path(operation, absolute);
            return;
        }
    }
    inspect_resolved_path(operation, "<unresolved-relative-path>");
}

static void inspect_path(const char *operation, const char *path) {
    inspect_at_path(operation, AT_FDCWD, path);
}

static void inspect_fd(const char *operation, int descriptor) {
    char path[PATH_MAX];
    bool resolved = false;
#ifdef __APPLE__
    resolved = fcntl(descriptor, F_GETPATH, path) == 0;
#else
    char fd_path[64];
    int written = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", descriptor);
    ssize_t (*real_readlink)(const char *, char *, size_t) =
        REAL_SYMBOL(readlink);
    if (written > 0 && (size_t)written < sizeof(fd_path) && real_readlink != NULL) {
        ssize_t length = real_readlink(fd_path, path, sizeof(path) - 1);
        if (length >= 0) {
            path[length] = '\0';
            resolved = true;
        }
    }
#endif
    inspect_resolved_path(
        operation,
        resolved ? path : "<unresolved-file-descriptor>"
    );
}

char *INTERPOSED(getenv)(const char *name) {
    char *value = lookup_environment(name);
    if (credential_or_account_environment(name) || credential_canary(value)) {
        char event[256];
        int written = snprintf(event, sizeof(event), "CREDENTIAL_ENV|%s", name);
        if (written > 0 && (size_t)written < sizeof(event)) {
            append_event(event);
        } else {
            append_event("CREDENTIAL_ENV|format-error");
        }
    }
    return value;
}

#ifndef __APPLE__
char *secure_getenv(const char *name) {
    char *value = lookup_environment(name);
    if (credential_or_account_environment(name) || credential_canary(value)) {
        char event[256];
        int written = snprintf(event, sizeof(event), "CREDENTIAL_ENV|%s", name);
        if (written > 0 && (size_t)written < sizeof(event)) {
            append_event(event);
        } else {
            append_event("CREDENTIAL_ENV|format-error");
        }
    }
    return value;
}
#endif

int INTERPOSED(getaddrinfo)(
    const char *node,
    const char *service,
    const struct addrinfo *hints,
    struct addrinfo **result
) {
    (void)node;
    (void)service;
    (void)hints;
    if (result != NULL) {
        *result = NULL;
    }
    append_event("DNS");
    return EAI_FAIL;
}

struct hostent *INTERPOSED(gethostbyname)(const char *name) {
    (void)name;
    append_event("DNS_GETHOSTBYNAME");
    h_errno = HOST_NOT_FOUND;
    return NULL;
}

struct hostent *INTERPOSED(gethostbyname2)(const char *name, int family) {
    (void)name;
    (void)family;
    append_event("DNS_GETHOSTBYNAME2");
    h_errno = HOST_NOT_FOUND;
    return NULL;
}

struct hostent *INTERPOSED(gethostbyaddr)(
    const void *address,
    socklen_t length,
    int family
) {
    (void)address;
    (void)length;
    (void)family;
    append_event("DNS_GETHOSTBYADDR");
    h_errno = HOST_NOT_FOUND;
    return NULL;
}

int INTERPOSED(res_query)(
    const char *domain,
    int dns_class,
    int dns_type,
    unsigned char *answer,
    int answer_length
) {
    (void)domain;
    (void)dns_class;
    (void)dns_type;
    (void)answer;
    (void)answer_length;
    append_event("DNS_RES_QUERY");
    h_errno = HOST_NOT_FOUND;
    return -1;
}

int INTERPOSED(socket)(int domain, int type, int protocol) {
    int (*real_socket)(int, int, int) = REAL_SYMBOL(socket);
    if (domain == AF_INET) {
        append_event("AF_INET");
        errno = ENETDOWN;
        return -1;
    }
    if (domain == AF_INET6) {
        append_event("AF_INET6");
        errno = ENETDOWN;
        return -1;
    }
    if (domain == AF_UNIX) {
        append_event("AF_UNIX");
    }
    if (real_socket == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_socket(domain, type, protocol);
}

static void append_unix_socket_event(
    const char *operation,
    const struct sockaddr *address,
    socklen_t length
) {
    char path[sizeof(((struct sockaddr_un *)0)->sun_path) + 2];
    const char *display_path = "<unnamed>";
    if (address != NULL && address->sa_family == AF_UNIX) {
        const struct sockaddr_un *local = (const struct sockaddr_un *)address;
        size_t offset = offsetof(struct sockaddr_un, sun_path);
        if ((size_t)length > offset) {
            size_t available = (size_t)length - offset;
            if (available > sizeof(local->sun_path)) {
                available = sizeof(local->sun_path);
            }
            if (available > 0 && local->sun_path[0] == '\0') {
#ifdef __linux__
                path[0] = '@';
                size_t payload = available - 1;
                if (payload > sizeof(path) - 2) {
                    payload = sizeof(path) - 2;
                }
                memcpy(path + 1, local->sun_path + 1, payload);
                path[payload + 1] = '\0';
                display_path = path;
#endif
            } else if (available > 0) {
                size_t payload = strnlen(local->sun_path, available);
                if (payload > sizeof(path) - 1) {
                    payload = sizeof(path) - 1;
                }
                memcpy(path, local->sun_path, payload);
                path[payload] = '\0';
                display_path = path;
            }
        }
    }
    char event[sizeof(path) + 64];
    int written = snprintf(
        event,
        sizeof(event),
        "%s|%s",
        operation,
        display_path
    );
    if (written > 0 && (size_t)written < sizeof(event)) {
        append_event(event);
    } else {
        append_event("AF_UNIX_FORMAT_ERROR");
    }
}

int INTERPOSED(connect)(
    int descriptor,
    const struct sockaddr *address,
    socklen_t length
) {
    int (*real_connect)(int, const struct sockaddr *, socklen_t) =
        REAL_SYMBOL(connect);
    if (address != NULL && address->sa_family == AF_INET) {
        append_event("CONNECT_AF_INET");
        errno = ENETDOWN;
        return -1;
    }
    if (address != NULL && address->sa_family == AF_INET6) {
        append_event("CONNECT_AF_INET6");
        errno = ENETDOWN;
        return -1;
    }
    if (address != NULL && address->sa_family == AF_UNIX) {
        append_unix_socket_event("CONNECT_AF_UNIX", address, length);
    }
    if (real_connect == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_connect(descriptor, address, length);
}

int INTERPOSED(bind)(
    int descriptor,
    const struct sockaddr *address,
    socklen_t length
) {
    int (*real_bind)(int, const struct sockaddr *, socklen_t) =
        REAL_SYMBOL(bind);
    if (address != NULL && address->sa_family == AF_INET) {
        append_event("BIND_AF_INET");
        errno = ENETDOWN;
        return -1;
    }
    if (address != NULL && address->sa_family == AF_INET6) {
        append_event("BIND_AF_INET6");
        errno = ENETDOWN;
        return -1;
    }
    if (address != NULL && address->sa_family == AF_UNIX) {
        append_unix_socket_event("BIND_AF_UNIX", address, length);
    }
    if (real_bind == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_bind(descriptor, address, length);
}

static bool open_needs_mode(int flags) {
#ifdef O_TMPFILE
    return (flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE;
#else
    return (flags & O_CREAT) != 0;
#endif
}

static const char *open_operation(const char *base, int flags) {
    int write_flags = O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND;
#ifdef O_TMPFILE
    write_flags |= O_TMPFILE;
#endif
    if ((flags & write_flags) == 0) {
        return base;
    }
    if (strcmp(base, "open") == 0) {
        return "open-write";
    }
    if (strcmp(base, "open64") == 0) {
        return "open64-write";
    }
    if (strcmp(base, "openat") == 0) {
        return "openat-write";
    }
    return "openat64-write";
}

int INTERPOSED(open)(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (open_needs_mode(flags)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    inspect_path(open_operation("open", flags), path);
    int (*real_open)(const char *, int, ...) = REAL_SYMBOL(open);
    if (real_open == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return open_needs_mode(flags) ? real_open(path, flags, mode) : real_open(path, flags);
}

int INTERPOSED(open64)(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (open_needs_mode(flags)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    inspect_path(open_operation("open64", flags), path);
    int (*real_open64)(const char *, int, ...) = dlsym(RTLD_NEXT, "open64");
    if (real_open64 == NULL) {
        real_open64 = REAL_SYMBOL(open);
    }
    if (real_open64 == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return open_needs_mode(flags) ? real_open64(path, flags, mode) : real_open64(path, flags);
}

int INTERPOSED(openat)(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (open_needs_mode(flags)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    inspect_at_path(open_operation("openat", flags), dirfd, path);
    int (*real_openat)(int, const char *, int, ...) = REAL_SYMBOL(openat);
    if (real_openat == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return open_needs_mode(flags)
        ? real_openat(dirfd, path, flags, mode)
        : real_openat(dirfd, path, flags);
}

int INTERPOSED(openat64)(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (open_needs_mode(flags)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    inspect_at_path(open_operation("openat64", flags), dirfd, path);
    int (*real_openat64)(int, const char *, int, ...) = dlsym(RTLD_NEXT, "openat64");
    if (real_openat64 == NULL) {
        real_openat64 = REAL_SYMBOL(openat);
    }
    if (real_openat64 == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return open_needs_mode(flags)
        ? real_openat64(dirfd, path, flags, mode)
        : real_openat64(dirfd, path, flags);
}

DIR *INTERPOSED(opendir)(const char *path) {
    inspect_path("opendir", path);
    DIR *(*real_opendir)(const char *) = REAL_SYMBOL(opendir);
    if (real_opendir == NULL) {
        errno = ENOSYS;
        return NULL;
    }
    return real_opendir(path);
}

int INTERPOSED(access)(const char *path, int mode) {
    inspect_path("access", path);
    int (*real_access)(const char *, int) = REAL_SYMBOL(access);
    if (real_access == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_access(path, mode);
}

ssize_t INTERPOSED(readlink)(const char *path, char *buffer, size_t size) {
    inspect_path("readlink", path);
    ssize_t (*real_readlink)(const char *, char *, size_t) =
        REAL_SYMBOL(readlink);
    if (real_readlink == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_readlink(path, buffer, size);
}

int INTERPOSED(stat)(const char *path, struct stat *metadata) {
    inspect_path("stat", path);
    int (*real_stat)(const char *, struct stat *) = REAL_SYMBOL(stat);
    if (real_stat == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_stat(path, metadata);
}

int INTERPOSED(lstat)(const char *path, struct stat *metadata) {
    inspect_path("lstat", path);
    int (*real_lstat)(const char *, struct stat *) = REAL_SYMBOL(lstat);
    if (real_lstat == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_lstat(path, metadata);
}

int INTERPOSED(fstatat)(
    int dirfd,
    const char *path,
    struct stat *metadata,
    int flags
) {
    inspect_at_path("fstatat", dirfd, path);
    int (*real_fstatat)(int, const char *, struct stat *, int) =
        REAL_SYMBOL(fstatat);
    if (real_fstatat == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_fstatat(dirfd, path, metadata, flags);
}

int INTERPOSED(mkdir)(const char *path, mode_t mode) {
    inspect_path("mkdir", path);
    int (*real_mkdir)(const char *, mode_t) = REAL_SYMBOL(mkdir);
    if (real_mkdir == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_mkdir(path, mode);
}

int INTERPOSED(mkdirat)(int dirfd, const char *path, mode_t mode) {
    inspect_at_path("mkdirat", dirfd, path);
    int (*real_mkdirat)(int, const char *, mode_t) = REAL_SYMBOL(mkdirat);
    if (real_mkdirat == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_mkdirat(dirfd, path, mode);
}

int INTERPOSED(unlink)(const char *path) {
    inspect_path("unlink", path);
    int (*real_unlink)(const char *) = REAL_SYMBOL(unlink);
    if (real_unlink == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_unlink(path);
}

int INTERPOSED(unlinkat)(int dirfd, const char *path, int flags) {
    inspect_at_path("unlinkat", dirfd, path);
    int (*real_unlinkat)(int, const char *, int) = REAL_SYMBOL(unlinkat);
    if (real_unlinkat == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_unlinkat(dirfd, path, flags);
}

int INTERPOSED(rename)(const char *old_path, const char *new_path) {
    inspect_path("rename-from", old_path);
    inspect_path("rename-to", new_path);
    int (*real_rename)(const char *, const char *) = REAL_SYMBOL(rename);
    if (real_rename == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_rename(old_path, new_path);
}

int INTERPOSED(renameat)(
    int old_dirfd,
    const char *old_path,
    int new_dirfd,
    const char *new_path
) {
    inspect_at_path("renameat-from", old_dirfd, old_path);
    inspect_at_path("renameat-to", new_dirfd, new_path);
    int (*real_renameat)(int, const char *, int, const char *) =
        REAL_SYMBOL(renameat);
    if (real_renameat == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_renameat(old_dirfd, old_path, new_dirfd, new_path);
}

char *INTERPOSED(realpath)(const char *path, char *resolved_path) {
    inspect_path("realpath", path);
    char *(*real_realpath)(const char *, char *) = REAL_SYMBOL(realpath);
    if (real_realpath == NULL) {
        errno = ENOSYS;
        return NULL;
    }
    return real_realpath(path, resolved_path);
}

int INTERPOSED(chmod)(const char *path, mode_t mode) {
    inspect_path("chmod", path);
    int (*real_chmod)(const char *, mode_t) = REAL_SYMBOL(chmod);
    if (real_chmod == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_chmod(path, mode);
}

int INTERPOSED(fchmod)(int descriptor, mode_t mode) {
    inspect_fd("fchmod", descriptor);
    int (*real_fchmod)(int, mode_t) = REAL_SYMBOL(fchmod);
    if (real_fchmod == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_fchmod(descriptor, mode);
}

int INTERPOSED(chown)(const char *path, uid_t owner, gid_t group) {
    inspect_path("chown", path);
    int (*real_chown)(const char *, uid_t, gid_t) = REAL_SYMBOL(chown);
    if (real_chown == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_chown(path, owner, group);
}

int INTERPOSED(fchown)(int descriptor, uid_t owner, gid_t group) {
    inspect_fd("fchown", descriptor);
    int (*real_fchown)(int, uid_t, gid_t) = REAL_SYMBOL(fchown);
    if (real_fchown == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_fchown(descriptor, owner, group);
}

int INTERPOSED(lchown)(const char *path, uid_t owner, gid_t group) {
    inspect_path("lchown", path);
    int (*real_lchown)(const char *, uid_t, gid_t) = REAL_SYMBOL(lchown);
    if (real_lchown == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_lchown(path, owner, group);
}

int INTERPOSED(truncate)(const char *path, off_t length) {
    inspect_path("truncate", path);
    int (*real_truncate)(const char *, off_t) = REAL_SYMBOL(truncate);
    if (real_truncate == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_truncate(path, length);
}

int INTERPOSED(ftruncate)(int descriptor, off_t length) {
    inspect_fd("ftruncate", descriptor);
    int (*real_ftruncate)(int, off_t) = REAL_SYMBOL(ftruncate);
    if (real_ftruncate == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_ftruncate(descriptor, length);
}

int INTERPOSED(rmdir)(const char *path) {
    inspect_path("rmdir", path);
    int (*real_rmdir)(const char *) = REAL_SYMBOL(rmdir);
    if (real_rmdir == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_rmdir(path);
}

int INTERPOSED(remove)(const char *path) {
    inspect_path("remove", path);
    int (*real_remove)(const char *) = REAL_SYMBOL(remove);
    if (real_remove == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_remove(path);
}

int INTERPOSED(link)(const char *source, const char *destination) {
    inspect_path("link-from", source);
    inspect_path("link-to", destination);
    int (*real_link)(const char *, const char *) = REAL_SYMBOL(link);
    if (real_link == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_link(source, destination);
}

int INTERPOSED(linkat)(
    int source_dirfd,
    const char *source,
    int destination_dirfd,
    const char *destination,
    int flags
) {
    inspect_at_path("linkat-from", source_dirfd, source);
    inspect_at_path("linkat-to", destination_dirfd, destination);
    int (*real_linkat)(int, const char *, int, const char *, int) =
        REAL_SYMBOL(linkat);
    if (real_linkat == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_linkat(
        source_dirfd,
        source,
        destination_dirfd,
        destination,
        flags
    );
}

int INTERPOSED(symlink)(const char *target, const char *link_path) {
    inspect_path("symlink-to", link_path);
    int (*real_symlink)(const char *, const char *) = REAL_SYMBOL(symlink);
    if (real_symlink == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_symlink(target, link_path);
}

int INTERPOSED(symlinkat)(
    const char *target,
    int destination_dirfd,
    const char *link_path
) {
    inspect_at_path("symlinkat-to", destination_dirfd, link_path);
    int (*real_symlinkat)(const char *, int, const char *) =
        REAL_SYMBOL(symlinkat);
    if (real_symlinkat == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_symlinkat(target, destination_dirfd, link_path);
}

int INTERPOSED(utimes)(const char *path, const struct timeval times[2]) {
    inspect_path("utimes", path);
    int (*real_utimes)(const char *, const struct timeval[2]) =
        REAL_SYMBOL(utimes);
    if (real_utimes == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_utimes(path, times);
}

int INTERPOSED(futimes)(int descriptor, const struct timeval times[2]) {
    inspect_fd("futimes", descriptor);
    int (*real_futimes)(int, const struct timeval[2]) = REAL_SYMBOL(futimes);
    if (real_futimes == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_futimes(descriptor, times);
}

int INTERPOSED(lutimes)(const char *path, const struct timeval times[2]) {
    inspect_path("lutimes", path);
    int (*real_lutimes)(const char *, const struct timeval[2]) =
        REAL_SYMBOL(lutimes);
    if (real_lutimes == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_lutimes(path, times);
}

#ifdef __APPLE__
int INTERPOSED(setxattr)(
    const char *path,
    const char *name,
    const void *value,
    size_t size,
    u_int32_t position,
    int options
) {
    inspect_path("setxattr", path);
    int (*real_setxattr)(
        const char *,
        const char *,
        const void *,
        size_t,
        u_int32_t,
        int
    ) = REAL_SYMBOL(setxattr);
    if (real_setxattr == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_setxattr(path, name, value, size, position, options);
}

int INTERPOSED(fsetxattr)(
    int descriptor,
    const char *name,
    const void *value,
    size_t size,
    u_int32_t position,
    int options
) {
    inspect_fd("fsetxattr", descriptor);
    int (*real_fsetxattr)(
        int,
        const char *,
        const void *,
        size_t,
        u_int32_t,
        int
    ) = REAL_SYMBOL(fsetxattr);
    if (real_fsetxattr == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_fsetxattr(descriptor, name, value, size, position, options);
}

int INTERPOSED(removexattr)(const char *path, const char *name, int options) {
    inspect_path("removexattr", path);
    int (*real_removexattr)(const char *, const char *, int) =
        REAL_SYMBOL(removexattr);
    if (real_removexattr == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_removexattr(path, name, options);
}

int INTERPOSED(fremovexattr)(int descriptor, const char *name, int options) {
    inspect_fd("fremovexattr", descriptor);
    int (*real_fremovexattr)(int, const char *, int) =
        REAL_SYMBOL(fremovexattr);
    if (real_fremovexattr == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_fremovexattr(descriptor, name, options);
}

int INTERPOSED(fclonefileat)(
    int source_descriptor,
    int destination_dirfd,
    const char *destination,
    uint32_t flags
) {
    inspect_fd("fclonefileat-from", source_descriptor);
    inspect_at_path("fclonefileat-to", destination_dirfd, destination);
    int (*real_fclonefileat)(int, int, const char *, uint32_t) =
        REAL_SYMBOL(fclonefileat);
    if (real_fclonefileat == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_fclonefileat(
        source_descriptor,
        destination_dirfd,
        destination,
        flags
    );
}
#else
int INTERPOSED(setxattr)(
    const char *path,
    const char *name,
    const void *value,
    size_t size,
    int flags
) {
    inspect_path("setxattr", path);
    int (*real_setxattr)(const char *, const char *, const void *, size_t, int) =
        REAL_SYMBOL(setxattr);
    if (real_setxattr == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_setxattr(path, name, value, size, flags);
}

int INTERPOSED(lsetxattr)(
    const char *path,
    const char *name,
    const void *value,
    size_t size,
    int flags
) {
    inspect_path("lsetxattr", path);
    int (*real_lsetxattr)(const char *, const char *, const void *, size_t, int) =
        REAL_SYMBOL(lsetxattr);
    if (real_lsetxattr == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_lsetxattr(path, name, value, size, flags);
}

int INTERPOSED(fsetxattr)(
    int descriptor,
    const char *name,
    const void *value,
    size_t size,
    int flags
) {
    inspect_fd("fsetxattr", descriptor);
    int (*real_fsetxattr)(int, const char *, const void *, size_t, int) =
        REAL_SYMBOL(fsetxattr);
    if (real_fsetxattr == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_fsetxattr(descriptor, name, value, size, flags);
}

int INTERPOSED(removexattr)(const char *path, const char *name) {
    inspect_path("removexattr", path);
    int (*real_removexattr)(const char *, const char *) =
        REAL_SYMBOL(removexattr);
    if (real_removexattr == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_removexattr(path, name);
}

int INTERPOSED(lremovexattr)(const char *path, const char *name) {
    inspect_path("lremovexattr", path);
    int (*real_lremovexattr)(const char *, const char *) =
        REAL_SYMBOL(lremovexattr);
    if (real_lremovexattr == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_lremovexattr(path, name);
}

int INTERPOSED(fremovexattr)(int descriptor, const char *name) {
    inspect_fd("fremovexattr", descriptor);
    int (*real_fremovexattr)(int, const char *) = REAL_SYMBOL(fremovexattr);
    if (real_fremovexattr == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_fremovexattr(descriptor, name);
}
#endif

static bool environment_contains(
    char *const environment[],
    const char *name
) {
    if (environment == NULL || name == NULL) {
        return false;
    }
    size_t name_length = strlen(name);
    for (char *const *entry = environment; *entry != NULL; entry++) {
        if (strncmp(*entry, name, name_length) == 0
            && (*entry)[name_length] == '='
            && (*entry)[name_length + 1] != '\0') {
            return true;
        }
    }
    return false;
}

static void append_execution_event(
    const char *operation,
    const char *path,
    char *const environment[]
) {
    const char *display_path = path == NULL ? "<null>" : path;
    bool log_present =
        environment_contains(environment, "OMNIS_SOVEREIGNTY_LOG");
#ifdef __APPLE__
    bool injection_present =
        environment_contains(environment, "DYLD_INSERT_LIBRARIES");
#else
    bool injection_present = environment_contains(environment, "LD_PRELOAD");
#endif
    char event[PATH_MAX + 128];
    int written = snprintf(
        event,
        sizeof(event),
        "EXEC_ATTEMPT|%s|trace=%d|inject=%d|%s",
        operation,
        log_present ? 1 : 0,
        injection_present ? 1 : 0,
        display_path
    );
    if (written > 0 && (size_t)written < sizeof(event)) {
        for (size_t index = 0; event[index] != '\0'; index++) {
            if (event[index] == '\n' || event[index] == '\r') {
                event[index] = '?';
            }
        }
        append_event(event);
    } else {
        append_event("EXEC_ATTEMPT|format-error|trace=0|inject=0|<format-error>");
    }
}

int INTERPOSED(execve)(
    const char *path,
    char *const arguments[],
    char *const environment[]
) {
    append_execution_event("execve", path, environment);
    int (*real_execve)(const char *, char *const[], char *const[]) =
        REAL_SYMBOL(execve);
    if (real_execve == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_execve(path, arguments, environment);
}

int INTERPOSED(execvp)(const char *path, char *const arguments[]) {
    char **environment = process_environment();
    append_execution_event("execvp", path, environment);
    int (*real_execvp)(const char *, char *const[]) = REAL_SYMBOL(execvp);
    if (real_execvp == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_execvp(path, arguments);
}

int INTERPOSED(posix_spawn)(
    pid_t *pid,
    const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes,
    char *const arguments[],
    char *const environment[]
) {
    append_execution_event("posix_spawn", path, environment);
    int (*real_posix_spawn)(
        pid_t *,
        const char *,
        const posix_spawn_file_actions_t *,
        const posix_spawnattr_t *,
        char *const[],
        char *const[]
    ) = REAL_SYMBOL(posix_spawn);
    if (real_posix_spawn == NULL) {
        return ENOSYS;
    }
    int result = real_posix_spawn(
        pid,
        path,
        file_actions,
        attributes,
        arguments,
        environment
    );
    char event[PATH_MAX + 128];
    int written = snprintf(
        event,
        sizeof(event),
        "EXEC_RESULT|posix_spawn|result=%d|pid=%ld|%s",
        result,
        result == 0 && pid != NULL ? (long)*pid : -1L,
        path
    );
    if (written > 0 && (size_t)written < sizeof(event)) {
        append_event(event);
    }
    return result;
}

int INTERPOSED(posix_spawnp)(
    pid_t *pid,
    const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes,
    char *const arguments[],
    char *const environment[]
) {
    append_execution_event("posix_spawnp", path, environment);
    int (*real_posix_spawnp)(
        pid_t *,
        const char *,
        const posix_spawn_file_actions_t *,
        const posix_spawnattr_t *,
        char *const[],
        char *const[]
    ) = REAL_SYMBOL(posix_spawnp);
    if (real_posix_spawnp == NULL) {
        return ENOSYS;
    }
    int result = real_posix_spawnp(
        pid,
        path,
        file_actions,
        attributes,
        arguments,
        environment
    );
    char event[PATH_MAX + 128];
    int written = snprintf(
        event,
        sizeof(event),
        "EXEC_RESULT|posix_spawnp|result=%d|pid=%ld|%s",
        result,
        result == 0 && pid != NULL ? (long)*pid : -1L,
        path
    );
    if (written > 0 && (size_t)written < sizeof(event)) {
        append_event(event);
    }
    return result;
}

#ifdef __APPLE__
#define DYLD_INTERPOSE(replacement, replacee)                                  \
    __attribute__((used)) static struct {                                      \
        const void *replacement;                                               \
        const void *replacee;                                                  \
    } interpose_##replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(uintptr_t)&replacement,                                 \
        (const void *)(uintptr_t)&replacee                                     \
    }

DYLD_INTERPOSE(omnis_getaddrinfo, getaddrinfo);
DYLD_INTERPOSE(omnis_getenv, getenv);
DYLD_INTERPOSE(omnis_gethostbyname, gethostbyname);
DYLD_INTERPOSE(omnis_gethostbyname2, gethostbyname2);
DYLD_INTERPOSE(omnis_gethostbyaddr, gethostbyaddr);
DYLD_INTERPOSE(omnis_res_query, res_query);
DYLD_INTERPOSE(omnis_socket, socket);
DYLD_INTERPOSE(omnis_connect, connect);
DYLD_INTERPOSE(omnis_bind, bind);
DYLD_INTERPOSE(omnis_open, open);
DYLD_INTERPOSE(omnis_openat, openat);
DYLD_INTERPOSE(omnis_opendir, opendir);
DYLD_INTERPOSE(omnis_access, access);
DYLD_INTERPOSE(omnis_readlink, readlink);
DYLD_INTERPOSE(omnis_stat, stat);
DYLD_INTERPOSE(omnis_lstat, lstat);
DYLD_INTERPOSE(omnis_fstatat, fstatat);
DYLD_INTERPOSE(omnis_mkdir, mkdir);
DYLD_INTERPOSE(omnis_mkdirat, mkdirat);
DYLD_INTERPOSE(omnis_unlink, unlink);
DYLD_INTERPOSE(omnis_unlinkat, unlinkat);
DYLD_INTERPOSE(omnis_rename, rename);
DYLD_INTERPOSE(omnis_renameat, renameat);
DYLD_INTERPOSE(omnis_realpath, realpath);
DYLD_INTERPOSE(omnis_chmod, chmod);
DYLD_INTERPOSE(omnis_fchmod, fchmod);
DYLD_INTERPOSE(omnis_chown, chown);
DYLD_INTERPOSE(omnis_fchown, fchown);
DYLD_INTERPOSE(omnis_lchown, lchown);
DYLD_INTERPOSE(omnis_truncate, truncate);
DYLD_INTERPOSE(omnis_ftruncate, ftruncate);
DYLD_INTERPOSE(omnis_rmdir, rmdir);
DYLD_INTERPOSE(omnis_remove, remove);
DYLD_INTERPOSE(omnis_link, link);
DYLD_INTERPOSE(omnis_linkat, linkat);
DYLD_INTERPOSE(omnis_symlink, symlink);
DYLD_INTERPOSE(omnis_symlinkat, symlinkat);
DYLD_INTERPOSE(omnis_utimes, utimes);
DYLD_INTERPOSE(omnis_futimes, futimes);
DYLD_INTERPOSE(omnis_lutimes, lutimes);
DYLD_INTERPOSE(omnis_setxattr, setxattr);
DYLD_INTERPOSE(omnis_fsetxattr, fsetxattr);
DYLD_INTERPOSE(omnis_removexattr, removexattr);
DYLD_INTERPOSE(omnis_fremovexattr, fremovexattr);
DYLD_INTERPOSE(omnis_fclonefileat, fclonefileat);
DYLD_INTERPOSE(omnis_execve, execve);
DYLD_INTERPOSE(omnis_execvp, execvp);
DYLD_INTERPOSE(omnis_posix_spawn, posix_spawn);
DYLD_INTERPOSE(omnis_posix_spawnp, posix_spawnp);
#endif
