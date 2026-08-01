#define _GNU_SOURCE

#include <dlfcn.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __APPLE__
#define INTERPOSED(name) omnis_hold_##name
#define REAL_SYMBOL(name) name
#else
#define INTERPOSED(name) name
#define REAL_SYMBOL(name) dlsym(RTLD_NEXT, #name)
#endif

static volatile sig_atomic_t injected;

static bool ascii_alphanumeric(char value) {
    return (value >= '0' && value <= '9')
        || (value >= 'A' && value <= 'Z')
        || (value >= 'a' && value <= 'z');
}

static bool exact_demo_root_name(const char *path) {
    static const char prefix[] = "omnis-key-demo-";
    const char *name;
    const char *separator;
    size_t suffix_length = 0;

    if (path == NULL) {
        return false;
    }
    separator = strrchr(path, '/');
    name = separator == NULL ? path : separator + 1;
    if (strncmp(name, prefix, sizeof(prefix) - 1) != 0) {
        return false;
    }
    name += sizeof(prefix) - 1;
    if (*name < '0' || *name > '9') {
        return false;
    }
    while (*name >= '0' && *name <= '9') {
        name++;
    }
    if (*name++ != '-') {
        return false;
    }
    while (ascii_alphanumeric(*name)) {
        suffix_length++;
        name++;
    }
    return suffix_length == 24 && *name == '\0';
}

static void kill_after_successful_demo_mkdir(const char *path, int result) {
    if (result == 0 && !injected && exact_demo_root_name(path)) {
        injected = 1;
        (void)kill(getpid(), SIGKILL);
        _exit(137);
    }
}

int INTERPOSED(mkdir)(const char *path, mode_t mode) {
    int (*real_mkdir)(const char *, mode_t) = REAL_SYMBOL(mkdir);
    if (real_mkdir == NULL) {
        return -1;
    }
    int result = real_mkdir(path, mode);
    kill_after_successful_demo_mkdir(path, result);
    return result;
}

int INTERPOSED(mkdirat)(int dirfd, const char *path, mode_t mode) {
    int (*real_mkdirat)(int, const char *, mode_t) = REAL_SYMBOL(mkdirat);
    if (real_mkdirat == NULL) {
        return -1;
    }
    int result = real_mkdirat(dirfd, path, mode);
    kill_after_successful_demo_mkdir(path, result);
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

DYLD_INTERPOSE(omnis_hold_mkdir, mkdir);
DYLD_INTERPOSE(omnis_hold_mkdirat, mkdirat);
#endif
