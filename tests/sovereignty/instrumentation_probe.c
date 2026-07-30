#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifdef __APPLE__
#include <crt_externs.h>
#else
extern char **environ;
#endif

#include "credential_environment_names.h"

/*
 * Positive control for the sovereignty interposer. Every call is expected to
 * be observed; networking is intentionally denied by the interposer.
 */
int main(int argc, char **argv) {
    if (argc != 3) {
        return 2;
    }

    struct addrinfo *addresses = NULL;
    (void)getaddrinfo("fixture-only.invalid", "443", NULL, &addresses);
    if (addresses != NULL) {
        freeaddrinfo(addresses);
    }
    (void)gethostbyname("fixture-only.invalid");
    (void)gethostbyname2("fixture-only.invalid", AF_INET6);
    unsigned char loopback[4] = {127, 0, 0, 1};
    (void)gethostbyaddr(loopback, sizeof(loopback), AF_INET);
    unsigned char answer[512];
    (void)res_query(
        "fixture-only.invalid",
        1,
        1,
        answer,
        (int)sizeof(answer)
    );

    int ipv4 = socket(AF_INET, SOCK_STREAM, 0);
    int ipv6 = socket(AF_INET6, SOCK_STREAM, 0);
    int local = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ipv4 >= 0) {
        (void)close(ipv4);
    }
    if (ipv6 >= 0) {
        (void)close(ipv6);
    }
    if (local >= 0) {
        (void)close(local);
    }
    struct sockaddr_in ipv4_address;
    memset(&ipv4_address, 0, sizeof(ipv4_address));
    ipv4_address.sin_family = AF_INET;
    (void)connect(
        -1,
        (const struct sockaddr *)&ipv4_address,
        (socklen_t)sizeof(ipv4_address)
    );
    (void)bind(
        -1,
        (const struct sockaddr *)&ipv4_address,
        (socklen_t)sizeof(ipv4_address)
    );
    struct sockaddr_in6 ipv6_address;
    memset(&ipv6_address, 0, sizeof(ipv6_address));
    ipv6_address.sin6_family = AF_INET6;
    (void)connect(
        -1,
        (const struct sockaddr *)&ipv6_address,
        (socklen_t)sizeof(ipv6_address)
    );
    (void)bind(
        -1,
        (const struct sockaddr *)&ipv6_address,
        (socklen_t)sizeof(ipv6_address)
    );
    struct sockaddr_un local_address;
    memset(&local_address, 0, sizeof(local_address));
    local_address.sun_family = AF_UNIX;
    (void)connect(
        -1,
        (const struct sockaddr *)&local_address,
        (socklen_t)sizeof(local_address)
    );
    size_t local_path_length = strnlen(argv[2], sizeof(local_address.sun_path) - 1);
    memcpy(local_address.sun_path, argv[2], local_path_length);
    local_address.sun_path[local_path_length] = '\0';
    (void)bind(
        -1,
        (const struct sockaddr *)&local_address,
        (socklen_t)sizeof(local_address)
    );

    int opened = open(argv[1], O_RDONLY);
    if (opened >= 0) {
        (void)close(opened);
    }
    opened = openat(AT_FDCWD, argv[1], O_RDONLY);
    if (opened >= 0) {
        (void)close(opened);
    }

    struct stat metadata;
    (void)stat(argv[1], &metadata);

#define OMNIS_CREDENTIAL_NAME(value) value,
    static const char *const credential_environment[] = {
        OMNIS_CREDENTIAL_ENVIRONMENT_NAMES(OMNIS_CREDENTIAL_NAME)
    };
#undef OMNIS_CREDENTIAL_NAME
    for (size_t index = 0;
         index < sizeof(credential_environment) / sizeof(credential_environment[0]);
         index++) {
        (void)getenv(credential_environment[index]);
    }

    opened = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (opened >= 0) {
        (void)fchmod(opened, 0600);
        (void)fchown(opened, getuid(), getgid());
        (void)close(opened);
        (void)chmod(argv[2], 0600);
        (void)chown(argv[2], getuid(), getgid());
        (void)lchown(argv[2], getuid(), getgid());
        (void)utimes(argv[2], NULL);
#ifdef __APPLE__
        (void)setxattr(
            argv[2],
            "user.omnis-sovereignty-probe",
            "fixture",
            7,
            0,
            0
        );
#else
        (void)setxattr(
            argv[2],
            "user.omnis-sovereignty-probe",
            "fixture",
            7,
            0
        );
#endif
        (void)unlink(argv[2]);
    }

#ifdef __APPLE__
    char **environment = *_NSGetEnviron();
#else
    char **environment = environ;
#endif
    pid_t child = -1;
    char *const missing_arguments[] = {
        (char *)"omnis-sovereignty-missing-executable",
        NULL,
    };
    (void)posix_spawnp(
        &child,
        missing_arguments[0],
        NULL,
        NULL,
        missing_arguments,
        environment
    );
    return 0;
}
