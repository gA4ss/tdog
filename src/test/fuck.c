#include <unistd.h>
#include <sys/types.h>
#include <elf.h>
#include <sys/exec_elf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#if 0
#define UNIX_PATH_MAX 108
struct sockaddr_un {
 sa_family_t sun_family;
 char sun_path[UNIX_PATH_MAX];
};
#endif

#define DEBUGGER_SOCKET_NAME "android:debuggerd"
static int socket_abstract_client(const char* name, int type) {
    struct sockaddr_un addr;

    // Test with length +1 for the *initial* '\0'.
    size_t namelen = strlen(name);
    if ((namelen + 1) > sizeof(addr.sun_path)) {
        errno = EINVAL;
        return -1;
    }

    /* This is used for abstract socket namespace, we need
     * an initial '\0' at the start of the Unix socket path.
     *
     * Note: The path in this case is *not* supposed to be
     * '\0'-terminated. ("man 7 unix" for the gory details.)
     */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_LOCAL;
    addr.sun_path[0] = 0;
    memcpy(addr.sun_path + 1, name, namelen);

    socklen_t alen = namelen + offsetof(struct sockaddr_un, sun_path) + 1;

    int s = socket(AF_LOCAL, type, 0);
    if (s == -1) {
        return -1;
    }

    int err = connect(s, (struct sockaddr*) &addr, alen);
    if (err == -1) {
        close(s);
        s = -1;
    }

    return s;
}

int main() {
int s;
printf("sss\r\n");
	s = socket_abstract_client(DEBUGGER_SOCKET_NAME, SOCK_STREAM);
	if (s >= 0) {
		printf("debug found\r\n");
	}
	else printf("debug not found\r\n");
	
	return 0;
}
