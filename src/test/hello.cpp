/* hello1.c */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

int g_a = 1;
int g_b = 2;
int g_x;

void my_init() {
	printf("my_init\r\n");
}

typedef void (*r_brk)(void);

void foo() {
	int a = g_a + 0x1983;
	printf("g_a = %d\n", g_a);
	printf("a = %d\n", a);
}
void foo_end() {
	printf("foo_end\n");
}

#define bkpt 0xe7f001f0

#define DEBUGGER_SOCKET_NAME "android:debuggerd"
char* gAbortMessage = "fuck me";

enum debugger_action_t {
    DEBUGGER_ACTION_CRASH,
    DEBUGGER_ACTION_DUMP_TOMBSTONE,
    DEBUGGER_ACTION_DUMP_BACKTRACE,
};

/* gdb调试器信息 */
struct debugger_msg_t {
	debugger_action_t action;
	pid_t tid;
	// version 2
	uintptr_t abort_msg_address;
};

#define MAX_TASK_NAME_LEN (16)

static int socket_abstract_client(const char* name, int type) {
    sockaddr_un addr;

    size_t namelen = strlen(name);
    if ((namelen + 1) > sizeof(addr.sun_path)) {
        errno = EINVAL;
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_LOCAL;
    addr.sun_path[0] = 0;
    memcpy(addr.sun_path + 1, name, namelen);

    socklen_t alen = namelen + offsetof(sockaddr_un, sun_path) + 1;

    int s = socket(AF_LOCAL, type, 0);
    if (s == -1) {
        return -1;
    }

    int err = connect(s, (sockaddr*) &addr, alen);
    if (err == -1) {
        close(s);
        s = -1;
    }

    return s;
}

static void log_signal_summary(int signum, const siginfo_t* info) {
    const char* signal_name;
    switch (signum) {
        case SIGILL:    signal_name = "SIGILL";     break;
        case SIGABRT:   signal_name = "SIGABRT";    break;
        case SIGBUS:    signal_name = "SIGBUS";     break;
        case SIGFPE:    signal_name = "SIGFPE";     break;
        case SIGSEGV:   signal_name = "SIGSEGV";    break;
#if defined(SIGSTKFLT)
        case SIGSTKFLT: signal_name = "SIGSTKFLT";  break;
#endif
        case SIGPIPE:   signal_name = "SIGPIPE";    break;
	    case SIGTRAP:   signal_name = "SIGTRAP";    break;
        default:        signal_name = "???";        break;
    }

	printf("sig name = %s\n", signal_name);

    char thread_name[MAX_TASK_NAME_LEN + 1];
    if (prctl(PR_GET_NAME, (unsigned long)thread_name, 0, 0, 0) != 0) {
        strcpy(thread_name, "<name unknown>");
    } else {
        thread_name[MAX_TASK_NAME_LEN] = 0;
    }

    if (info != NULL) {
		printf("Fatal signal %d (%s) at 0x%08x (code=%d), thread %d (%s)\n",
			   signum, signal_name, info->si_addr,
			   info->si_code, gettid(), thread_name);
    } else {
        printf("Fatal signal %d (%s), thread %d (%s)\n",
			   signum, signal_name, gettid(), thread_name);
    }
}

static bool have_siginfo(int signum) {
    struct sigaction old_action, new_action;

    memset(&new_action, 0, sizeof(new_action));
    new_action.sa_handler = SIG_DFL;
    new_action.sa_flags = SA_RESTART;
    sigemptyset(&new_action.sa_mask);

    if (sigaction(signum, &new_action, &old_action) < 0) {
		printf("Failed testing for SA_SIGINFO: %s\n",
			   strerror(errno));
      return false;
    }
    bool result = (old_action.sa_flags & SA_SIGINFO) != 0;

	/* 恢复 */
    if (sigaction(signum, &old_action, NULL) == -1) {
		printf("Restore failed in test for SA_SIGINFO: %s\n",
			   strerror(errno));
    }
    return result;
}

void debuggerd_signal_handler(int n, siginfo_t* info, void*) {
	/* 不是我们处理的信号直接忽略 */
    if (!have_siginfo(n)) {
        info = NULL;
    }

	/* 打印信号信息 */
    log_signal_summary(n, info);

	/* 链接调试器 */
    pid_t tid = gettid();
    int s = socket_abstract_client(DEBUGGER_SOCKET_NAME, SOCK_STREAM);

	/* 链接调试器成功 */
    if (s >= 0) {
        debugger_msg_t msg;

		printf("connect android dbg success\n");

        msg.action = DEBUGGER_ACTION_CRASH;
        msg.tid = tid;
        msg.abort_msg_address = (uintptr_t)gAbortMessage;
        int ret = write(s, &msg, sizeof(msg));
        if (ret == sizeof(msg)) {
            ret = read(s, &tid, 1);
            int saved_errno = errno;
            errno = saved_errno;
        }

        if (ret < 0) {
			printf("Failed while talking to debuggerd: %s\n",
				   strerror(errno));
        }

        close(s);
    } else {
		printf("Unable to open connection to debuggerd: %s\n",
			   strerror(errno));
    }

    signal(n, SIG_DFL);

    switch (n) {
        case SIGABRT:
        case SIGFPE:
        case SIGPIPE:
#ifdef SIGSTKFLT
        case SIGSTKFLT:
#endif
            //(void) tgkill(getpid(), gettid(), n);
            break;
        default:    // SIGILL, SIGBUS, SIGSEGV
            break;
    }
}

void debuggerd_init() {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_sigaction = debuggerd_signal_handler;   /* 调试器信号处理函数 */
    action.sa_flags = SA_RESTART | SA_SIGINFO;

	// 使用交替信号stack,如果有效我们可以防止stack溢出
    action.sa_flags |= SA_ONSTACK;

	/* 设置我们要处理的信号 */
    sigaction(SIGABRT, &action, NULL);
    sigaction(SIGBUS, &action, NULL);
    sigaction(SIGFPE, &action, NULL);
    sigaction(SIGILL, &action, NULL);
    sigaction(SIGPIPE, &action, NULL);
    sigaction(SIGSEGV, &action, NULL);
#if defined(SIGSTKFLT)
    sigaction(SIGSTKFLT, &action, NULL);
#endif
    sigaction(SIGTRAP, &action, NULL);
}


int main() {
	debuggerd_init();

	try {
		unsigned char* i = NULL;
		int j = *(i+4);
	} catch (...) {
		printf("error\n");
	}
   
	

	//__asm__("bkpt");

	/* void *h = dlopen("./world.so", RTLD_NOW); */
	/* if (h) { */
	/* 	r_brk brk = dlsym(h, "world"); */
	/* 	if (brk) { */
	/* 		brk(); */
	/* 	} */
	/* } */	


	pause();

	return 0;
}

