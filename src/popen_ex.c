#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <wraith.h>
#include <sys/wait.h>
#include <malloc.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

static pid_t    *childpid = NULL;

static int      maxfd;

FILE *
popen_ex(const char *cmdstring, const char *type)
{
    DEBUG_PRINT("Run command: %s", cmdstring);

    int i;
    int pfd[2];
    pid_t pid;
    FILE *fp;

    if (childpid == NULL) {
        maxfd = 256;
        if ((childpid = calloc(maxfd, sizeof(pid_t))) == NULL) {
            return NULL;
        }
    }

    if (pipe(pfd) < 0) {
        return NULL;
    }

    if ((pid = fork()) < 0) {
        return NULL;
    } else if (pid == 0) {
        close(pfd[0]);
        if (pfd[1] != STDOUT_FILENO) {
            dup2(pfd[1], STDOUT_FILENO);
            dup2(pfd[1], STDERR_FILENO);
            close(pfd[1]);
        }

        for (i = 0; i < maxfd; i++) {
            if (childpid[i] > 0) {
                close(i);
            }
        }

        execl("/bin/sh", "sh", "-c", cmdstring, (char *)0);
        _exit(127);
    }

    close(pfd[1]);

    if ((fp = fdopen(pfd[0], type)) == NULL) {
        return NULL;
    }

    childpid[fileno(fp)] = pid;
    return fp;
}

int
pclose_ex(FILE *fp)
{
    int fd;
    int stat;
    pid_t pid;

    if (childpid == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = fileno(fp);
    if ((pid = childpid[fd]) == 0) {
        errno = EINVAL;
        return -1;
    }

    childpid[fd] = 0;
    if (fclose(fp) == EOF) {
        return -1;
    }

    while (waitpid(pid, &stat, 0) < 0) {
        if (errno != EINTR) {
            return -1;
        }
    }

    return stat & 0xFF;
}

void
pclose_destroy()
{
    if (childpid) {
        free(childpid);
    }
}
