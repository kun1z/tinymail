//----------------------------------------------------------------------------------------------------------------------
#include <assert.h>
#include <limits.h>
static_assert(CHAR_BIT == 8, "ERROR: This code requires [char] to be exactly 8 bits.");
//----------------------------------------------------------------------------------------------------------------------
#include <stdint.h>
typedef   unsigned char        u8     ;   typedef   char         s8     ;
typedef   uint16_t             u16    ;   typedef   int16_t      s16    ;
typedef   uint32_t             u32    ;   typedef   int32_t      s32    ;
typedef   uint64_t             u64    ;   typedef   int64_t      s64    ;
typedef   __uint128_t          u128   ;   typedef   __int128_t   s128   ;
typedef   unsigned int         ui     ;   typedef   int          si     ;
typedef   unsigned long        ul     ;   typedef   long         sl     ;
typedef   unsigned long long   ull    ;   typedef   long long    sll    ;
typedef   float                r32    ;   typedef   double       r64    ;
//----------------------------------------------------------------------------------------------------------------------
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <semaphore.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
//----------------------------------------------------------------------------------------------------------------------
#define ENABLE_OUTPUT       1
#define MAX_LISTEN        100
#define BUFSIZE         16384
#define MAXSIZE         65536
//----------------------------------------------------------------------------------------------------------------------
void pump(struct sockaddr_in * const restrict, const si);                               // network pump
void ez_packet(const si socket, s8 const * const restrict, s8 const * const restrict);  // smtp ez-send
void o(s8 const * const restrict, ... );                                                // utility
s8 * datetime(s8 * const restrict);                                                     // utility
sem_t * csoutput;                                                                         // critical section
//----------------------------------------------------------------------------------------------------------------------
void pump(struct sockaddr_in * const restrict addr, const si sock)
{
    s8 * const restrict buf = malloc(BUFSIZE);

    if (!buf)
    {
        o("memory could not be allocated\n");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        s8 dtbuf[64];
        o("%s > socket accepting\n", datetime(dtbuf));

        socklen_t socklen = sizeof(struct sockaddr_in);

        errno = 0;
        const si client_sock = accept(sock, (void *)addr, &socklen);

        if (client_sock == -1)
        {
            o("%s > accept error: %d\n", datetime(dtbuf), errno);
        }
        else
        {
            errno = 0;
            pid_t pid = fork();

            if (pid == -1) // error
            {
                o("%s > fork error: %d\n", datetime(dtbuf), errno);

                errno = 0;
                const si res = close(client_sock);

                if (res == -1)
                {
                    o("%s > close(client_sock) error: %d\n", datetime(dtbuf), errno);
                    exit(EXIT_FAILURE);
                }
            }
            else if (!pid) // child
            {
                s8 const * const restrict ip = inet_ntoa(addr->sin_addr);

                if (!ip || strnlen(ip, 16) == 16)
                {
                    o("%s > inet_ntoa() failed\n", datetime(dtbuf));
                    exit(EXIT_FAILURE);
                }

                errno = 0;
                si res = close(sock);

                if (res == -1)
                {
                    o("%s > close(sock) error: %d\n", datetime(dtbuf), errno);
                    exit(EXIT_FAILURE);
                }

                u64 recvdata = 0;

                o("%s > client with IP %s connected\n", datetime(dtbuf), ip);

                ez_packet(client_sock, "220 computerstuntman.com SMTP tinymail/1.0\r\n", ip);

                si body = 0;

                while (1)
                {
                    memset(buf, 0, 8);

                    errno = 0;
                    const ssize_t len = recv(client_sock, buf, BUFSIZE, 0);

                    if (len == -1)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            o("%s > recv timeout: %s\n", datetime(dtbuf), ip);
                        }
                        else
                        {
                            o("%s > recv error: %d (%s)\n", datetime(dtbuf), errno, ip);
                        }

                        break;
                    }
                    else if (!len)
                    {
                        o("%s > orderly close: %s\n", datetime(dtbuf), ip);
                        break;
                    }
                    else
                    {
                        o("%s > recv %zu bytes from %s\n", datetime(dtbuf), len, ip);

                        if ((recvdata += len) >= MAXSIZE)
                        {
                            o("closing connection: data exceeded (%"PRIu64" bytes) from %s\n", recvdata, ip);
                            break;
                        }

                        if (ENABLE_OUTPUT)
                        {
                            errno = 0;
                            res = sem_wait(csoutput);

                            if (res == -1)
                            {
                                perror("sem_wait error");
                                exit(EXIT_FAILURE);
                            }

                            if (fwrite(buf, 1, len, stdout) != len)
                            {
                                puts("fwrite error");
                                exit(EXIT_FAILURE);
                            }

                            putchar('\n');

                            errno = 0;
                            res = sem_post(csoutput);

                            if (res == -1)
                            {
                                perror("sem_post error");
                                exit(EXIT_FAILURE);
                            }
                        }

                        if (body)
                        {
                            const s8 END[5] = "\r\n.\r\n";

                            if (len >= sizeof(END))
                            {
                                if (!memcmp(&buf[len - sizeof(END)], END, sizeof(END)))
                                {
                                    body = 0;
                                    ez_packet(client_sock, "250 OK\r\n", ip);
                                }
                            }
                            else
                            {
                                ez_packet(client_sock, "451 Unsupported\r\n", ip);
                                break;
                            }
                        }
                        else
                        {
                            if (!strncasecmp(buf, "helo ", 5) || !strncasecmp(buf, "mail ", 5) || !strncasecmp(buf, "rcpt ", 5))
                            {
                                o("valid request from %s\n", ip);
                                ez_packet(client_sock, "250 OK\r\n", ip);
                            }
                            else if (!strncasecmp(buf, "ehlo ", 5) || !strncasecmp(buf, "starttls", 8))
                            {
                                o("valid request from %s\n", ip);
                                ez_packet(client_sock, "502 NOT SUPPORTED\r\n", ip);
                            }
                            else if (!strncasecmp(buf, "quit\r\n", 6))
                            {
                                o("valid request from %s\n", ip);
                                ez_packet(client_sock, "221 BYE\r\n", ip);
                                break;
                            }
                            else if (!strncasecmp(buf, "data\r\n", 6))
                            {
                                o("valid request from %s\n", ip);
                                ez_packet(client_sock, "354 GO AHEAD\r\n", ip);
                                body = 1;
                            }
                            else
                            {
                                o("invalid request from %s\n", ip);
                                ez_packet(client_sock, "250 OK\r\n", ip);
                            }
                        }
                    }
                }

                errno = 0;
                res = close(client_sock);

                if (res == -1)
                {
                    o("%s > close(client_sock) error: %d\n", datetime(dtbuf), errno);
                    exit(EXIT_FAILURE);
                }

                exit(EXIT_SUCCESS);
            }
            else // parent
            {
                errno = 0;
                const si res = close(client_sock);

                if (res == -1)
                {
                    o("%s > close(client_sock) error: %d\n", datetime(dtbuf), errno);
                    exit(EXIT_FAILURE);
                }
            }
        }
    }
}
//----------------------------------------------------------------------------------------------------------------------
si main(si argc, s8 ** argv)
{
    signal(SIGCHLD, SIG_IGN); // ignore children when they die

    if ((csoutput = mmap(0, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED)
    {
        o("mmap error\n");
        return EXIT_FAILURE;
    }

    errno = 0;
    si res = sem_init(csoutput, 1, 1);

    if (res == -1)
    {
        perror("sem_init error");
        return EXIT_FAILURE;
    }

    s8 dtbuf[64];
    o("%s > tinymail v1.0\n", datetime(dtbuf));

    if (argc != 3)
    {
        o("%s <local bind ip> <local port>\n", argv[0]);
        o("example: %s 127.0.0.1 80 > smtpout.txt\n", argv[0]);
        return EXIT_FAILURE;
    }

    struct sockaddr_in addr = { 0 };

    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[2]));
    addr.sin_addr.s_addr = inet_addr(argv[1]);

    errno = 0;
    const si sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sock == -1)
    {
        perror("socket error");
        return EXIT_FAILURE;
    }

    o("socket open\n");

    // socket & TCP options: You may want to change them!

    const si off = 0, on = 1;
    const struct linger li =  {  1, 15 }; // linger on close enabled, 15 seconds before timeout
    const struct timeval tv = { 15,  0 }; // send/recv 15 second timeout

    // Pack all of our options into structured arrays so we can loop over them:

    #define options 5

    const si p[options][3] =
    {
        { SOL_SOCKET,  SO_KEEPALIVE, sizeof(off) },
        { SOL_SOCKET,  SO_LINGER,    sizeof(li)  },
        { IPPROTO_TCP, TCP_NODELAY,  sizeof(on)  },
        { SOL_SOCKET,  SO_RCVTIMEO,  sizeof(tv)  },
        { SOL_SOCKET,  SO_SNDTIMEO,  sizeof(tv)  },
    };

    void const * const restrict v[options] = { &off, &li, &on, &tv, &tv };

    for (si i=0;i<options;i++)
    {
        errno = 0;
        res = setsockopt(sock, p[i][0], p[i][1], v[i], p[i][2]);

        if (res == -1)
        {
            perror("setsockopt error");
            return EXIT_FAILURE;
        }
    }

    #undef options

    errno = 0;
    res = bind(sock, (void *)&addr, sizeof(struct sockaddr_in));

    if (res == -1)
    {
        perror("bind error");
        return EXIT_FAILURE;
    }

    o("socket bound\n");

    errno = 0;
    res = listen(sock, MAX_LISTEN);

    if (res == -1)
    {
        perror("listen error");
        return EXIT_FAILURE;
    }

    o("socket listening\n");

    pump(&addr, sock);

    __builtin_unreachable();
}
//----------------------------------------------------------------------------------------------------------------------
void ez_packet(const si socket, s8 const * const restrict text, s8 const * const restrict ip)
{
    s8 dtbuf[64];
    const ssize_t packet_size = strlen(text);

    o("%s", text);

    errno = 0;
    const ssize_t sent = send(socket, text, packet_size, 0);

    if (sent == -1)
    {
        o("%s > send error: %d (%s)\n", datetime(dtbuf), errno, ip);
        exit(EXIT_FAILURE);
    }
    else if (sent == packet_size)
    {
        o("sent %zu bytes to %s\n", sent, ip);
    }
    else
    {
        o("%s > unkown send error: %s\n", datetime(dtbuf), ip);
        exit(EXIT_FAILURE);
    }
}
//----------------------------------------------------------------------------------------------------------------------
void o(s8 const * const restrict format, ... )
{
    if (ENABLE_OUTPUT)
    {
        errno = 0;
        si res = sem_wait(csoutput);

        if (res == -1)
        {
            perror("sem_wait error");
            exit(EXIT_FAILURE);
        }

        va_list t;
        va_start(t, format);
        res = vprintf(format, t);
        va_end(t);

        if (res < 0)
        {
            fputs("vprintf error\n", stderr);
            exit(EXIT_FAILURE);
        }

        fflush(stdout);

        errno = 0;
        res = sem_post(csoutput);

        if (res == -1)
        {
            perror("sem_post error");
            exit(EXIT_FAILURE);
        }
    }
}
//----------------------------------------------------------------------------------------------------------------------
s8 * datetime(s8 * const restrict buf)
{
    struct tm l;

    errno = 0;
    const time_t t = time(0);

    if (t == -1)
    {
        perror("time error");
        exit(EXIT_FAILURE);
    }

    if (localtime_r(&t, &l) != &l)
    {
        fputs("localtime_r error\n", stderr);
        exit(EXIT_FAILURE);
    }

    if (asctime_r(&l, buf) != buf)
    {
        fputs("asctime_r error\n", stderr);
        exit(EXIT_FAILURE);
    }

    buf[strlen(buf) - 1] = 0;

    return buf;
}
//----------------------------------------------------------------------------------------------------------------------