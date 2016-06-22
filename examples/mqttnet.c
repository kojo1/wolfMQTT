/* mqttnet.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfMQTT.
 *
 * wolfMQTT is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfMQTT is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Include the autoconf generated config.h */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfmqtt/mqtt_client.h"
#include "mqttnet.h"

/* FreeRTOS and LWIP */
#ifdef FREERTOS
    /* Scheduler includes. */
    #include "FreeRTOS.h"
    #include "task.h"
    #include "semphr.h"

    /* lwIP includes. */
    #include "lwip/api.h"
    #include "lwip/tcpip.h"
    #include "lwip/memp.h"
    #include "lwip/stats.h"
    #include "lwip/sockets.h"
    #include "lwip/netdb.h"

/* Windows */
#elif defined(USE_WINDOWS_API)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <stdio.h>
    #define SOCKET_T        SOCKET
    #define SOERROR_T       char
    #define SELECT_FD(fd)   (fd)
    #define SOCKET_INVALID  ((SOCKET_T)INVALID_SOCKET)
    #define SOCK_CLOSE      closesocket
    #define SOCK_SEND(s,b,l,f) send((s), (const char*)(b), (size_t)(l), (f))
    #define SOCK_RECV(s,b,l,f) recv((s), (char*)(b), (size_t)(l), (f))

/* Freescale MQX / RTCS */
#elif defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
    #if defined(FREESCALE_MQX)
        #include <posix.h>
    #endif
    #include <rtcs.h>
    /* Note: Use "RTCS_geterror(sock->fd);" to get error number */

/* Microchip MPLABX Harmony, TCP/IP */
#elif defined(MICROCHIP_MPLAB_HARMONY)

#include "system_config.h"
#include "tcpip/tcpip.h"
#include <sys/errno.h>
#include <errno.h>
struct timeval {
    int tv_sec ;
    int tv_usec ;
} ;

typedef int socklen_t ;
#define SO_ERROR 0
#define SOERROR_T uint8_t

/* Linux */
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/param.h>
    #include <sys/time.h>
    #include <sys/select.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <signal.h>

    /* Wake on stdin activity */
    #define ENABLE_STDIN_CAPTURE
    #define STDIN   0
#endif

/* Setup defaults */
#ifndef SOCKET_T
    #define SOCKET_T        int
#endif
#ifndef SOERROR_T
    #define SOERROR_T       int
#endif
#ifndef SELECT_FD
    #define SELECT_FD(fd)   ((fd) + 1)
#endif
#ifndef SOCKET_INVALID
    #define SOCKET_INVALID  ((SOCKET_T)0)
#endif
#ifndef SOCK_CONNECT
    #define SOCK_CONNECT    connect
#endif
#ifndef SOCK_SEND
    #define SOCK_SEND(s,b,l,f) send((s), (b), (size_t)(l), (f))
#endif
#ifndef SOCK_RECV
    #define SOCK_RECV(s,b,l,f) recv((s), (b), (size_t)(l), (f))
#endif
#ifndef SOCK_CLOSE
    #define SOCK_CLOSE      close
#endif


/* Include the example code */
#include "mqttexample.h"

/* Local context for Net callbacks */
typedef struct _SocketContext {
    SOCKET_T fd;
#ifdef ENABLE_STDIN_CAPTURE
    byte stdin_cap_enable;
    byte stdin_has_data;
#endif
#if defined(WOLFMQTT_NONBLOCK) || defined(MICROCHIP_MPLAB_HARMONY)
    enum {
        SOCK_BEGIN = 0 ,
        SOCK_SOCK,
        SOCK_CONN,
        SOCK_RCV ,
    } stat ;
    int bytes ;
#endif
} SocketContext;

/* Private functions */
static void setup_timeout(struct timeval* tv, int timeout_ms)
{
    tv->tv_sec = timeout_ms / 1000;
    tv->tv_usec = (timeout_ms % 1000) * 1000;

    /* Make sure there is a minimum value specified */
    if (tv->tv_sec < 0 || (tv->tv_sec == 0 && tv->tv_usec <= 0)) {
        tv->tv_sec = 0;
        tv->tv_usec = 100;
    }
}

static void tcp_set_nonblocking(SOCKET_T* sockfd)
{
#ifdef USE_WINDOWS_API
    unsigned long blocking = 1;
    int ret = ioctlsocket(*sockfd, FIONBIO, &blocking);
    if (ret == SOCKET_ERROR)
        PRINTF("ioctlsocket failed!");
#elif defined(MICROCHIP_MPLAB_HARMONY)
    /* Do nothing */
#else
    int flags = fcntl(*sockfd, F_GETFL, 0);
    if (flags < 0)
        PRINTF("fcntl get failed!");
    flags = fcntl(*sockfd, F_SETFL, flags | O_NONBLOCK);
    if (flags < 0)
        PRINTF("fcntl set failed!");
#endif
}


#if defined(WOLFMQTT_NONBLOCK) || defined(MICROCHIP_MPLAB_HARMONY)
    #define SWITCH(s) switch(s)
    #define CASE(s) case s:

    #if defined(WOLFMQTT_NO_SELECT) || defined(MICROCHIP_MPLAB_HARMONY)
        #define select(p1, p2, p3, p4, p5) (1)
        #define FD_ISSET(f, fp) (true)
        #define FD_ZERO(f)
        #define FD_SET(f, e)
    #endif

#else
    #define SWITCH(s)
    #define CASE(s)
    
#endif
static int NetConnect(void *context, const char* host, word16 port,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int type = SOCK_STREAM;
    struct sockaddr_in address;
    int rc;
    SOERROR_T so_error = 0;
    struct addrinfo *result = NULL;
    struct addrinfo hints;

    XMEMSET(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    XMEMSET(&address, 0, sizeof(address));
    address.sin_family = AF_INET;

    /* Get address information for host and locate IPv4 */

    SWITCH(sock->stat) {
    CASE(SOCK_BEGIN)
    
#if defined(MICROCHIP_MPLAB_HARMONY)
    {
        struct hostent *hostInfo;
        
        hostInfo = gethostbyname((char *)host);
        if (hostInfo != NULL)
        {
            address.sin_port = htons(port);
            address.sin_family = AF_INET;
            XMEMCPY(&address.sin_addr,
                        *(hostInfo->h_addr_list), sizeof(IPV4_ADDR));
            sock->stat = SOCK_SOCK ;
        } else {
            break;
        }
    }
#else
    rc = getaddrinfo(host, NULL, &hints, &result);
    if (rc >= 0 && result != NULL) {
        struct addrinfo* res = result;

        /* prefer ip4 addresses */
        while (res) {
            if (res->ai_family == AF_INET) {
                result = res;
                break;
            }
            res = res->ai_next;
        }

        if (result->ai_family == AF_INET) {
            address.sin_port = htons(port);
            address.sin_family = AF_INET;
            address.sin_addr =
                ((struct sockaddr_in*)(result->ai_addr))->sin_addr;
        }
        else {
            rc = -1;
        }

        freeaddrinfo(result);
    }
#endif

    CASE(SOCK_SOCK)

    if (rc != 0) goto exit ;
        /* Default to error */
        rc = -1;

        /* Create socket */
        sock->fd = socket(address.sin_family, type, 0);
        if (sock->fd == SOCKET_INVALID) goto exit ;
        sock->stat = SOCK_CONN ;
    
    CASE(SOCK_CONN)        
        {
            #if !defined(NO_SELECT) && !defined(MICROCHIP_MPLAB_HARMONY)
            fd_set fdset;
            #endif
            struct timeval tv;

            /* Setup timeout and FD's */
            setup_timeout(&tv, timeout_ms);
            FD_ZERO(&fdset);
            FD_SET(sock->fd, &fdset);

            /* Set socket as non-blocking */
            tcp_set_nonblocking(&sock->fd);

            /* Start connect */
            connect(sock->fd, (struct sockaddr*)&address, sizeof(address));

            /* Wait for connect */
            if (select((int)SELECT_FD(sock->fd), NULL, &fdset, NULL, &tv) > 0)
            {
                socklen_t len = sizeof(so_error);

                /* Check for error */
                getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
                if (so_error == 0) {
                    rc = 0; /* Success */
                }
            }
        }
    
    } /* end of SWITCH(context->conn_stat) */

exit:
    /* Show error */
    if (rc != 0) {
        PRINTF("MqttSocket_Connect: Rc=%d, SoErr=%d", rc, so_error);
    }

    return rc;
}

static int NetWrite(void *context, const byte* buf, int buf_len,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int rc;
    SOERROR_T so_error = 0;
    struct timeval tv;

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Setup timeout */
    setup_timeout(&tv, timeout_ms);
    setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));

    rc = (int)SOCK_SEND(sock->fd, buf, buf_len, 0);
    if (rc == -1) {
        /* Get error */
        socklen_t len = sizeof(so_error);
        getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            rc = 0; /* Handle signal */
        }
        else {
            PRINTF("MqttSocket_NetWrite: Error %d", so_error);
        }
    }

    return rc;
}

static int NetRead(void *context, byte* buf, int buf_len,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int rc = -1, bytes ;
    SOERROR_T so_error = 0;
    #if !defined(WOLFMQTT_NO_SELECT) && !defined(MICROCHIP_MPLAB_HARMONY)
    fd_set recvfds, errfds;
    #endif
    struct timeval tv;

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#if defined(WOLFMQTT_NONBLOCK) || defined(MICROCHIP_MPLAB_HARMONY)
    #define bytes sock->bytes

#else
    bytes = 0 ;
#endif
    
    /* Setup timeout and FD's */
    setup_timeout(&tv, timeout_ms);
    FD_ZERO(&recvfds);
    FD_SET(sock->fd, &recvfds);
    FD_ZERO(&errfds);
    FD_SET(sock->fd, &errfds);

#ifdef ENABLE_STDIN_CAPTURE
    if (sock->stdin_cap_enable) {
        FD_SET(STDIN, &recvfds);
    }
#endif

    #if !defined(WOLFMQTT_NONBLOCK) && !defined(MICROCHIP_MPLAB_HARMONY)
    /* Loop until buf_len has been read, error or timeout */
    while (bytes < buf_len)
    #else
    #define break   /* void out "break" statement in "if" block */
    if (bytes < buf_len)
    #endif
    {
        /* Wait for rx data to be available */
        rc = select((int)SELECT_FD(sock->fd), &recvfds, NULL, &errfds, &tv);
        if (rc > 0) {
            /* Check if rx or error */
            if (FD_ISSET(sock->fd, &recvfds)) {
                /* Try and read number of buf_len provided,
                    minus what's already been read */
                rc = (int)SOCK_RECV(sock->fd,
                               &buf[bytes],
                               buf_len - bytes,
                               0);
                if (rc <= 0) {
                    rc = -1;
                    break; /* Error */
                }
                else {
                    bytes += rc; /* Data */
                }
            }
#ifdef ENABLE_STDIN_CAPTURE
            else if (FD_ISSET(STDIN, &recvfds)) {
                sock->stdin_has_data = 1;
                /* Don't exit read until cap enabled */
                if (sock->stdin_cap_enable) {
                    return 0;
                }
            }
#endif
            if (FD_ISSET(sock->fd, &errfds)) {
                rc = -1;
                break;
            }
        }
        else {
            break; /* timeout or signal */
        }
    }

    if (rc < 0) {
        /* Get error */
        socklen_t len = sizeof(so_error);
        getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            rc = 0; /* Handle signal */
        }
        else {
            PRINTF("MqttSocket_NetRead: Error %d", so_error);
        }
    }
    else {
        rc = bytes;
    }

    return rc;
}

#if defined(WOLFMQTT_NONBLOCK) || defined(MICROCHIP_MPLAB_HARMONY)
    #undef bytes
    #undef break
#endif

static int NetDisconnect(void *context)
{
    SocketContext *sock = (SocketContext*)context;
    if (sock) {
        if (sock->fd != SOCKET_INVALID) {
#ifdef USE_WINDOWS_API
            closesocket(sock->fd);
#else
            close(sock->fd);
#endif
            sock->fd = -1;
        }
    }

#if defined(WOLFMQTT_NONBLOCK) || defined(MICROCHIP_MPLAB_HARMONY)
    sock->stat = SOCK_BEGIN ;
#endif
    return 0;
}

/* Public Functions */
int MqttClientNet_Init(MqttNet* net)
{
#ifdef USE_WINDOWS_API
    WSADATA wsd;
    WSAStartup(0x0002, &wsd);
    
#endif

    if (net) {
        XMEMSET(net, 0, sizeof(MqttNet));
        net->connect = NetConnect;
        net->read = NetRead;
        net->write = NetWrite;
        net->disconnect = NetDisconnect;
        net->context = WOLFMQTT_MALLOC(sizeof(SocketContext));
        if (net->context == NULL) {
            return MQTT_CODE_ERROR_MEMORY;
        }
        XMEMSET(net->context, 0, sizeof(SocketContext));
    }
    
#if defined(WOLFMQTT_NONBLOCK) || defined(MICROCHIP_MPLAB_HARMONY)

    ((SocketContext*)(net->context))->stat = SOCK_BEGIN ;

    /* For Debug */
{
    static IPV4_ADDR    dwLastIP[2] = { {-1}, {-1} };
    IPV4_ADDR           ipAddr;
    int i, nNets;
    TCPIP_NET_HANDLE    netH;

    nNets = TCPIP_STACK_NumberOfNetworksGet();
    for (i = 0; i < nNets; i++) 
    {
        netH = TCPIP_STACK_IndexToNet(i);
        ipAddr.Val = TCPIP_STACK_NetAddress(netH);
        if(dwLastIP[i].Val != ipAddr.Val)
        {
            dwLastIP[i].Val = ipAddr.Val;
            PRINTF("%s", TCPIP_STACK_NetNameGet(netH));
            PRINTF(" IP Address: ");
            PRINTF("%d.%d.%d.%d \r\n", ipAddr.v[0], ipAddr.v[1], ipAddr.v[2], ipAddr.v[3]);
            if (ipAddr.v[0] != 0 && ipAddr.v[0] != 169) // Wait for a Valid IP
            {
                PRINTF("\r\nWaiting for command type: openurl <url>\r\n");
            }
        }
    }
}
#endif

    return 0;
}

int MqttClientNet_DeInit(MqttNet* net)
{
    if (net) {
        if (net->context) {
            WOLFMQTT_FREE(net->context);
        }
        XMEMSET(net, 0, sizeof(MqttNet));
    }
    return 0;
}

int MqttClientNet_CheckForCommand_Enable(MqttNet* net)
{
    if (net && net->context) {
#ifdef ENABLE_STDIN_CAPTURE
        SocketContext *sock = (SocketContext*)net->context;
        sock->stdin_cap_enable = 1;
#endif
    }
    return 0;
}

/* Return length of data */
int MqttClientNet_CheckForCommand(MqttNet* net, byte* buffer, word32 length)
{
    int ret = 0;

    if (net && net->context) {
#ifdef ENABLE_STDIN_CAPTURE
        SocketContext *sock = (SocketContext*)net->context;
        if (sock->stdin_has_data) {
            if(fgets((char*)buffer, length, stdin) != NULL) {
                ret = (int)XSTRLEN((char*)buffer);
            }
            sock->stdin_has_data = 0;
        }
#endif
    }

    (void)buffer;
    (void)length;

    return ret;
}
