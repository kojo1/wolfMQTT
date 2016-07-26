/* mqttclient.c
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

#define WOLFSSL_MAX_ERROR_SZ 80
#include "wolfmqtt/mqtt_client.h"
#include <wolfssl/options.h>

#include <wolfssl/ssl.h>

#include "examples/mqttexample.h"
#include "examples/mqttclient/mqttclient.h"
#include "examples/mqttnet.h"

/* Globals */
int myoptind = 0;
char* myoptarg = NULL;

/* Locals */
static int mStopRead = 0;
static const char* mTlsFile = NULL;
static int mPacketIdLast;

/* Configuration */
#define DEFAULT_CLIENT_ID       "WolfMQTTClient"
#define MAX_BUFFER_SIZE         1024    /* Maximum size for network read/write callbacks */
#define TEST_MESSAGE            "test"

#if defined(WOLFMQTT_NONBLOCK) || defined(MICROCHIP_MPLAB_HARMONY)
#ifndef NO_MAIN_DRIVER
#define NO_MAIN_DRIVER
#endif
#define ERROR_EXIT(c) return (c)
#else
#define ERROR_EXIT(c) exit(c)
#endif

/* Usage */
static void Usage(void)
{
    PRINTF("mqttclient:");
    PRINTF("-?          Help, print this usage");
    PRINTF("-h <host>   Host to connect to, default %s",
        DEFAULT_MQTT_HOST);
    PRINTF("-p <num>    Port to connect on, default: Normal %d, TLS %d",
        MQTT_DEFAULT_PORT, MQTT_SECURE_PORT);
    PRINTF("-t          Enable TLS");
    PRINTF("-c <file>   Use provided certificate file");
    PRINTF("-q <num>    Qos Level 0-2, default %d",
        DEFAULT_MQTT_QOS);
    PRINTF("-s          Disable clean session connect flag");
    PRINTF("-k <num>    Keep alive seconds, default %d",
        DEFAULT_KEEP_ALIVE_SEC);
    PRINTF("-i <id>     Client Id, default %s",
        DEFAULT_CLIENT_ID);
    PRINTF("-l          Enable LWT (Last Will and Testament)");
    PRINTF("-u <str>    Username");
    PRINTF("-w <str>    Password");
    PRINTF("-n <str>    Topic name, default %s", DEFAULT_TOPIC_NAME);
    PRINTF("-C <num>    Command Timeout, default %dms", DEFAULT_CMD_TIMEOUT_MS);
    PRINTF("-T          Test mode");
}

static word16 mqttclient_get_packetid(void)
{
    mPacketIdLast = (mPacketIdLast >= MAX_PACKET_ID) ?
        1 : mPacketIdLast + 1;
    return (word16)mPacketIdLast;
}

#ifdef ENABLE_MQTT_TLS
static int mqttclient_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ];

    PRINTF("MQTT TLS Verify Callback: PreVerify %d, Error %d (%s)", preverify,
        store->error, wolfSSL_ERR_error_string(store->error, buffer));
    PRINTF("  Subject's domain name is %s", store->domain);

    /* Allowing to continue */
    /* Should check certificate and return 0 if not okay */
    PRINTF("  Allowing cert anyways");

    return 1;
}

/* Use this callback to setup TLS certificates and verify callbacks */
static int mqttclient_tls_cb(MqttClient* client)
{
    int rc = SSL_FAILURE;
    (void)client; /* Supress un-used argument */

    client->tls.ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (client->tls.ctx) {
        wolfSSL_CTX_set_verify(client->tls.ctx, SSL_VERIFY_PEER, mqttclient_tls_verify_cb);

        rc = SSL_SUCCESS;
        if (mTlsFile) {
    #if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
            /* Load CA certificate file */
            rc = wolfSSL_CTX_load_verify_locations(client->tls.ctx, mTlsFile, NULL);
        /* If using a client certificate it can be loaded using: */
        /* rc = wolfSSL_CTX_use_certificate_file(client->tls.ctx, clientCertFile, SSL_FILETYPE_PEM);*/
    #else
            rc = SSL_SUCCESS;
    #endif
        }
        else {
            rc = SSL_SUCCESS;
        }
    }

    PRINTF("MQTT TLS Setup (%d)", rc);

    return rc;
}
#else
static int mqttclient_tls_cb(MqttClient* client)
{
    (void)client;
    return 0;
}
#endif /* ENABLE_MQTT_TLS */

static int mqttclient_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    byte buf[PRINT_BUFFER_SIZE+1];
    word32 len;

    (void)client; /* Supress un-used argument */

    if (msg_new) {
        /* Determine min size to dump */
        len = msg->topic_name_len;
        if (len > PRINT_BUFFER_SIZE) {
            len = PRINT_BUFFER_SIZE;
        }
        XMEMCPY(buf, msg->topic_name, len);
        buf[len] = '\0'; /* Make sure its null terminated */

        /* Print incoming message */
        PRINTF("MQTT Message: Topic %s, Qos %d, Len %u",
            buf, msg->qos, msg->total_len);
    }

    /* Print message payload */
    len = msg->buffer_len;
    if (len > PRINT_BUFFER_SIZE) {
        len = PRINT_BUFFER_SIZE;
    }
    XMEMCPY(buf, msg->buffer, len);
    buf[len] = '\0'; /* Make sure its null terminated */
    PRINTF("Payload (%d - %d): %s",
        msg->buffer_pos, msg->buffer_pos + len, buf);

    if (msg_done) {
        PRINTF("MQTT Message: Done");
    }

    /* Return negative to terminate publish processing */
    return MQTT_CODE_SUCCESS;
}

int mqttclient_test(void* args, MQTTCtx *mqttCtx)
{

    int rc;
    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;

    switch(mqttCtx->stat) {

    case WMQ_BEGIN:

    mqttCtx->port = 0;
    mqttCtx->host = DEFAULT_MQTT_HOST;
    mqttCtx->use_tls = 0;
    mqttCtx->qos = DEFAULT_MQTT_QOS;
    mqttCtx->clean_session = 1;
    mqttCtx->keep_alive_sec = DEFAULT_KEEP_ALIVE_SEC;
    mqttCtx->client_id = DEFAULT_CLIENT_ID;
    mqttCtx->enable_lwt = 0;
    mqttCtx->username = NULL;
    mqttCtx->password = NULL;
    mqttCtx->tx_buf = NULL, mqttCtx->rx_buf = NULL;
    mqttCtx->topicName = DEFAULT_TOPIC_NAME;
    mqttCtx->cmd_timeout_ms = DEFAULT_CMD_TIMEOUT_MS;
    mqttCtx->test_mode = 0;

    ((func_args*)args)->return_code = -1; /* error state */

    while ((rc = mygetopt(argc, argv, "?h:p:tc:q:sk:i:lu:w:n:C:T")) != -1) {
        switch ((char)rc) {
            case '?' :
                Usage();
                ERROR_EXIT(EXIT_SUCCESS);

            case 'h' :
                mqttCtx->host = myoptarg;
                break;

            case 'p' :
                mqttCtx->port = (word16)XATOI(myoptarg);
                if (mqttCtx->port == 0) {
                    return err_sys("Invalid Port Number!");
                }
                break;

            case 't':
                mqttCtx->use_tls = 1;
                break;

            case 'c':
                mTlsFile = myoptarg;
                break;

            case 'q' :
                mqttCtx->qos = (MqttQoS)((byte)XATOI(myoptarg));
                if (mqttCtx->qos > MQTT_QOS_2) {
                    return err_sys("Invalid QoS value!");
                }
                break;

            case 's':
                mqttCtx->clean_session = 0;
                break;

            case 'k':
                mqttCtx->keep_alive_sec = XATOI(myoptarg);
                break;

            case 'i':
                mqttCtx->client_id = myoptarg;
                break;

            case 'l':
                mqttCtx->enable_lwt = 1;
                break;

            case 'u':
                mqttCtx->username = myoptarg;
                break;

            case 'w':
                mqttCtx->password = myoptarg;
                break;

            case 'n':
                mqttCtx->topicName = myoptarg;
                break;

            case 'C':
                mqttCtx->cmd_timeout_ms = XATOI(myoptarg);
                break;

            case 'T':
                mqttCtx->test_mode = 1;
                break;

            default:
                Usage();
                ERROR_EXIT(MY_EX_USAGE);
        }
    }

    myoptind = 0; /* reset for test cases */

    /* Start example MQTT Client */
    PRINTF("MQTT Client: QoS %d, Use TLS %d", mqttCtx->qos, mqttCtx->use_tls);
    
    case WMQ_INIT:

    /* Initialize Network */
    rc = MqttClientNet_Init(&mqttCtx->net);
    mqttCtx->stat = WMQ_INIT ; if (rc == MQTT_CODE_CONTINUE)return rc ;
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }
    PRINTF("MQTT Net Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    /* Initialize MqttClient structure */
    mqttCtx->tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    mqttCtx->rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    rc = MqttClient_Init(&mqttCtx->client, &mqttCtx->net, mqttclient_message_cb,
        mqttCtx->tx_buf, MAX_BUFFER_SIZE, mqttCtx->rx_buf, MAX_BUFFER_SIZE,
        mqttCtx->cmd_timeout_ms);
    PRINTF("MQTT Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }
    
    case WMQ_TCP_CONN:
    /* Connect to broker */
    rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host, mqttCtx->port,
        DEFAULT_CON_TIMEOUT_MS, mqttCtx->use_tls, mqttclient_tls_cb);
    mqttCtx->stat = WMQ_TCP_CONN ; if (rc == MQTT_CODE_CONTINUE)return rc ;
    PRINTF("MQTT Socket Connect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS)goto disconn ;

    case WMQ_MQTT_CONN:
        XMEMSET(&mqttCtx->connect, 0, sizeof(MqttConnect));
        mqttCtx->connect.keep_alive_sec = mqttCtx->keep_alive_sec;
        mqttCtx->connect.clean_session = mqttCtx->clean_session;
        mqttCtx->connect.client_id = mqttCtx->client_id;

        /* Last will and testament sent by broker to subscribers
            of topic when broker connection is lost */
        XMEMSET(&mqttCtx->lwt_msg, 0, sizeof(mqttCtx->lwt_msg));
        mqttCtx->connect.lwt_msg = &mqttCtx->lwt_msg;
        mqttCtx->connect.enable_lwt = mqttCtx->enable_lwt;
        if (mqttCtx->enable_lwt) {
            /* Send client id in LWT payload */
            mqttCtx->lwt_msg.qos = mqttCtx->qos;
            mqttCtx->lwt_msg.retain = 0;
            mqttCtx->lwt_msg.topic_name = WOLFMQTT_TOPIC_NAME"lwttopic";
            mqttCtx->lwt_msg.buffer = (byte*)mqttCtx->client_id;
            mqttCtx->lwt_msg.total_len = (word16)XSTRLEN(mqttCtx->client_id);
        }
        /* Optional authentication */
        mqttCtx->connect.username = mqttCtx->username;
        mqttCtx->connect.password = mqttCtx->password;

        /* Send Connect and wait for Connect Ack */
        rc = MqttClient_Connect(&mqttCtx->client, &mqttCtx->connect);
        mqttCtx->stat = WMQ_MQTT_CONN ; if (rc == MQTT_CODE_CONTINUE)return rc ;
        PRINTF("MQTT Connect: %s (%d)",
            MqttClient_ReturnCodeToString(rc), rc);
        if (rc != MQTT_CODE_SUCCESS)goto exit ;

            /* Build list of topics */
            mqttCtx->topics[0].topic_filter = mqttCtx->topicName;
            mqttCtx->topics[0].qos = mqttCtx->qos;

            /* Validate Connect Ack info */
            PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
                mqttCtx->connect.ack.return_code,
                (mqttCtx->connect.ack.flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
                    1 : 0
            );
            
            int i;
            /* Build list of topics */
            mqttCtx->topics[0].topic_filter = mqttCtx->topicName;
            mqttCtx->topics[0].qos = mqttCtx->qos;

            /* Subscribe Topic */
            XMEMSET(&mqttCtx->subscribe, 0, sizeof(MqttSubscribe));
            mqttCtx->subscribe.packet_id = mqttclient_get_packetid();
            mqttCtx->subscribe.topic_count = sizeof(mqttCtx->topics)/sizeof(MqttTopic);
            mqttCtx->subscribe.topics = mqttCtx->topics;

    case WMQ_SUB:
            rc = MqttClient_Subscribe(&mqttCtx->client, &mqttCtx->subscribe);
            mqttCtx->stat = WMQ_SUB ; if (rc == MQTT_CODE_CONTINUE)return rc ;
            
            PRINTF("MQTT Subscribe: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
            for (i = 0; i < mqttCtx->subscribe.topic_count; i++) {
                mqttCtx->topic = &mqttCtx->subscribe.topics[i];
                PRINTF("  Topic %s, Qos %u, Return Code %u",
                    mqttCtx->topic->topic_filter,
                    mqttCtx->topic->qos, mqttCtx->topic->return_code);
            }

            /* Publish Topic */
            XMEMSET(&mqttCtx->publish, 0, sizeof(MqttPublish));
            mqttCtx->publish.retain = 0;
            mqttCtx->publish.qos = mqttCtx->qos;
            mqttCtx->publish.duplicate = 0;
            mqttCtx->publish.topic_name = mqttCtx->topicName;
            mqttCtx->publish.packet_id = mqttclient_get_packetid();
            mqttCtx->publish.buffer = (byte*)TEST_MESSAGE;
            mqttCtx->publish.total_len = (word16)XSTRLEN(TEST_MESSAGE);
    
    case WMQ_PUB:
            rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);
            mqttCtx->stat=WMQ_PUB ; if (rc == MQTT_CODE_CONTINUE)return rc ;
            PRINTF("MQTT Publish: Topic %s, %s (%d)",
                mqttCtx->publish.topic_name, MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* Read Loop */
            PRINTF("MQTT Waiting for message...");
            MqttClientNet_CheckForCommand_Enable(&mqttCtx->net);
            
    case WMQ_WAIT_MSG:

            while (mStopRead == 0) {
                /* Try and read packet */
                rc = MqttClient_WaitMessage(&mqttCtx->client, mqttCtx->cmd_timeout_ms);
                if (rc == MQTT_CODE_ERROR_TIMEOUT) {
                    /* Check to see if command data (stdin) is available */
                    rc = MqttClientNet_CheckForCommand(&mqttCtx->net, mqttCtx->rx_buf, MAX_BUFFER_SIZE);
                    if (rc > 0) {
                        /* Publish Topic */
                        XMEMSET(&(mqttCtx->publish), 0, sizeof(MqttPublish));
                        mqttCtx->publish.retain = 0;
                        mqttCtx->publish.qos = mqttCtx->qos;
                        mqttCtx->publish.duplicate = 0;
                        mqttCtx->publish.topic_name = mqttCtx->topicName;
                        mqttCtx->publish.packet_id = mqttclient_get_packetid();
                        mqttCtx->publish.buffer = mqttCtx->rx_buf;
                        mqttCtx->publish.total_len = (word16)rc;
                        rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);
                        PRINTF("MQTT Publish: Topic %s, %s (%d)",
                            mqttCtx->publish.topic_name, MqttClient_ReturnCodeToString(rc), rc);
                    }
                    /* Keep Alive */
                    else {
                        rc = MqttClient_Ping(&mqttCtx->client);
                        mqttCtx->stat = WMQ_WAIT_MSG; if(rc == MQTT_CODE_CONTINUE)return(rc) ;
                        if (rc != MQTT_CODE_SUCCESS) {
                            PRINTF("MQTT Ping Keep Alive Error: %s (%d)",
                                MqttClient_ReturnCodeToString(rc), rc);
                            break;
                        }
                    }
                }
                else {
                    mqttCtx->stat = WMQ_WAIT_MSG; if(rc == MQTT_CODE_CONTINUE)return(rc) ;
                    if (rc != MQTT_CODE_SUCCESS) {
                        /* There was an error */
                        PRINTF("MQTT Message Wait: %s (%d)",
                            MqttClient_ReturnCodeToString(rc), rc);
                        break;
                    }
                }

                /* Exit if test mode */
                if (mqttCtx->test_mode) {
                    break;
                }
            }
            /* Check for error */
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* Unsubscribe Topics */
            XMEMSET(&(mqttCtx->unsubscribe), 0, sizeof(MqttUnsubscribe));
            mqttCtx->unsubscribe.packet_id = mqttclient_get_packetid();
            mqttCtx->unsubscribe.topic_count = sizeof(mqttCtx->topics)/sizeof(MqttTopic);
            mqttCtx->unsubscribe.topics = mqttCtx->topics;
            rc = MqttClient_Unsubscribe(&mqttCtx->client, &mqttCtx->unsubscribe);
            PRINTF("MQTT Unsubscribe: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
            
    } /* end of non-blocking SWITCH */
    rc = MQTT_CODE_SUCCESS;
            /* Disconnect */
disconn:
    if(rc == MQTT_CODE_CONTINUE)return(rc) ;
    rc = MqttClient_NetDisconnect(&mqttCtx->client);
    
    PRINTF("MQTT Socket Disconnect: %s (%d)",
           MqttClient_ReturnCodeToString(rc), rc);

exit:
    if(rc == MQTT_CODE_CONTINUE)return(rc) ;
    /* Free resources */
    if (mqttCtx->tx_buf) WOLFMQTT_FREE(mqttCtx->tx_buf);
    if (mqttCtx->rx_buf) WOLFMQTT_FREE(mqttCtx->rx_buf);

    /* Cleanup network */
    MqttClientNet_DeInit(&mqttCtx->net);

    /* Set return code */
    ((func_args*)args)->return_code = (rc == 0) ? 0 : EXIT_FAILURE;

    return 0;
}


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER
    #ifdef USE_WINDOWS_API
        static BOOL CtrlHandler(DWORD fdwCtrlType)
        {
            if (fdwCtrlType == CTRL_C_EVENT) {
                mStopRead = 1;
                PRINTF("Received Ctrl+c");
                return TRUE;
            }
            return FALSE;
        }
    #elif HAVE_SIGNAL
        #include <signal.h>
        static void sig_handler(int signo)
        {
            if (signo == SIGINT) {
                mStopRead = 1;
                PRINTF("Received SIGINT");
            }
        }
    #endif

    int main(int argc, char** argv)
    {
        func_args args;

        args.argc = argc;
        args.argv = argv;

        MQTT_nbCtl mqttCtx ;

#ifdef USE_WINDOWS_API
        if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE) == FALSE) {
            PRINTF("Error setting Ctrl Handler! Error %d", (int)GetLastError());
        }
#elif HAVE_SIGNAL
        if (signal(SIGINT, sig_handler) == SIG_ERR) {
            PRINTF("Can't catch SIGINT");
        }
#endif
        mqttclient_test_init  (&mqttCtx) ;
        mqttclient_test(&args, &mqttCtx);

        return args.return_code;
    }

#endif /* NO_MAIN_DRIVER */
