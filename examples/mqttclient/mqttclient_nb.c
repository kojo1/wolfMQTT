/* mqttclient_nb
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

#include "wolfmqtt/mqtt_client.h"
#include <wolfssl/ssl.h>
#include "examples/mqttclient/mqttclient.h"
#include "examples/mqttnet.h"
#include "examples/mqttexample.h"

/* Globals */
int myoptind = 0;
char* myoptarg = NULL;

/* Locals */
static int mStopRead = 0;
static const char* mTlsFile = NULL;
static int mPacketIdLast;

/* Configuration */
#define DEFAULT_CLIENT_ID       "WolfMQTTClient"
#define MAX_BUFFER_SIZE         1024
#define TEST_MESSAGE            "test"

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

        if (mTlsFile) {
    #if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
            /* Load CA certificate file */
            rc = wolfSSL_CTX_load_verify_locations(client->tls.ctx, mTlsFile, 0);
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

#if defined(WOLFMQTT_NONBLOCK) || defined(MICROCHIP_MPLAB_HARMONY)
/* making following data access to the control block */
#define client         mqtt_ctl->client
#define net            mqtt_ctl->net
#define port           mqtt_ctl->port
#define host           mqtt_ctl->host
#define use_tls        mqtt_ctl->use_tls
#define Qos            mqtt_ctl->Qos
#define Clean_session  mqtt_ctl->Clean_session
#define Keep_alive_sec mqtt_ctl->Keep_alive_sec
#define Client_id      mqtt_ctl->Client_id
#define Enable_lwt     mqtt_ctl->Enable_lwt
#define Username       mqtt_ctl->Username
#define Password       mqtt_ctl->Password
#define tx_buf         mqtt_ctl->tx_buf
#define rx_buf         mqtt_ctl->rx_buf
#define topicName      mqtt_ctl->topicName
#define cmd_timeout_ms mqtt_ctl->cmd_timeout_ms
#define test_mode      mqtt_ctl->test_mode

/* statements only for non-blocking */
#define SWITCH(stat) switch(mqtt_ctl->stat)
#define CASE(c)   mqtt_ctl->stat = c ; case c:
#define IF(c)     if(c)
#define RETURN(rc)    return(rc)
#else
#define SWITCH(s)
#define CASE(c)
#define IF(c)
#define RETURN(rc)
#endif


#ifdef WOLFMQTT_NONBLOCK 
void mqttclient_test_init(MQTT_nbCtl *mqtt_ctl)
{    
    mqtt_ctl->stat = WMQ_BEGIN ;
}

int mqttclient_test(void* args, MQTT_nbCtl *mqtt_ctl)
#else
int mqttclient_test(void* args)
#endif
{
    int rc ;

    SWITCH(stat) {

    CASE(WMQ_BEGIN)
    
    port = 0;
    host = DEFAULT_MQTT_HOST;
    use_tls = 0;
    Qos = DEFAULT_MQTT_QOS;
    Clean_session = 1;
    Keep_alive_sec = DEFAULT_KEEP_ALIVE_SEC;
    Client_id = DEFAULT_CLIENT_ID;
    Enable_lwt = 0;
    Username = NULL;
    Password = NULL;
    tx_buf = NULL, rx_buf = NULL;
    topicName = DEFAULT_TOPIC_NAME;
    cmd_timeout_ms = DEFAULT_CMD_TIMEOUT_MS;
    test_mode = 0;

    int argc = ((func_args*)args)->argc;
    char **argv = ((func_args*)args)->argv;

    ((func_args*)args)->return_code = -1; /* error state */

    while ((rc = mygetopt(argc, argv, "?h:p:tc:q:sk:i:lu:w:n:C:T")) != -1) {
        switch ((char)rc) {
            case '?' :
                Usage();
                exit(EXIT_SUCCESS);

            case 'h' :
                host = myoptarg;
                break;

            case 'p' :
                port = (word16)XATOI(myoptarg);
                if (port == 0) {
                    return err_sys("Invalid Port Number!");
                }
                break;

            case 't':
                use_tls = 1;
                break;

            case 'c':
                mTlsFile = myoptarg;
                break;

            case 'q' :
                Qos = (MqttQoS)((byte)XATOI(myoptarg));
                if (Qos > MQTT_QOS_2) {
                    return err_sys("Invalid QoS value!");
                }
                break;

            case 's':
                Clean_session = 0;
                break;

            case 'k':
                Keep_alive_sec = XATOI(myoptarg);
                break;

            case 'i':
                Client_id = myoptarg;
                break;

            case 'l':
                Enable_lwt = 1;
                break;

            case 'u':
                Username = myoptarg;
                break;

            case 'w':
                Password = myoptarg;
                break;

            case 'n':
                topicName = myoptarg;
                break;

            case 'C':
                cmd_timeout_ms = XATOI(myoptarg);
                break;

            case 'T':
                test_mode = 1;
                break;

            default:
                Usage();
                exit(MY_EX_USAGE);
        }
    }

    myoptind = 0; /* reset for test cases */

    /* Start example MQTT Client */
    PRINTF("MQTT Client: QoS %d", Qos);

    /* Initialize Network */
    rc = MqttClientNet_Init(&net);
    PRINTF("MQTT Net Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }

    /* Initialize MqttClient structure */
    tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    rc = MqttClient_Init(&client, &net, mqttclient_message_cb,
        tx_buf, MAX_BUFFER_SIZE, rx_buf, MAX_BUFFER_SIZE,
        cmd_timeout_ms);
    PRINTF("MQTT Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }
    
    CASE(WMQ_TCP_CONN)
    /* Connect to broker */
    rc = MqttClient_NetConnect(&client, host, port,
        DEFAULT_CON_TIMEOUT_MS, use_tls, mqttclient_tls_cb);
    PRINTF("MQTT Socket Connect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);

    if (rc != MQTT_CODE_SUCCESS)goto disconn ;
        
    CASE(WMQ_MQTT_CONN)
        /* Define connect parameters -> MQTT_nbCtl */
        /* MqttConnect connect;      */
        /* MqttMessage lwt_msg;      */
        #define Connect        mqtt_ctl->Connect
        #define Lwt_msg        mqtt_ctl->Lwt_msg
        
        XMEMSET(&Connect, 0, sizeof(MqttConnect));
        Connect.keep_alive_sec = Keep_alive_sec;
        Connect.clean_session = Clean_session;
        Connect.client_id = Client_id;
        /* Last will and testament sent by broker to subscribers
            of topic when broker connection is lost */
        XMEMSET(&Lwt_msg, 0, sizeof(Lwt_msg));
        Connect.lwt_msg = &Lwt_msg;
        Connect.enable_lwt = Enable_lwt;
        if (Enable_lwt) {
            /* Send client id in LWT payload */
            Lwt_msg.qos = Qos;
            Lwt_msg.retain = 0;
            Lwt_msg.topic_name = WOLFMQTT_TOPIC_NAME"lwttopic";
            Lwt_msg.buffer = (byte*)Client_id;
            Lwt_msg.total_len = (word16)XSTRLEN(Client_id);
        }
        /* Optional authentication */
        Connect.username = Username;
        Connect.password = Password;

        /* Send Connect and wait for Connect Ack */
        rc = MqttClient_Connect(&client, &Connect);
        PRINTF("MQTT Connect: %s (%d)",
            MqttClient_ReturnCodeToString(rc), rc);

        if (rc != MQTT_CODE_SUCCESS)goto disconn ;
    
    CASE(WMQ_SUB)
    {
            /* moved to MQTT_nbCtl          */
            /* MqttSubscribe subscribe;     */
            /* MqttUnsubscribe unsubscribe; */
            /* MqttTopic topics[1], *topic; */
            /* MqttPublish publish;         */
            #define subscribe      mqtt_ctl->subscribe
            #define unsubscribe    mqtt_ctl->unsubscribe
            #define Topics         mqtt_ctl->Topics
            #define topic          mqtt_ctl->topic
            #define publish        mqtt_ctl->publish

            int i;


            /* Build list of topics */
            Topics[0].topic_filter = topicName;
            Topics[0].qos = Qos;

            /* Validate Connect Ack info */
            PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
                Connect.ack.return_code,
                (Connect.ack.flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
                    1 : 0
            );

            /* Subscribe Topic */
            XMEMSET(&subscribe, 0, sizeof(MqttSubscribe));
            subscribe.packet_id = mqttclient_get_packetid();
            subscribe.topic_count = sizeof(Topics)/sizeof(MqttTopic);
            subscribe.topics = Topics;
            rc = MqttClient_Subscribe(&client, &subscribe);
            PRINTF("MQTT Subscribe: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
                
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
            for (i = 0; i < subscribe.topic_count; i++) {
                topic = &subscribe.topics[i];
                PRINTF("  Topic %s, Qos %u, Return Code %u",
                    topic->topic_filter, topic->qos, topic->return_code);
            }
    }
    
    CASE(WMQ_PUB)
            /* Publish Topic */
            XMEMSET(&publish, 0, sizeof(MqttPublish));
            publish.retain = 0;
            publish.qos = Qos;
            publish.duplicate = 0;
            publish.topic_name = topicName;
            publish.packet_id = mqttclient_get_packetid();
            publish.buffer = (byte*)TEST_MESSAGE;
            publish.total_len = (word16)XSTRLEN(TEST_MESSAGE);
            rc = MqttClient_Publish(&client, &publish);
            PRINTF("MQTT Publish: Topic %s, %s (%d)",
                publish.topic_name, MqttClient_ReturnCodeToString(rc), rc);

            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* Read Loop */
            PRINTF("MQTT Waiting for message...");

    CASE(WMQ_WAIT_MSG)
            while (mStopRead == 0) {
                /* Try and read packet */
                rc = MqttClient_WaitMessage(&client, cmd_timeout_ms);
                if (rc == MQTT_CODE_ERROR_TIMEOUT) {
                    /* Check to see if command data (stdin) is available */
                    rc = MqttClientNet_CheckForCommand(&net, rx_buf, MAX_BUFFER_SIZE);
                    if (rc > 0) {
                        /* Publish Topic */
                        XMEMSET(&publish, 0, sizeof(MqttPublish));
                        publish.retain = 0;
                        publish.qos = Qos;
                        publish.duplicate = 0;
                        publish.topic_name = topicName;
                        publish.packet_id = mqttclient_get_packetid();
                        publish.buffer = rx_buf;
                        publish.total_len = (word16)rc;
                        rc = MqttClient_Publish(&client, &publish);
                        PRINTF("MQTT Publish: Topic %s, %s (%d)",
                            publish.topic_name, MqttClient_ReturnCodeToString(rc), rc);
                    }
                    /* Keep Alive */
                    else {
                        rc = MqttClient_Ping(&client);
                        IF(rc == MQTT_CODE_CONTINUE)RETURN(rc) ;
                        if (rc != MQTT_CODE_SUCCESS) {
                            PRINTF("MQTT Ping Keep Alive Error: %s (%d)",
                                MqttClient_ReturnCodeToString(rc), rc);
                            break;
                        }
                    }
                }
                else {
                    IF(rc == MQTT_CODE_CONTINUE)RETURN(rc) ;
                    if (rc != MQTT_CODE_SUCCESS) {
                        /* There was an error */
                        PRINTF("MQTT Message Wait: %s (%d)",
                            MqttClient_ReturnCodeToString(rc), rc);
                        break;
                    }
                }

                /* Exit if test mode */
                if (test_mode) {
                    break;
                }
            }
            /* Check for error */
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* Unsubscribe Topics */
            XMEMSET(&unsubscribe, 0, sizeof(MqttUnsubscribe));
            unsubscribe.packet_id = mqttclient_get_packetid();
            unsubscribe.topic_count = sizeof(Topics)/sizeof(MqttTopic);
            unsubscribe.topics = Topics;
            rc = MqttClient_Unsubscribe(&client, &unsubscribe);
            PRINTF("MQTT Unsubscribe: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
    
} /* end of non-blocking SWITCH */

/* Disconnect */
disconn:
    IF(rc == MQTT_CODE_CONTINUE)RETURN(rc) ;
    rc = MqttClient_NetDisconnect(&client);
    PRINTF("MQTT Socket Disconnect: %s (%d)",
    MqttClient_ReturnCodeToString(rc), rc);

exit:
    IF(rc == MQTT_CODE_CONTINUE)RETURN(rc) ;
    /* Free resources */
    if (tx_buf) WOLFMQTT_FREE(tx_buf);
    if (rx_buf) WOLFMQTT_FREE(rx_buf);

    /* Cleanup network */
    MqttClientNet_DeInit(&net);

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

#ifdef USE_WINDOWS_API
        if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE) == FALSE) {
            PRINTF("Error setting Ctrl Handler! Error %d", (int)GetLastError());
        }
#elif HAVE_SIGNAL
        if (signal(SIGINT, sig_handler) == SIG_ERR) {
            PRINTF("Can't catch SIGINT");
        }
#endif

        mqttclient_test(&args);

        return args.return_code;
    }

#endif /* NO_MAIN_DRIVER */
