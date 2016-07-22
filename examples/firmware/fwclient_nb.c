/* fwclient_nb.c
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

#if defined(WOLFMQTT_NONBLOCK) || defined(MICROCHIP_MPLAB_HARMONY)

#include <wolfssl/options.h>
#include <wolfssl/version.h>

#define NO_MAIN_DRIVER

/* The signature wrapper for this example was added in wolfSSL after 3.7.1 */
#if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX > 0x03007001 \
	    && defined(HAVE_ECC )
    #undef ENABLE_FIRMWARE_EXAMPLE
    #define ENABLE_FIRMWARE_EXAMPLE
#endif


#if defined(ENABLE_FIRMWARE_EXAMPLE)

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/hash.h>

#define WOLFMQTT_CUSTOM_TYPES

#include "wolfmqtt/mqtt_client.h"
#include "examples/mqttexample.h"

#include "examples/mqttnet.h"
#include "examples/firmware/fwclient.h"
#include "examples/firmware/firmware.h"

/* Configuration */
#undef DEFAULT_MQTT_QOS
#define DEFAULT_MQTT_QOS        MQTT_QOS_2
#define DEFAULT_CLIENT_ID       "WolfMQTTFwClient"
#define DEFAULT_SAVE_AS         "firmware.bin"
#define MAX_BUFFER_SIZE         FIRMWARE_MAX_PACKET

/* Globals */
int myoptind = 0;
char* myoptarg = NULL;

/* Locals */
static int mStopRead = 0;
static const char* mTlsFile = NULL;
static byte* mFwBuf;
static const char* mFwFile = DEFAULT_SAVE_AS;
static int mPacketIdLast;

/* Usage */
static void Usage(void)
{
    PRINTF("fwclient:");
    PRINTF("-?          Help, print this usage");
    PRINTF("-f <file>   Save firmware file as, default %s",
        DEFAULT_SAVE_AS);
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
    PRINTF("-u <str>    Username");
    PRINTF("-w <str>    Password");
    PRINTF("-C <num>    Command Timeout, default %dms", DEFAULT_CMD_TIMEOUT_MS);
    PRINTF("-T          Test mode");
}

static word16 mqttclient_get_packetid(void)
{
    mPacketIdLast = (mPacketIdLast >= MAX_PACKET_ID) ? 1 : mPacketIdLast + 1;
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

static int fwfile_save(const char* filePath, byte* fileBuf, int fileLen)
{
    int ret = 0;
    FILE* file = NULL;

    /* Check arguments */
    if (filePath == NULL || XSTRLEN(filePath) == 0 || fileLen == 0 ||
        fileBuf == NULL) {
        return EXIT_FAILURE;
    }
#if defined(NO_FILESYSTEM)
    PRINTF("Entered fwfile_save(len=%d):No Filesystem\n", fileLen) ;
    return fileLen ;
#else
    /* Open file */
    file = fopen(filePath, "wb");
    if (file == NULL) {
        PRINTF("File %s write error!", filePath);
        ret = EXIT_FAILURE;
        goto exit;
    }

    /* Save file */
    ret = (int)fwrite(fileBuf, 1, fileLen, file);
    if (ret != fileLen) {
        PRINTF("Error reading file! %d", ret);
        ret = EXIT_FAILURE;
        goto exit;
    }

    PRINTF("Saved %d bytes to %s", fileLen, filePath);

exit:
    if (file) {
        fclose(file);
    }
    return ret;
#endif
}

static int fw_message_process(byte* buffer, word32 len)
{
    int rc;
    FirmwareHeader* header = (FirmwareHeader*)buffer;
    byte *sigBuf, *pubKeyBuf, *fwBuf;
    ecc_key eccKey;
    word32 check_len = sizeof(FirmwareHeader) + header->sigLen +
        header->pubKeyLen + header->fwLen;

    /* Verify entire message was received */
    if (len != check_len) {
        PRINTF("Message header vs. actual size mismatch! %d != %d",
            len, check_len);
        return EXIT_FAILURE;
    }

    /* Get pointers to structure elements */
    sigBuf = (buffer + sizeof(FirmwareHeader));
    pubKeyBuf = (buffer + sizeof(FirmwareHeader) + header->sigLen);
    fwBuf = (buffer + sizeof(FirmwareHeader) + header->sigLen +
        header->pubKeyLen);

    /* Import the public key */
    wc_ecc_init(&eccKey);
    rc = wc_ecc_import_x963(pubKeyBuf, header->pubKeyLen, &eccKey);
    if (rc == 0) {
        /* Perform signature verification using public key */
        rc = wc_SignatureVerify(
            FIRMWARE_HASH_TYPE, FIRMWARE_SIG_TYPE,
            fwBuf, header->fwLen,
            sigBuf, header->sigLen,
            &eccKey, sizeof(eccKey));
        PRINTF("Firmware Signature Verification: %s (%d)",
            (rc == 0) ? "Pass" : "Fail", rc);

        if (rc == 0) {
            /* TODO: Process firmware image */
            /* For example, save to disk using topic name */
            fwfile_save(mFwFile, fwBuf, header->fwLen);
        }
    }
    else {
        PRINTF("ECC public key import failed! %d", rc);
    }
    wc_ecc_free(&eccKey);

    return rc;
}

static int mqttclient_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    (void)client; /* Supress un-used argument */

    /* Verify this message is for the firmware topic */
    if (msg_new &&
        memcmp(msg->topic_name, FIRMWARE_TOPIC_NAME,
            msg->topic_name_len) == 0 &&
        !mFwBuf)
    {
        /* Allocate buffer for entire message */
        /* Note: On an embedded system this could just be a write to flash.
                 If writting to flash change FIRMWARE_MAX_BUFFER to match
                 block size */
        mFwBuf = (byte*)WOLFMQTT_MALLOC(msg->total_len);
        if (mFwBuf == NULL) {
            return MQTT_CODE_ERROR_OUT_OF_BUFFER;
        }

        /* Print incoming message */
        PRINTF("MQTT Firmware Message: Qos %d, Len %u",
            msg->qos, msg->total_len);
    }

    if (mFwBuf) {
        XMEMCPY(&mFwBuf[msg->buffer_pos], msg->buffer, msg->buffer_len);

        /* Process message if done */
        if (msg_done) {
            fw_message_process(mFwBuf, msg->total_len);

            /* Free */
            WOLFMQTT_FREE(mFwBuf);
            mFwBuf = NULL;
        }
    }

    /* Return negative to termine publish processing */
    return MQTT_CODE_SUCCESS;
}

/* #if defined(WOLFMQTT_NONBLOCK) || defined(MICROCHIP_MPLAB_HARMONY) */
/* making following data access to the control block */
void fwclient_test_init(MQTT_nbCtl *mqtt_ctl) 
{    
    mqtt_ctl->stat = WMQ_BEGIN ;
}

int fwclient_test(void* args, MQTT_nbCtl *mqtt_ctl)
{
    int rc;
    
    switch(mqtt_ctl->stat) {
    case WMQ_BEGIN:
    
    mqtt_ctl->port = 0;
    mqtt_ctl->host = DEFAULT_MQTT_HOST;
    mqtt_ctl->use_tls = 0;
    mqtt_ctl->qos = DEFAULT_MQTT_QOS;
    mqtt_ctl->clean_session = 1;
    mqtt_ctl->keep_alive_sec = DEFAULT_KEEP_ALIVE_SEC;
    mqtt_ctl->client_id = DEFAULT_CLIENT_ID;
    mqtt_ctl->enable_lwt = 0;
    mqtt_ctl->username = NULL;
    mqtt_ctl->password = NULL;
    mqtt_ctl->tx_buf = NULL, mqtt_ctl->rx_buf = NULL;
    mqtt_ctl->topicName = DEFAULT_TOPIC_NAME;
    mqtt_ctl->cmd_timeout_ms = DEFAULT_CMD_TIMEOUT_MS;
    mqtt_ctl->test_mode = 0;

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;

    ((func_args*)args)->return_code = -1; /* error state */

    while ((rc = mygetopt(argc, argv, "?f:h:p:tc:q:sk:i:u:w:C:T")) != -1) {
        switch ((char)rc) {
            case '?' :
                Usage();
                return(EXIT_SUCCESS);

            case 'f':
                mFwFile = myoptarg;
                break;

            case 'h' :
                mqtt_ctl->host   = myoptarg;
                break;

            case 'p' :
                mqtt_ctl->port = (word16)atoi(myoptarg);
                if (mqtt_ctl->port == 0) {
                    return err_sys("Invalid Port Number!");
                }
                break;

            case 't':
                mqtt_ctl->use_tls = 1;
                break;

            case 'c':
                mTlsFile = myoptarg;
                break;

            case 'q' :
                mqtt_ctl->qos = (MqttQoS)((byte)XATOI(myoptarg));
                if (mqtt_ctl->qos > MQTT_QOS_2) {
                    return err_sys("Invalid QoS value!");
                }
                break;

            case 's':
                mqtt_ctl->clean_session = 0;
                break;

            case 'k':
                mqtt_ctl->keep_alive_sec = XATOI(myoptarg);
                break;

            case 'i':
                mqtt_ctl->client_id = myoptarg;
                break;

            case 'u':
                mqtt_ctl->username = myoptarg;
                break;

            case 'w':
                mqtt_ctl->password = myoptarg;
                break;

            case 'C':
                mqtt_ctl->cmd_timeout_ms = XATOI(myoptarg);
                break;

            case 'T':
                mqtt_ctl->test_mode = 1;
                break;

            default:
                Usage();
                return(MY_EX_USAGE);
        }
    }

    myoptind = 0; /* reset for test cases */

    /* Start example MQTT Client */
    PRINTF("MQTT Firmware Client: QoS %d, Use TLS %d", mqtt_ctl->qos, mqtt_ctl->use_tls);
    mqtt_ctl->stat = WMQ_INIT ;
    
    case WMQ_INIT:

    /* Initialize Network */
    rc = MqttClientNet_Init(&(mqtt_ctl->net));
    if (rc == MQTT_CODE_CONTINUE)return rc ;
    PRINTF("MQTT Net Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }
    PRINTF("MQTT Net Init\n") ;
    /* Initialize MqttClient structure */
    mqtt_ctl->tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    mqtt_ctl->rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    rc = MqttClient_Init(&(mqtt_ctl->client), &(mqtt_ctl->net), mqttclient_message_cb,
        mqtt_ctl->tx_buf, MAX_BUFFER_SIZE, mqtt_ctl->rx_buf, MAX_BUFFER_SIZE,
        mqtt_ctl->cmd_timeout_ms);
    if (rc == MQTT_CODE_CONTINUE)return rc ;
    PRINTF("MQTT Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }
    mqtt_ctl->stat = WMQ_TCP_CONN ;
    
    case WMQ_TCP_CONN:

    /* Connect to broker */
    rc = MqttClient_NetConnect(&(mqtt_ctl->client), mqtt_ctl->host, mqtt_ctl->port,
        DEFAULT_CON_TIMEOUT_MS, mqtt_ctl->use_tls, mqttclient_tls_cb);
    if (rc == MQTT_CODE_CONTINUE)return rc ;
    PRINTF("MQTT Socket Connect: %s (%d, len=%d)",
        MqttClient_ReturnCodeToString(rc), rc, mqtt_ctl->client.rx_buf_len);
    if (rc != MQTT_CODE_SUCCESS)goto disconn ;
        
    mqtt_ctl->stat = WMQ_MQTT_CONN ;
    
    case WMQ_MQTT_CONN:

        /* Define connect parameters -> MQTT_nbCtl */
        /* MqttConnect connect; */
        XMEMSET(&(mqtt_ctl->connect), 0, sizeof(MqttConnect));
        mqtt_ctl->connect.keep_alive_sec = mqtt_ctl->keep_alive_sec;
        mqtt_ctl->connect.clean_session = mqtt_ctl->clean_session;
        mqtt_ctl->connect.client_id = mqtt_ctl->client_id;

        /* Optional authentication */
        mqtt_ctl->connect.username = mqtt_ctl->username;
        mqtt_ctl->connect.password = mqtt_ctl->password;

        /* Send Connect and wait for Connect Ack */
        rc = MqttClient_Connect(&(mqtt_ctl->client), &(mqtt_ctl->connect));
        if (rc == MQTT_CODE_CONTINUE)return rc ;
        PRINTF("MQTT Connect: %s (%len=%dd, )",
            MqttClient_ReturnCodeToString(rc), rc, mqtt_ctl->client.rx_buf_len);
            /* Validate Connect Ack info */
            PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
                mqtt_ctl->connect.ack.return_code,
                (mqtt_ctl->connect.ack.flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
                    1 : 0
            );
            if (rc != MQTT_CODE_SUCCESS)goto exit ;
            /* MqttSubscribe subscribe; */
            /* MqttTopic topics[1], *topic; */
            /* Build list of topics */
            mqtt_ctl->topics[0].topic_filter = mqtt_ctl->topicName;
            mqtt_ctl->topics[0].qos = mqtt_ctl->qos;

            /* Subscribe Topic */
            XMEMSET(&(mqtt_ctl->subscribe), 0, sizeof(MqttSubscribe));
            mqtt_ctl->subscribe.packet_id = mqttclient_get_packetid();
            mqtt_ctl->subscribe.topic_count = 1;
            mqtt_ctl->subscribe.topics = mqtt_ctl->topics;
            mqtt_ctl->topics[0].topic_filter = FIRMWARE_TOPIC_NAME;
            mqtt_ctl->topics[0].qos = mqtt_ctl->qos;

            mqtt_ctl->stat = WMQ_SUB ;
            
        case WMQ_SUB:
        {
            int i ;
            rc = MqttClient_Subscribe(&(mqtt_ctl->client), &(mqtt_ctl->subscribe));
            if (rc == MQTT_CODE_CONTINUE)return rc ;
            
            PRINTF("MQTT Subscribe: %s (%d, len = %d)",
                MqttClient_ReturnCodeToString(rc), rc, mqtt_ctl->client.rx_buf_len);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
            for (i = 0; i < mqtt_ctl->subscribe.topic_count; i++) {
                mqtt_ctl->topic = &(mqtt_ctl->subscribe.topics[i]);
                PRINTF("  Topic %s, Qos %u, Return Code %u",
                    mqtt_ctl->topic->topic_filter, 
                    mqtt_ctl->topic->qos, 
                    mqtt_ctl->topic->return_code);
            }
        }

            /* Read Loop */
            PRINTF("MQTT Waiting for message..., len=%d", mqtt_ctl->client.rx_buf_len);
            mqtt_ctl->stat = WMQ_WAIT_MSG ;
        
        case WMQ_WAIT_MSG:

            while (mStopRead == 0) {
                /* Try and read packet */
                rc = MqttClient_WaitMessage(&(mqtt_ctl->client), mqtt_ctl->cmd_timeout_ms);
                if (rc == MQTT_CODE_CONTINUE)return rc ;
                if (rc == MQTT_CODE_ERROR_TIMEOUT) {
                    /* Keep Alive */
                    rc = MqttClient_Ping(&(mqtt_ctl->client));
                    if (rc == MQTT_CODE_CONTINUE)return rc ;
                    if (rc != MQTT_CODE_SUCCESS) {
                        PRINTF("MQTT Ping Keep Alive Error: %s (%d)",
                            MqttClient_ReturnCodeToString(rc), rc);
                        break;
                    }
                }
                else {
                    if (rc == MQTT_CODE_CONTINUE)return rc ;
                    if (rc != MQTT_CODE_SUCCESS) {
                        /* There was an error */
                        PRINTF("MQTT Message Wait: %s (%d)",
                            MqttClient_ReturnCodeToString(rc), rc);
                        break;
                    }
                }
                
                /* Exit if test mode */
                if (mqtt_ctl->test_mode) {
                    break;
                }
            }
            /* Check for error */
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* Disconnect */
            rc = MqttClient_Disconnect(&(mqtt_ctl->client));
            PRINTF("MQTT Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
        }

/* Disconnect */
disconn:
    if(rc == MQTT_CODE_CONTINUE)return(rc) ;
    rc = MqttClient_NetDisconnect(&(mqtt_ctl->client));
    PRINTF("MQTT Socket Disconnect: %s (%d)", MqttClient_ReturnCodeToString(rc), rc);

exit:
    if(rc == MQTT_CODE_CONTINUE)return(rc) ;
    /* Free resources */
    if (mqtt_ctl->tx_buf) WOLFMQTT_FREE(mqtt_ctl->tx_buf);
    if (mqtt_ctl->rx_buf) WOLFMQTT_FREE(mqtt_ctl->rx_buf);

    /* Cleanup network */
    MqttClientNet_DeInit(&(mqtt_ctl->net));

    ((func_args*)args)->return_code = (rc == 0) ? 0 : EXIT_FAILURE;

    return 0;
}
#endif /* ENABLE_FIRMWARE_EXAMPLE */


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER
    #ifdef USE_WINDOWS_API
        static BOOL CtrlHandler(DWORD fdwCtrlType)
        {
            if (fdwCtrlType == CTRL_C_EVENT) {
            #if defined(ENABLE_FIRMWARE_EXAMPLE)
                mStopRead = 1;
            #endif
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
            #if defined(ENABLE_FIRMWARE_EXAMPLE)
                mStopRead = 1;
            #endif
                PRINTF("Received SIGINT");
            }
        }
    #endif

    int main(int argc, char** argv)
    {
        func_args args;

        args.argc = argc;
        args.argv = argv;
        args.return_code = 0;

#ifdef USE_WINDOWS_API
        if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE) == FALSE) {
            PRINTF("Error setting Ctrl Handler! Error %d", (int)GetLastError());
        }
#elif HAVE_SIGNAL
        if (signal(SIGINT, sig_handler) == SIG_ERR) {
            PRINTF("Can't catch SIGINT");
        }
#endif

    #if defined(ENABLE_FIRMWARE_EXAMPLE)
        fwclient_test(&args);
    #else
        /* This example requires wolfSSL after 3.7.1 for signature wrapper */
        PRINTF("Example not compiled in!");
        args.return_code = EXIT_FAILURE;
    #endif

        return args.return_code;
    }

#endif /* NO_MAIN_DRIVER */
    
#endif /* defined(WOLFMQTT_NONBLOCK) || defined(MICROCHIP_MPLAB_HARMONY) */