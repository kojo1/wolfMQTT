/* fwclient.h
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

#ifndef WOLFMQTT_FWCLIENT_H
#define WOLFMQTT_FWCLIENT_H


#ifdef WOLFMQTT_NONBLOCK
#define NO_MAIN_DRIVER

/* MQTT Client status control block */
enum MQTT_NB_Stat {
    WMQ_BEGIN,
    WMQ_INIT,
    WMQ_TCP_CONN,
    WMQ_MQTT_CONN,
    WMQ_SUB,
    WMQ_PUB,
    WMQ_WAIT_MSG,
} ;

typedef struct {
    enum MQTT_NB_Stat stat ;
    MqttClient client;
    MqttNet net;
    word16 port;
    const char* host ;
    int use_tls ;
    MqttQoS qos ;
    byte clean_session ;
    word16 keep_alive_sec ;
    const char* client_id ;
    int enable_lwt ;
    const char* username ;
    const char* password ;
    byte *tx_buf, *rx_buf;
    const char* topicName;
    word32 cmd_timeout_ms;
    byte test_mode ;
    
    MqttConnect connect;
    MqttMessage lwt_msg;
    MqttSubscribe subscribe; 
    MqttUnsubscribe unsubscribe;
    MqttTopic topics[1], *topic;
    MqttPublish publish;
} MQTT_nbCtl ;
#endif 

/* Exposed functions */
#ifdef WOLFMQTT_NONBLOCK
void mqttclient_test_init(MQTT_nbCtl *mqtt_ctl);
int mqttclient_test(void* args, MQTT_nbCtl *mqtt_ctl);
#else
int fwclient_test(void* args);
#endif

#endif /* WOLFMQTT_FWCLIENT_H */
