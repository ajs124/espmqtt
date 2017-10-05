/*
* @Author: Tuan PM
* @Date:   2016-09-10 09:33:06
* @Last Modified by:   Tuan PM
* @Last Modified time: 2017-02-15 13:11:53
*/
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"
#include "ringbuf.h"
#include "mqtt.h"
#include "esp_log.h"

#include "mbedtls/platform.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

/* Root cert taken from server_root_cert.pem
   The PEM file was extracted from the output of this command:
   openssl s_client -showcerts -connect p.toposens.de:9001 </dev/null
   The CA root cert is the last cert given in the chain of certs. */
extern const uint8_t server_root_cert_pem_start[] asm("_binary_server_root_cert_pem_start");
extern const uint8_t server_root_cert_pem_end[] asm("_binary_server_root_cert_pem_end");

#define TAG "MQTT"

static TaskHandle_t xMqttTask = NULL;
static TaskHandle_t xMqttSendingTask = NULL;

static bool terminate_mqtt = false;
static bool mbedtls_initialized = false;

void _mqtt_mbedtls_cleanup(mqtt_client *client, int ret) {
	if(&client->ssl != NULL) {
		mbedtls_ssl_session_reset(&client->ssl);
	}
	mbedtls_net_free(&client->server_fd);

	if(ret != 0) {
		char *buf = malloc(100);
		mbedtls_strerror(ret, buf, 100);
		ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
		free(buf);
	}
}

void _mqtt_mbedtls_close(mqtt_client *client) {
    ESP_LOGD(TAG, "_mqtt_mbedtls_close called in task: %s", pcTaskGetTaskName(NULL));
	if(&client->ssl != NULL) {
		mbedtls_ssl_close_notify(&client->ssl);
		mbedtls_ssl_session_reset(&client->ssl);
	}
	ESP_LOGD(TAG, "_mqtt_mbedtls_close about to return");
}

static bool _mqtt_mbedtls_connect(mqtt_client *client) {
	int ret, flags;
//	if(client->server_fd.fd < 0) {
        mbedtls_net_init(&client->server_fd);

		ESP_LOGI(TAG, "Connecting to %s:%s...", client->settings->host, client->settings->port);

		if ((ret = mbedtls_net_connect(&client->server_fd, client->settings->host, client->settings->port, MBEDTLS_NET_PROTO_TCP)) != 0) {
			ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
			_mqtt_mbedtls_cleanup(client, ret);
			return false;
		}
		ESP_LOGI(TAG, "Connected.");

        mbedtls_ssl_set_bio(&client->ssl, &client->server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

		while ((ret = mbedtls_ssl_handshake(&client->ssl)) != 0) {
			if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
				_mqtt_mbedtls_cleanup(client, ret);
				return false;
			}
		}

        ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

		if ((flags = mbedtls_ssl_get_verify_result(&client->ssl)) != 0) {
		    char buf[256];
			/* In real life, we probably want to close connection if ret != 0 */
			ESP_LOGW(TAG, "Failed to verify peer certificate!");
			mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
			ESP_LOGW(TAG, "verification info: %s", buf);
		} else {
			ESP_LOGI(TAG, "Certificate verified.");
		}

        ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(&client->ssl));

//	}
	return true;
}

int _mqtt_mbedtls_init(mqtt_client *client, mbedtls_entropy_context entropy,
		mbedtls_ctr_drbg_context ctr_drbg, mbedtls_x509_crt cacert,
		mbedtls_ssl_config conf) {
	if(mbedtls_initialized) return -128;
    int ret;

    mbedtls_ssl_init(&client->ssl);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ESP_LOGI(TAG, "Seeding the random number generator");

    mbedtls_ssl_config_init(&conf);

    mbedtls_entropy_init(&entropy);
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        return -1;
    }

    ESP_LOGI(TAG, "Loading the CA root certificate...");

    ret = mbedtls_x509_crt_parse(&cacert, server_root_cert_pem_start, server_root_cert_pem_end-server_root_cert_pem_start);

    if(ret < 0) {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        return -2;
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

	/* Hostname set here should match CN in server certificate */
	if ((ret = mbedtls_ssl_set_hostname(&client->ssl, client->settings->host)) != 0) {
		ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
		return -3;
	}

	ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

	if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
		_mqtt_mbedtls_cleanup(client, ret);
		return -4;
	}

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#ifdef CONFIG_MBEDTLS_DEBUG
	mbedtls_esp_enable_debug_log(&conf, 4);
#endif

	if ((ret = mbedtls_ssl_setup(&client->ssl, &conf)) != 0) {
		ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
		_mqtt_mbedtls_cleanup(client, ret);
		return -5;
	}

    ESP_LOGD(TAG, "Successfully initialized mbedtls");
    mbedtls_initialized = true;
    return 1;
}

static void mqtt_queue(mqtt_client *client) {
    int msg_len;
    while (rb_available(&client->send_rb) < client->mqtt_state.outbound_message->length) {
        xQueueReceive(client->xSendingQueue, &msg_len, 1000 / portTICK_RATE_MS);
        rb_read(&client->send_rb, client->mqtt_state.out_buffer, msg_len);
    }
    rb_write(&client->send_rb,
             client->mqtt_state.outbound_message->data,
             client->mqtt_state.outbound_message->length);
    xQueueSend(client->xSendingQueue, &client->mqtt_state.outbound_message->length, 0);
}

int _mqtt_mbedtls_read(mqtt_client *client, void *buf, int len, int timeout_ms) {
    int ret;
    struct timeval tv;
    if (timeout_ms > 0) {
        tv.tv_sec = 0;
        tv.tv_usec = timeout_ms * 1000;
        while (tv.tv_usec > 1000 * 1000) {
            tv.tv_usec -= 1000 * 1000;
            tv.tv_sec++;
        }
        setsockopt(client->server_fd.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

	bzero(buf, sizeof(*buf));
	ret = mbedtls_ssl_read(&client->ssl, (unsigned char *) buf, len);

	if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
		ESP_LOGD(TAG, "there is more data to be read (or written?)");
	} else if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
		ESP_LOGD(TAG, "tls connection is about to be closed");
		return -1;
	} else if (ret < 0) {
		ESP_LOGE(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
		return -2;
	} else if (ret == 0) {
		ESP_LOGI(TAG, "connection closed");
		_mqtt_mbedtls_close(client);
		return -3;
	}

    if (timeout_ms > 0) {
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        setsockopt(client->server_fd.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    return ret;
}

int _mqtt_mbedtls_write(mqtt_client *client, const void *buffer, int len, int timeout_ms) {
    int result;
    size_t written_bytes = 0;
    struct timeval tv;
    if (timeout_ms > 0) {
        tv.tv_sec = 0;
        tv.tv_usec = timeout_ms * 1000;
        while (tv.tv_usec > 1000 * 1000) {
            tv.tv_usec -= 1000 * 1000;
            tv.tv_sec++;
        }
        setsockopt(client->server_fd.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    ESP_LOGD(TAG, "Sending %d bytes of data", len);
    do {
	    if(&client->ssl == NULL) return written_bytes;
	    result = mbedtls_ssl_write(&client->ssl, (const unsigned char *) buffer + written_bytes, len - written_bytes);
	    if (result >= 0) {
		    ESP_LOGD(TAG, "%d bytes written", result);
		    written_bytes += result;
	    } else if (result != MBEDTLS_ERR_SSL_WANT_WRITE && result != MBEDTLS_ERR_SSL_WANT_READ) {
		    ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -result);
		    _mqtt_mbedtls_cleanup(client, result);
		    return -1;
	    }
    } while (written_bytes < len);

    if (result > 0 && timeout_ms > 0) {
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        setsockopt(client->server_fd.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    return written_bytes;
}

/*
 * mqtt_connect
 * input - client
 * return 1: success, 0: fail
 */
static bool mqtt_connect(mqtt_client *client)
{
    int write_len, read_len, connect_rsp_code;


    mqtt_msg_init(&client->mqtt_state.mqtt_connection,
                  client->mqtt_state.out_buffer,
                  client->mqtt_state.out_buffer_length);
    client->mqtt_state.outbound_message = mqtt_msg_connect(&client->mqtt_state.mqtt_connection,
                                          client->mqtt_state.connect_info);
    client->mqtt_state.pending_msg_type = mqtt_get_type(client->mqtt_state.outbound_message->data);
    client->mqtt_state.pending_msg_id = mqtt_get_id(client->mqtt_state.outbound_message->data,
                                        client->mqtt_state.outbound_message->length);
    ESP_LOGI(TAG,"Sending MQTT CONNECT message, type: %d, id: %04X",
              client->mqtt_state.pending_msg_type,
              client->mqtt_state.pending_msg_id);

    write_len = client->settings->write_cb(client,
                      client->mqtt_state.outbound_message->data,
                      client->mqtt_state.outbound_message->length, 0);
    if(write_len < 0) {
        ESP_LOGE(TAG,"Writing failed: %d", errno);
        return false;
    }

    ESP_LOGI(TAG,"Reading MQTT CONNECT response message");

    read_len = client->settings->read_cb(client, client->mqtt_state.in_buffer, CONFIG_MQTT_BUFFER_SIZE_BYTE, 10 * 1000);

    if (read_len < 0) {
        ESP_LOGE(TAG,"Error network response");
        return false;
    }
    if (mqtt_get_type(client->mqtt_state.in_buffer) != MQTT_MSG_TYPE_CONNACK) {
        ESP_LOGE(TAG,"Invalid MSG_TYPE response: %d, read_len: %d", mqtt_get_type(client->mqtt_state.in_buffer), read_len);
        return false;
    }
    connect_rsp_code = mqtt_get_connect_return_code(client->mqtt_state.in_buffer);
    switch (connect_rsp_code) {
        case CONNECTION_ACCEPTED:
            ESP_LOGI(TAG,"Connected");
            return true;
        case CONNECTION_REFUSE_PROTOCOL:
            ESP_LOGW(TAG,"Connection refused, bad protocol");
            return false;
        case CONNECTION_REFUSE_SERVER_UNAVAILABLE:
            ESP_LOGW(TAG,"Connection refused, server unavailable");
            return false;
        case CONNECTION_REFUSE_BAD_USERNAME:
            ESP_LOGW(TAG,"Connection refused, bad username or password");
            return false;
        case CONNECTION_REFUSE_NOT_AUTHORIZED:
            ESP_LOGW(TAG,"Connection refused, not authorized");
            return false;
        default:
            ESP_LOGW(TAG,"Connection refused, Unknow reason");
            return false;
    }
    return false;
}

void mqtt_sending_task(void *pvParameters)
{
    mqtt_client *client = (mqtt_client *)pvParameters;
    uint32_t msg_len;
    int send_len;
    bool connected = true;
    ESP_LOGI(TAG,"mqtt_sending_task");

    while (connected) {
        if (xQueueReceive(client->xSendingQueue, &msg_len, 1000 / portTICK_RATE_MS)) {
            //queue available
            while (msg_len > 0) {
                send_len = msg_len;
                if (send_len > CONFIG_MQTT_BUFFER_SIZE_BYTE) {
                    send_len = CONFIG_MQTT_BUFFER_SIZE_BYTE;
		}
                ESP_LOGD(TAG,"Sending %d bytes", send_len);

                // blocking operation, takes data from ring buffer
                rb_read(&client->send_rb, client->mqtt_state.out_buffer, send_len);
                client->mqtt_state.pending_msg_type = mqtt_get_type(client->mqtt_state.out_buffer);
                client->mqtt_state.pending_msg_id = mqtt_get_id(client->mqtt_state.out_buffer, send_len);
                send_len = client->settings->write_cb(client, client->mqtt_state.out_buffer, send_len, 5 * 1000);
                if(send_len <= 0) {
                    ESP_LOGI(TAG,"Write error: %d", errno);
                    connected = false;
                    break;
                }

                //TODO: Check sending type, to callback publish message
                msg_len -= send_len;
            }
            //invalidate keepalive timer
            client->keepalive_tick = client->settings->keepalive / 2;
        }
        else {
            if (client->keepalive_tick > 0) client->keepalive_tick --;
            else {
                client->keepalive_tick = client->settings->keepalive / 2;
                client->mqtt_state.outbound_message = mqtt_msg_pingreq(&client->mqtt_state.mqtt_connection);
                client->mqtt_state.pending_msg_type = mqtt_get_type(client->mqtt_state.outbound_message->data);
                client->mqtt_state.pending_msg_id = mqtt_get_id(client->mqtt_state.outbound_message->data,
                                                    client->mqtt_state.outbound_message->length);
                ESP_LOGI(TAG,"Sending pingreq");
                send_len = client->settings->write_cb(client,
                      client->mqtt_state.outbound_message->data,
                      client->mqtt_state.outbound_message->length, 0);
                if(send_len <= 0) {
					ESP_LOGI(TAG,"Write error: %d", errno);
                    connected = false;
					break;
				}
            }
        }
    }
//    _mqtt_mbedtls_close(client);
    xMqttSendingTask = NULL;
    ESP_LOGD(TAG, "mqtt_sending_task destroy");
    vTaskDelete(NULL);
}

void deliver_publish(mqtt_client *client, uint8_t *message, int length)
{
    mqtt_event_data_t event_data;
    int len_read, total_mqtt_len = 0, mqtt_len = 0, mqtt_offset = 0;

    do
    {
        event_data.topic_length = length;
        event_data.topic = mqtt_get_publish_topic(message, &event_data.topic_length);
        event_data.data_length = length;
        event_data.data = mqtt_get_publish_data(message, &event_data.data_length);

        if(total_mqtt_len == 0){
            total_mqtt_len = client->mqtt_state.message_length - client->mqtt_state.message_length_read + event_data.data_length;
            mqtt_len = event_data.data_length;
        } else {
            mqtt_len = len_read;
        }

        event_data.data_total_length = total_mqtt_len;
        event_data.data_offset = mqtt_offset;
        event_data.data_length = mqtt_len;

        ESP_LOGI(TAG,"Data received: %d/%d bytes ", mqtt_len, total_mqtt_len);
        if(client->settings->data_cb) {
            client->settings->data_cb(client, &event_data);
        }
        mqtt_offset += mqtt_len;
        if (client->mqtt_state.message_length_read >= client->mqtt_state.message_length)
            break;

        len_read = client->settings->read_cb(client, client->mqtt_state.in_buffer, CONFIG_MQTT_BUFFER_SIZE_BYTE, 0);
        if(len_read < 0) {
            ESP_LOGI(TAG,"Read error: %d", errno);
            break;
        }
        client->mqtt_state.message_length_read += len_read;
    } while (1);

}
void mqtt_start_receive_schedule(mqtt_client *client)
{
    int read_len;
    uint8_t msg_type;
    uint8_t msg_qos;
    uint16_t msg_id;

    while (1) {
    	if (terminate_mqtt) break;
    	if (xMqttSendingTask == NULL) break;

        read_len = client->settings->read_cb(client, client->mqtt_state.in_buffer, CONFIG_MQTT_BUFFER_SIZE_BYTE, 0);

        ESP_LOGD(TAG, "%d bytes read", read_len);
        if (read_len <= 0) {
            // ECONNRESET for example
            ESP_LOGW(TAG, "Read error %d", read_len);
            break;
        }

        msg_type = mqtt_get_type(client->mqtt_state.in_buffer);
        msg_qos = mqtt_get_qos(client->mqtt_state.in_buffer);
        msg_id = mqtt_get_id(client->mqtt_state.in_buffer, client->mqtt_state.in_buffer_length);
        // ESP_LOGI(TAG,"msg_type %d, msg_id: %d, pending_id: %d", msg_type, msg_id, client->mqtt_state.pending_msg_type);
        switch (msg_type)
        {
            case MQTT_MSG_TYPE_SUBACK:
                if (client->mqtt_state.pending_msg_type == MQTT_MSG_TYPE_SUBSCRIBE && client->mqtt_state.pending_msg_id == msg_id) {
                    ESP_LOGI(TAG,"Subscribe successful");
                    if (client->settings->subscribe_cb) {
                        client->settings->subscribe_cb(client, NULL);
                    }
                }
                break;
            case MQTT_MSG_TYPE_UNSUBACK:
                if (client->mqtt_state.pending_msg_type == MQTT_MSG_TYPE_UNSUBSCRIBE && client->mqtt_state.pending_msg_id == msg_id)
                    ESP_LOGI(TAG,"UnSubscribe successful");
                break;
            case MQTT_MSG_TYPE_PUBLISH:
                if (msg_qos == 1)
                    client->mqtt_state.outbound_message = mqtt_msg_puback(&client->mqtt_state.mqtt_connection, msg_id);
                else if (msg_qos == 2)
                    client->mqtt_state.outbound_message = mqtt_msg_pubrec(&client->mqtt_state.mqtt_connection, msg_id);

                if (msg_qos == 1 || msg_qos == 2) {
                    ESP_LOGI(TAG,"Queue response QoS: %d", msg_qos);
                    mqtt_queue(client);
                    // if (QUEUE_Puts(&client->msgQueue, client->mqtt_state.outbound_message->data, client->mqtt_state.outbound_message->length) == -1) {
                    //     ESP_LOGI(TAG,"MQTT: Queue full");
                    // }
                }
                client->mqtt_state.message_length_read = read_len;
                client->mqtt_state.message_length = mqtt_get_total_length(client->mqtt_state.in_buffer, client->mqtt_state.message_length_read);
                ESP_LOGI(TAG,"deliver_publish");

                deliver_publish(client, client->mqtt_state.in_buffer, client->mqtt_state.message_length_read);
                // deliver_publish(client, client->mqtt_state.in_buffer, client->mqtt_state.message_length_read);
                break;
            case MQTT_MSG_TYPE_PUBACK:
                if (client->mqtt_state.pending_msg_type == MQTT_MSG_TYPE_PUBLISH && client->mqtt_state.pending_msg_id == msg_id) {
                    ESP_LOGI(TAG,"received MQTT_MSG_TYPE_PUBACK, finish QoS1 publish");
                }

                break;
            case MQTT_MSG_TYPE_PUBREC:
                client->mqtt_state.outbound_message = mqtt_msg_pubrel(&client->mqtt_state.mqtt_connection, msg_id);
                mqtt_queue(client);
                break;
            case MQTT_MSG_TYPE_PUBREL:
                client->mqtt_state.outbound_message = mqtt_msg_pubcomp(&client->mqtt_state.mqtt_connection, msg_id);
                mqtt_queue(client);

                break;
            case MQTT_MSG_TYPE_PUBCOMP:
                if (client->mqtt_state.pending_msg_type == MQTT_MSG_TYPE_PUBREL && client->mqtt_state.pending_msg_id == msg_id) {
                    ESP_LOGI(TAG,"Receive MQTT_MSG_TYPE_PUBCOMP, finish QoS2 publish");
                }
                break;
            case MQTT_MSG_TYPE_PINGREQ:
                client->mqtt_state.outbound_message = mqtt_msg_pingresp(&client->mqtt_state.mqtt_connection);
                mqtt_queue(client);
                break;
            case MQTT_MSG_TYPE_PINGRESP:
                ESP_LOGI(TAG,"MQTT_MSG_TYPE_PINGRESP");
                // Ignore
                break;
        }
    }
}

void mqtt_destroy(mqtt_client *client)
{
	if (client == NULL) return;

	vQueueDelete(client->xSendingQueue);

    free(client->mqtt_state.in_buffer);
    free(client->mqtt_state.out_buffer);
    free(client->send_rb.p_o);
    free(client);

    ESP_LOGI(TAG,"Client destroyed");
}

void mqtt_task(void *pvParameters)
{
    ESP_LOGI(TAG,"Starting mqtt task");

    mqtt_client *client = (mqtt_client *)pvParameters;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;
    _mqtt_mbedtls_init(client, entropy, ctr_drbg, cacert, conf);

    while (1) {
    	if (terminate_mqtt) break;

        client->settings->connect_cb(client);

        ESP_LOGI(TAG,"Connected to server %s:%s", client->settings->host, client->settings->port);
        if (!mqtt_connect(client)) {
            client->settings->disconnect_cb(client);

            if (client->settings->disconnected_cb) {
				client->settings->disconnected_cb(client, NULL);
			}

            if (!client->settings->auto_reconnect) {
				break;
			} else {
				continue;
			}
        }
        ESP_LOGI(TAG,"Connected to MQTT broker, creating sending thread before calling connected callback");
        xTaskCreate(&mqtt_sending_task, "mqtt_sending_task", 2048, client, CONFIG_MQTT_PRIORITY + 1, &xMqttSendingTask);
        if (client->settings->connected_cb) {
            client->settings->connected_cb(client, NULL);
        }

        ESP_LOGI(TAG,"mqtt_start_receive_schedule");
        mqtt_start_receive_schedule(client);

        ESP_LOGD(TAG, "wat?");
        client->settings->disconnect_cb(client);
        ESP_LOGD(TAG, "srsly");
        if (client->settings->disconnected_cb) {
        	client->settings->disconnected_cb(client, NULL);
		}

/*      FIXME: This hardlocks the µC
        if (xMqttSendingTask != NULL) {
            ESP_LOGD(TAG, "Will delete sending task from mqtt_task");
            vTaskDelete(xMqttSendingTask);
        }*/
        if (!client->settings->auto_reconnect) {
            ESP_LOGD(TAG, "About to auto_reconnect");
			break;
		}

        // clean up for new reconnect
        xQueueReset(client->xSendingQueue);
        rb_reset(&client->send_rb);

        vTaskDelay(1000 / portTICK_RATE_MS);

    }

    mqtt_destroy(client);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_config_free(&conf);

    xMqttTask = NULL;
    vTaskDelete(NULL);
}

mqtt_client *mqtt_start(mqtt_settings *settings)
{
	terminate_mqtt = false;

    uint8_t *rb_buf;
    if (xMqttTask != NULL)
        return NULL;
    mqtt_client *client = malloc(sizeof(mqtt_client));

    if (client == NULL) {
        ESP_LOGE(TAG,"Memory not enough");
        return NULL;
    }
    memset(client, 0, sizeof(mqtt_client));

    if (settings->lwt_msg_len > CONFIG_MQTT_MAX_LWT_MSG) {
        ESP_LOGE(TAG,"Last will message longer than CONFIG_MQTT_MAX_LWT_MSG!");
    }

    client->settings = settings;
    client->connect_info.client_id = settings->client_id;
    client->connect_info.username = settings->username;
    client->connect_info.password = settings->password;
    client->connect_info.will_topic = settings->lwt_topic;
    client->connect_info.will_message = settings->lwt_msg;
    client->connect_info.will_qos = settings->lwt_qos;
    client->connect_info.will_retain = settings->lwt_retain;
    client->connect_info.will_length = settings->lwt_msg_len;

    client->keepalive_tick = settings->keepalive / 2;

    client->connect_info.keepalive = settings->keepalive;
    client->connect_info.clean_session = settings->clean_session;

    client->mqtt_state.in_buffer = (uint8_t *)malloc(CONFIG_MQTT_BUFFER_SIZE_BYTE);
    client->mqtt_state.in_buffer_length = CONFIG_MQTT_BUFFER_SIZE_BYTE;
    client->mqtt_state.out_buffer =  (uint8_t *)malloc(CONFIG_MQTT_BUFFER_SIZE_BYTE);
    client->mqtt_state.out_buffer_length = CONFIG_MQTT_BUFFER_SIZE_BYTE;
    client->mqtt_state.connect_info = &client->connect_info;

    if (!client->settings->connect_cb)
        client->settings->connect_cb = _mqtt_mbedtls_connect;
    if (!client->settings->disconnect_cb)
        client->settings->disconnect_cb = _mqtt_mbedtls_close;
    if (!client->settings->read_cb)
        client->settings->read_cb = _mqtt_mbedtls_read;
    if (!client->settings->write_cb)
        client->settings->write_cb = _mqtt_mbedtls_write;

    /* Create a queue capable of containing 64 unsigned long values. */
    client->xSendingQueue = xQueueCreate(64, sizeof( uint32_t ));
    rb_buf = (uint8_t*) malloc(CONFIG_MQTT_QUEUE_BUFFER_SIZE_WORD * 4);

    if (rb_buf == NULL) {
        ESP_LOGE(TAG,"Memory not enough");
        return NULL;
    }

    rb_init(&client->send_rb, rb_buf, CONFIG_MQTT_QUEUE_BUFFER_SIZE_WORD * 4, 1);

    mqtt_msg_init(&client->mqtt_state.mqtt_connection,
                  client->mqtt_state.out_buffer,
                  client->mqtt_state.out_buffer_length);

    xTaskCreate(&mqtt_task, "mqtt_task", 10240, client, CONFIG_MQTT_PRIORITY, &xMqttTask);
    return client;
}

void mqtt_subscribe(mqtt_client *client, const char *topic, uint8_t qos)
{
    client->mqtt_state.outbound_message = mqtt_msg_subscribe(&client->mqtt_state.mqtt_connection,
                                          topic, qos,
                                          &client->mqtt_state.pending_msg_id);
    ESP_LOGI(TAG,"Queue subscribe, topic\"%s\", id: %d", topic, client->mqtt_state.pending_msg_id);
    mqtt_queue(client);
}


void mqtt_unsubscribe(mqtt_client *client, const char *topic)
{
	client->mqtt_state.outbound_message = mqtt_msg_unsubscribe(&client->mqtt_state.mqtt_connection,
	                                          topic,
	                                          &client->mqtt_state.pending_msg_id);
	ESP_LOGI(TAG,"Queue unsubscribe, topic\"%s\", id: %d", topic, client->mqtt_state.pending_msg_id);
	mqtt_queue(client);
}

void mqtt_publish(mqtt_client* client, const char *topic, const char *data, int len, int qos, int retain)
{

    client->mqtt_state.outbound_message = mqtt_msg_publish(&client->mqtt_state.mqtt_connection,
                                          topic, data, len,
                                          qos, retain,
                                          &client->mqtt_state.pending_msg_id);
    mqtt_queue(client);
    ESP_LOGI(TAG,"Queuing publish, length: %d, queue size(%d/%d)",
              client->mqtt_state.outbound_message->length,
              client->send_rb.fill_cnt,
              client->send_rb.size);
}

void mqtt_stop()
{
	terminate_mqtt = true;
}

