#include "net.h"
#include "net_tls.h"

// 'extension_type': {
//     0: 'server_name',
//     1: 'max_fragment_length',
//     2: 'client_certificate_url',
//     3: 'trusted_ca_keys',
//     4: 'truncated_hmac',
//     5: 'status_request',
//     6: 'user_mapping',
//     7: 'client_authz',
//     8: 'server_authz',
//     9: 'cert_type',
//     10: 'elliptic_curves',
//     11: 'ec_point_formats',
//     12: 'srp',
//     13: 'signature_algorithms',
//     14: 'use_srtp',
//     15: 'heartbeat',
//     16: 'application_layer_protocol_negotiation',
//     17: 'status_request_v2',
//     18: 'signed_certificate_timestamp',
//     19: 'client_certificate_type',
//     20: 'server_certificate_type',
//     21: 'padding',
//     22: 'encrypt_then_mac',
//     23: 'extended_master_secret',
//     35: 'SessionTicket_TLS',
//     13172: 'next_protocol_negotiation',
//     30031: 'channel_id_old',
//     30032: 'channel_id',
//     62208: 'tack',
//     65281: 'renegotiation_info'},
    
static int 
extension_message_info(struct tls_extension *ext)
{
    uint16_t list_len = 0;
    uint16_t name_len  = 0;
    uint8_t  name_type = 0;

    if (ext != NULL || ext->len == 0)
        return CMN_ERROR;
    
    switch (ext->type)
    {
    case 0:
        list_len = ntohs(GET_UINT16(ext->raw, 0));
        log_info("extension_data server_name list len: %u", list_len);

        name_type = GET_UINT8(ext->raw, 2);
        log_info("extension_data server_name name type: %u", name_type);

        name_len = ntohs(GET_UINT16(ext->raw, 3));
        log_info("extension_data server_name name len: %u", name_len);

        log_info("extension_data server_name is %s", (char *) ext->raw +5);
        break;
    case 13:
        list_len = ntohs(GET_UINT16(ext->raw, 0));
        log_info("extension_data signature_algorithms %u", list_len);
        break;
    }
    
    return CMN_OK;
}


int 
parse_extension_sni(uint8_t *data, uint32_t size, char *out, uint32_t out_size)
{
    uint16_t name_len  = 0;
    uint16_t ext_type = 0;

    if (data == NULL || size == 0 || out == NULL)
        return CMN_ERROR;

    ext_type = ntohs(GET_UINT16(data, 0));
    if (ext_type != 0) {
        log_error("ext type is not sni name, %u", ext_type);
        return CMN_ERROR;
    }

    name_len = ntohs(GET_UINT16(data, 7));
    log_info("extension_data server_name name len: %u", name_len);

    memcpy(out, (char *)data+9, MIN(name_len, out_size));
    log_info("extension_data server_name name: %s", out);

    return CMN_OK;
}

int 
parse_extension_message(uint8_t *data, uint32_t size)
{
    uint16_t msg_len = 0;
    uint16_t pos = 0;
    struct tls_extension ext;
    
    msg_len = size;
    while(msg_len > pos) {
        ext.type = ntohs(GET_UINT16(data, pos));
        pos += 2;
        ext.len = ntohs(GET_UINT16(data, pos));
        pos += 2;
        ext.raw = data + pos;
        pos += ext.len;
        
        // print ext information
        extension_message_info(&ext);
    }
    return CMN_OK;
}

int
parse_client_hello(uint8_t *msg, uint32_t size, struct tls_client_hello *client)
{
    uint32_t pos = 0;
    uint16_t msg_len = 0;
    uint16_t version = 0;

    if (size < MIN_CLIENT_HELLO_SIZE || msg == NULL) {
        return NET_INVALID_TLS_LENGTH;
    }

    // Check if the versions are valid
    version = ntohs(GET_UINT16(msg, pos));
    if (!is_tls_version(version)) {
        return NET_INVALID_VERSION;
    }

    client->version = version;
    pos += 2;

    // The struct tls_random structure    
    client->random.time = (msg[pos] << 24) + (msg[pos + 1] << 16) + (msg[pos + 2] << 8) + msg[pos + 3];
    pos += 4;
    memcpy(client->random.random_data, msg + pos, TLS_HELLO_RANDOM_SIZE);
    pos += TLS_HELLO_RANDOM_SIZE;

    // The struct tls_session_id structure
    client->session_id.len = msg[pos++];
    if (client->session_id.len > 0) {
        if (size < client->session_id.len + TLS_HELLO_RANDOM_SIZE + 4 + 2) {
            return NET_INVALID_TLS_LENGTH;
        }
        
        client->session_id.session_data = msg + pos;
        pos += client->session_id.len;
    }

    // The CipherSuitesStructure
    client->collection.len = ntohs(GET_UINT16(msg, pos));
    pos += 2;
    if (client->collection.len > 0) {
        if (size < pos + client->collection.len) {
            return NET_INVALID_TLS_LENGTH;
        }

        client->collection.cipher_suite_data = msg + pos;
        pos += client->collection.len;
    }

    // struct tls_compresion_method 2 bytes and Extensions 1 at least
    if (size < pos + 3) {
        return NET_INVALID_TLS_LENGTH;
    }

    // The CompresionMethodStructure
    client->method.len = msg[pos++];
    if (client->method.len != 1) {
        log_error("%x", client->method.len);
        return NET_INVALID_TLS_LENGTH;
    }

    client->method.method = msg[pos++];
    
    if (size > pos) {
        msg_len = ntohs(GET_UINT16(msg, pos));
        if (msg_len == 0) {
            log_info("extension_data len error, %u, %d, %u", size, pos, msg_len);
            return NET_INVALID_TLS_LENGTH;
        }
        pos += 2;
        client->is_extension = 1;
        client->extension_len = msg_len;
        client->extension_data = msg + pos;
    }

    return 0;
}


void
client_hello_message_info(struct tls_client_hello *msg)
{
    uint16_t i = 0;
    time_t raw_time = 0;
    struct tm *timeinfo = NULL;
    char buf[25] = {0};

    log_info("Details of struct tls_client_hello:");
    log_info("TLS Version: %s", tls_version_string(msg->version));

    // Time in human-readable format
    raw_time = (time_t) msg->random.time;
    timeinfo = localtime(&raw_time);

    strftime(buf, 25, "Timestamp: %c.", timeinfo);
    log_info("%s", buf);

    log_info("struct tls_random data: ");

    loga_hexdump(msg->random.random_data, TLS_HELLO_RANDOM_SIZE, "struct tls_random data");
    loga_hexdump(msg->session_id.session_data, msg->session_id.len, "struct tls_session_id data");
    loga_hexdump(msg->collection.cipher_suite_data, msg->collection.len, "choosen cipher suites");

    log_info("Compresion method: %d", msg->method.method);
    log_info("Has extension_data: %s", msg->is_extension ? "true" : "false");
    if (msg->extension_len > 0) {
        loga_hexdump(msg->extension_data, msg->extension_len, "raw extension_data data");
        parse_extension_message(msg->extension_data, msg->extension_len);
        char out[256] = {0};
        parse_extension_sni(msg->extension_data, msg->extension_len, out, 256);
        log_info("sni name is[%s]", out);
    }
}


int
parse_server_hello(uint8_t *msg, uint32_t size, struct tls_server_hello *server)
{
    uint32_t pos     = 0;
    uint16_t version = 0;
    uint16_t msg_len = 0;

    if (size < MIN_SERVER_HELLO_SIZE || msg == NULL || server == NULL) {
        return NET_INVALID_TLS_LENGTH;
    }

    // Check if the versions are valid
    version = ntohs(GET_UINT16(msg, pos));
    if (!is_tls_version(version)) {
        return NET_INVALID_VERSION;
    }

    server->version = version;
    pos += 2;

    // The struct tls_random structure    
    server->random.time = (msg[pos] << 24) + (msg[pos + 1] << 16) + (msg[pos + 2] << 8) + msg[pos + 3];
    pos += 4;
    memcpy(server->random.random_data, msg + pos, TLS_HELLO_RANDOM_SIZE);
    pos += TLS_HELLO_RANDOM_SIZE;

    // The struct tls_session_id structure
    server->session_id.len = msg[pos++];
    if (server->session_id.len > 0) {
        if (size < server->session_id.len + TLS_HELLO_RANDOM_SIZE + 4 + 2) {
            return NET_INVALID_TLS_LENGTH;
        }
        
        server->session_id.session_data = msg + pos;
        pos += server->session_id.len;
    }

    // The choosen cipher suite
    server->cipherSuite[0] = msg[pos++];
    server->cipherSuite[1] = msg[pos++];

    // struct tls_compresion_method needs to be present
    if (size < pos + 1) {
        return NET_INVALID_TLS_LENGTH;
    }

    // The CompresionMethodStructure
    server->method = msg[pos++];
   
    if (size > pos) {
        msg_len = ntohs(GET_UINT16(msg, pos));
        if (msg_len == 0) {
            log_info("extension_data len error, %u, %d, %u", size, pos, msg_len);
            // return NET_INVALID_TLS_LENGTH;
        }
        pos += 2;

        server->is_extension = 1; 
        server->extension_len = msg_len;
        server->extension_data = msg + pos;
    }
    return CMN_OK;
}

void
server_hello_message_info(struct tls_server_hello *msg)
{
    int    i = 0;
    time_t raw_time = 0;
    struct tm *timeinfo = NULL;

    log_info("Details of struct tls_server_hello:");
    log_info("TLS Version: %s", tls_version_string(msg->version));

    // Time in human-readable format
    raw_time = (time_t) msg->random.time;
    timeinfo = localtime(&raw_time);
    log_info ("Timestamp: %s", asctime(timeinfo));

    loga_hexdump(msg->random.random_data, TLS_HELLO_RANDOM_SIZE, "struct tls_random data");
    loga_hexdump(msg->session_id.session_data, msg->session_id.len, "struct tls_session_id");

    log_info("Choosen cipher suite: 0x");
    log_info("%x", msg->cipherSuite[0]); 
    log_info("%x", msg->cipherSuite[1]);

    log_info("Compresion method: %d", msg->method);
    
    if (msg->is_extension) {
        log_info("Has extension_data: true");
        loga_hexdump(msg->extension_data, msg->extension_len, "raw extension_data data");
    } else {
        log_info("Has extension_data: false");
    }
}

int
parse_certificate(uint8_t *msg, uint32_t size)
{
    // The Certificate msg contains only a chain of certificates. 
    // The only thing to do is to verify, that the chain is not empty 
    // as we are not able to (and not supposed to) say anything about the data.
    if (size == 0) {
        return NET_INVALID_TLS_LENGTH;
    }

    log_info("The certificate chain provided is %d bytes long.", size);
    
    return 0;
}


int parse_server_key_exchange(uint8_t *msg, uint32_t size)
{
    // The actual algorithm and other stuff like digital signatures of params
    // are not in scope as their presence is determined by extension_data in hello messages
    // and the used certificate (which are both ignored).
    log_info("The key exchange parameters provided are %d bytes long.", size);


    return 0;
}

int
parse_server_hello_done(uint8_t *msg, uint32_t size)
{
    // The ServerHelloDone is empty. Just check if thats true.
    if (size != 0) {
        return NET_INVALID_TLS_LENGTH;
    }

    return 0;
}

int
parse_client_key_exchange(uint8_t *msg, uint32_t size)
{
    // We only check until we get to the exchange parameters, whose
    // type is specified similiary as server key exchange parameters
    // in earlier messages.
    uint8_t len = msg[0];

    if (len != size - 1) {
        return INVALID_FILE_LENGTH_FOR_CLIENT_KEY_EXCHANGE;
    }

    log_info("The key exchange parameters provided are %d bytes long.", size);

    return 0;
}


int
setup_tls_handshake_message(uint8_t *data, uint32_t size, struct tls_handshake_message *msg)
{
    uint32_t pos = 0;
    uint16_t version = 0;
    uint32_t body_len = 0;
    
    // Record layer
    if (size <= MIN_RECORD_LAYER_SIZE || data == NULL) {
        return NET_INVALID_TLS_LENGTH;
    }

    msg->tls_type = data[pos];
    // Only handshake messages of TLS version 1.0 - 1.2 are allowed
    if (msg->tls_type != TLS_HANDSHAKE) {
        return CMN_ERROR;
    }

    pos++;
    version = ntohs(GET_UINT16(data, pos));
    if (!is_tls_version(version)) {
        log_error("invalid tls version: %2x", version);
        return NET_INVALID_VERSION;
    }

    // Values are safe to assign to our structure
    msg->version = version;
    pos += 2;

    // Convert data[3] and data[4] to uint16_t number
    msg->len = ntohs(GET_UINT16(data, pos));
    pos += 2;

    // Check if the sizes are correct (record protocol headers + len == file size)
    // if (msg->len + pos != size) {
    //     log_error("invalid tls size: %u, %u, %u", msg->len, pos, size);
    //     // return NET_INVALID_TLS_LENGTH;
    // }

    // Does not need to check this value as the parser will not continue if this is not a supported handshake msg type
    msg->hs_type = data[pos++];

    // Convert data[6], data[7] and data[8] into uint24_t number
    // It's actually uint24_t but thats not defined
    body_len = (0x00 << 24) + (data[pos] << 16) + (data[pos + 1] << 8) + data[pos + 2];
    msg->body_len = body_len;
    pos += 3;

    // Check if the sizes are correct (len value == body_len value + HandshakeType (1 byte) + body_len (3 bytes))
    if (msg->len != msg->body_len + 4) {
        log_error("invalid tls body size: %u, %u ---%u", msg->len, msg->body_len, body_len);
        // return NET_INVALID_TLS_LENGTH;
    }
    
    msg->body = (uint8_t *)data + pos;
    return 0;
}

void
tls_handshake_message_info(struct tls_handshake_message *msg)
{
    log_info("Identified the following TLS msg:");
    log_info("TLS Version: %s", tls_version_string(msg->version));
    log_info("Protocol type: %d", msg->tls_type);
    log_info("Fragment len: %d", msg->len);
    log_info("Handshake msg type: %d", msg->hs_type);
}

int
parse_tls_message(uint8_t *data, uint32_t data_size)
{
    uint8_t *payload = data;
    uint16_t version = 0;
    struct tls_handshake_message hs;
    struct tls_client_hello client;
    struct tls_server_hello server;

    if (!data || data_size <= 0) {
        return CMN_ERROR;
    }

    switch (GET_UINT8(payload, 0))
    {
    case TLS_CHANGE_CIPHER_SPEC:
        break;
    case TLS_ALERT:
        break;
    case TLS_HANDSHAKE:
        memset(&hs, 0x00, sizeof(struct tls_handshake_message));
        if (setup_tls_handshake_message(data, data_size, &hs) < 0)
            return CMN_ERROR;

        tls_handshake_message_info(&hs);
        
        if (!is_tls_version(hs.version)) {
            log_error("invalid tls version, %u", version);
            return CMN_ERROR;
        }

        // type
        if(hs.hs_type == TLS_CLIENT_HELLO) {
            log_info("         Handshake Type: client hello");
            memset(&client, 0x00, sizeof(struct tls_client_hello));

            if (parse_client_hello(hs.body, hs.body_len, &client) != CMN_OK) {
                log_error("parse client hello error");
                return CMN_ERROR;
            }
            client_hello_message_info(&client);

        } else if(hs.hs_type == TLS_SERVER_HELLO) {
            log_info("         Handshake Type: server hello");

            memset(&server, 0x00, sizeof(struct tls_server_hello));

            if (parse_server_hello(hs.body, hs.body_len, &server) != CMN_OK) {
                log_error("parse server hello error");
                return CMN_ERROR;
            }
            server_hello_message_info(&server);
            
        } else if(hs.hs_type == TLS_NEW_SESSION_TICKET) {
            log_info("         Handshake Type: session ticket");
        } else if(hs.hs_type == TLS_CERTIFICATE) {
            log_info("         Handshake Type: certificate");
        } else if(hs.hs_type == TLS_SERVER_KEY_EXCHANGE) {
            log_info("         Handshake Type: server key exchange");
        } else if(hs.hs_type == TLS_CERTIFICATE_REQUEST) {
            log_info("         Handshake Type: certificate request");
        } else if(hs.hs_type == TLS_SERVER_DONE) {
            log_info("         Handshake Type: server done");   
        } else if(hs.hs_type == TLS_CERTIFICATE_VERIFY) {
            log_info("         Handshake Type: certificate verify");
        } else if(hs.hs_type == TLS_CLIENT_KEY_EXCHANGE) {
            log_info("         Handshake Type: client key exchange");
        } else if(hs.hs_type == TLS_FINISHED) {
            log_info("         Handshake Type: finish");
        } else {
            log_error("unknown TLS handshake msg type, %u", hs.hs_type);
        }
        break;
    case TLS_APPLICATION_DATA:
        break;
    }

    return CMN_OK;
}


int
parse_tls_sni_name(uint8_t *data, uint32_t data_size, uint8_t *out, uint32_t out_size)
{
    int     ret  = 0;
    uint8_t *payload = data;
    uint16_t version = 0;
    struct tls_handshake_message hs;
    struct tls_client_hello client;
    struct tls_server_hello server;

    if (!data || data_size <= 0) {
        return CMN_ERROR;
    }

    switch (GET_UINT8(payload, 0))
    {
    case TLS_HANDSHAKE:
        memset(&hs, 0x00, sizeof(struct tls_handshake_message));
        ret = setup_tls_handshake_message(data, data_size, &hs); 
        if (ret != CMN_OK)
            return ret;
        
        if (!is_tls_version(hs.version)) {
            log_error("invalid tls version, %u", version);
            return CMN_ERROR;
        }

        // type
        if(hs.hs_type == TLS_CLIENT_HELLO) {
            log_info("         Handshake Type: client hello");
            memset(&client, 0x00, sizeof(struct tls_client_hello));

            ret = parse_client_hello(hs.body, hs.body_len, &client);
            if (ret != CMN_OK) {
                log_error("parse client hello error, %d", ret);
                return ret;
            }

            ret = parse_extension_sni(client.extension_data, client.extension_len, (char *)out, out_size);
            if (ret != CMN_OK) {
                log_error("parse extension sni error, %d", ret);
                return ret;
            }
        } else {
            ret = NET_TLS_NO_CLIENTHELLO;
        }
        break;
    default:
        ret = NET_TLS_NO_HANDSHAKE;
        break;
    }

    return ret;
}

