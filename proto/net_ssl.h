#ifndef __NET_SSL_H
#define __NET_SSL_H

#include "cmn.h"


#define CT_CHANGE_CIPHER_SPEC 0x14
#define CT_ALERT              0x15
#define CT_HANDSHAKE          0x16
#define CT_APPLICATION        0x17
#define STR_SIZE              64

struct ssl_header
{
    uint8_t type;
    uint8_t version[2];
    uint8_t length[2];
    uint8_t hs_type;
    uint8_t hs_length[3];
    uint8_t hs_version[2];
    uint8_t hs_random[32];
};

struct ssl_cipher
{
    uint8_t cipher[2];
    uint8_t str[STR_SIZE];
};

struct ssl_handshake_type{
    uint8_t type;
    uint8_t str[STR_SIZE];
};

enum
{
    CLIENT_HELLO = 0x1,
    SERVER_HELLO = 0x2,
    NEW_SESSION_TICKET = 0x4,
    SERVER_CERT = 0xB,
    SERVER_KEY_EXCHANGE = 0xC,
    SERVER_HELLO_DONE = 0xE,
    CLIENT_KEY_EXCHANGE = 0x10,
    FINISHED = 0x14,
};

enum HandShake_t
{
    TYPE,
    VERSION,
    LENGTH,
    HS_TYPE,
    HS_LENGTH,
    HS_VERSION,
    HS_RANDOM,
    HS_SESSION_ID,
    HS_CIPHER_SUITES,
    HS_CERT_LENGTH,
    FINISH,
};

enum SSLRecordType
{
    /** Change-cipher-spec message */
    SSL_CHANGE_CIPHER_SPEC = 20,
    /** SSL alert message */
    SSL_ALERT              = 21,
    /** SSL handshake message */
    SSL_HANDSHAKE          = 22,
    /** SSL data message */
    SSL_APPLICATION_DATA   = 23
};

enum SSLVersion
{
    /** SSLv2.0 */
    SSL2   = 0x0200,
    /** SSLv3.0 */
    SSL3   = 0x0300,
    /** TLSv1.0 */
    TLS1_0 = 0x0301,
    /** TLSv1.1 */
    TLS1_1 = 0x0302,
    /** TLSv1.2 */
    TLS1_2 = 0x0303
};

static inline char *ssl_version_string(SSLVersion ver)
{
    switch (ver)
    {
    case SSL2:
        return "SSLv2";
    case SSL3:
        return "SSLv3";
    case TLS1_0:
        return "TLSv1.0";
    case TLS1_1:
        return "TLSv1.1";
    case TLS1_2:
        return "TLSv1.2";
    default:
        return "SSL/TLS unknown";
    }
}

bool Is_SSL_Message(uint16_t srcPort, uint16_t dstPort, uint8_t* data, size_t dataLen, bool ignorePorts)
{
    // check the port map first
    if (!ignorePorts && !isSSLPort(srcPort) && !isSSLPort(dstPort))
        return false;

    if (dataLen < sizeof(struct ssl_tls_record_layer))
        return false;

    struct ssl_tls_record_layer* recordLayer = (struct ssl_tls_record_layer*)data;

    // there is no SSL message with length 0
    if (recordLayer->length == 0)
        return false;

    if (recordLayer->recordType < 20 || recordLayer->recordType > 23)
        return false;

    uint16_t recordVersion = be16toh(recordLayer->recordVersion);

    if (recordVersion != SSL3 &&
            recordVersion != TLS1_0 &&
            recordVersion != TLS1_1 &&
            recordVersion != TLS1_2)
        return false;

    return true;
}

#endif
