#include "net_ssl.h"


struct ssl_handshake_type handshake_type[] = {
    { CLIENT_HELLO,  "ClientHello"},
    { SERVER_HELLO,  "ServerHello"},
    { SERVER_CERT,  "Certificate"},
    { NEW_SESSION_TICKET,  "New Session Ticket"},
    { SERVER_KEY_EXCHANGE,  "Server Key Exchange"},
    { SERVER_HELLO_DONE,  "Server Hello Done"},
    { CLIENT_KEY_EXCHANGE, "Client Key Exchange"},
    { FINISHED, "Finished"},
};

struct ssl_cipher ciphersuites[] = {
    { 0x00, 0x0a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
    { 0x00, 0x2f, "TLS_RSA_WITH_AES_128_CBC_SHA"},
    { 0x00, 0x35, "TLS_RSA_WITH_AES_256_CBC_SHA"},
    { 0x00, 0x9c, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
    { 0x00, 0x9d, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
    { 0xc0, 0x13, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
    { 0xc0, 0x14, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
    { 0xc0, 0x2b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
    { 0xc0, 0x2c, "TLS_ECHDE_ECDSA_WITH_AES_256_GCM_SHA384"},
    { 0xc0, 0x2f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
    { 0xc0, 0x30, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
};

uint8_t *readHSType(uint8_t type)
{
        int index=0, hs_type_size;
        hs_type_size = sizeof(handshake_type)/sizeof(handshake_type[0]);
        for (index=0; index<hs_type_size; index++) {
                if (handshake_type[index].type == type) {
                        break;
                }
        }

        return handshake_type[index].str;
}

int c2i(char ch)
{
    if(isdigit(ch))
        return ch - 48;

    if( ch < 'A' || (ch > 'F' && ch < 'a') || ch > 'z' )
        return -1;

    if(isalpha(ch))
        return isupper(ch) ? ch - 55 : ch - 87;

    return -1;
}

int hex2dec(char *hex)
{
    int len;
    int num = 0;
    int temp;
    int bits;
    int i;

    len = strlen(hex);

    for (i=0, temp=0; i<len; i++, temp=0)
    {
        temp = c2i( *(hex + i) );
        bits = (len - i - 1) * 4;
        temp = temp << bits;

        num = num | temp;
    }

    return num;
}

int processType(uint8_t type, int length)
{
    printf("Content Type: ");
    switch(type) {
        case CT_CHANGE_CIPHER_SPEC:
            printf("Change cipher spec");
            break;
        case CT_ALERT:
            printf("Alert");
            break;
        case CT_HANDSHAKE:
            printf("Handshake");
            break;
        case CT_APPLICATION:
            printf("Application");
            break;
        default:
            printf("failed to read ssl type");
            break;
    }

    printf(" (%d)\r\n", type);
    return VERSION;
}

int processVersion(uint8_t *version, int length)
{
    readVersion(version, length);
    return LENGTH;
}

int processLength(struct ssl_header *sslheader, int len)
{
    int _length = 0, ret = FINISH;

    _length = calLength(sslheader->length, len);
    printf("Length: %d\r\n", _length);
    switch(sslheader->type) {
    case CT_HANDSHAKE:
        ret = HS_TYPE;
    }
    if (!strcmp(readHSType(sslheader->hs_type), "")) {
        ret = FINISH;
    }

    return ret;
}

int processHStype(uint8_t type, int len)
{
    printf("Handshake Type: ");
    printf("%s (%d)\r\n", readHSType(type), type);
    return HS_LENGTH;
}

int processHSlength(struct ssl_header *sslheader, int len)
{
    int _length = 0, ret = HS_VERSION;

    int i=0;
    _length = calLength(sslheader->hs_length, len);
    printf("Length: %d\r\n", _length);

    switch(sslheader->hs_type) {
    case CLIENT_HELLO:
    case SERVER_HELLO:
        ret = HS_VERSION;
        break;
    case SERVER_CERT:
        ret = HS_CERT_LENGTH;
        break;
    default:
        ret = FINISH;
        break;
    }

    return ret;
}

int processHSversion(uint8_t *version, int length)
{
    readVersion(version, length);
    return HS_RANDOM;
}

int processHSrandom(uint8_t *random, int len)
{
    int index=0;

    printf("Random: ");
    for(index=0; index<len; index++) {
        printf("%02X", random[index]);
    }
    printf("\r\n");

    return HS_SESSION_ID;
}

int processHSsessionID(uint8_t **hex, int len)
{
    int index=0;

    printf("Session ID Length: ");
    if (*hex[0] == 0) {
        puts("0");
        *hex+=1;
        goto done;
    }
    for (index=0; index<len; index) {
        printf("%02X", *hex[index]);
    }
    *hex+=32;
done:
    return HS_CIPHER_SUITES;
}

uint8_t *cipher2str(uint8_t *cipher, int len)
{
    int index=0, suites_size = 0;

    suites_size = sizeof(ciphersuites)/sizeof(ciphersuites[0]);
    for (index=0; index<suites_size; index++) {
        if (cipher[0] == ciphersuites[index].cipher[0] &&
                cipher[1] == ciphersuites[index].cipher[1]) {
            break;
        }
    }
    return ciphersuites[index].str;
}

int processHSciphersuites(struct ssl_header *sslheader, uint8_t **hex, int len)
{
    int _length=0, index=0, ret = FINISH;

    if (sslheader->type == CT_HANDSHAKE) {
        switch(sslheader->hs_type) {
        case CLIENT_HELLO:
            _length = calLength(*hex, len);
            printf("Cipher Suites Length: %d\r\n", _length);
            *hex+=len;
            break;
        case SERVER_HELLO:
            _length = 1;
            break;
        }
    }
    for (index=0; index<_length; index++, *hex+=2) {
        printf("Cipher Suites: ");
        printf("%s\r\n", cipher2str(*hex, 2));
    }

    return ret;
}

int processHScertLength(uint8_t **hex, int len)
{
    int _length = 0;
    _length = calLength(*hex, len);
    printf("Certificates Length: %d\r\n", _length);
    *hex+=len;

    return FINISH;
}

int main(int argc, char **argv)
{
    FILE *fp = NULL;
    char input[STR_SIZE];
    int c=0, status = TYPE;
    long size = 0, count=0;
    uint8_t *hex = NULL, *pHex = NULL;
    int index=0;
    struct ssl_header *sslheader;


    if (argc < 2) {
        printf("Wrong parameter\r\n");
        return 1;
    }
    strncpy(input, argv[1], sizeof(input));
    if ((fp = fopen(input, "r")) == NULL) {
        fprintf(stderr, "%s: %s\r\n", input, strerror(errno));
    }
    count = getFileSize(fp);

    hex = (uint8_t*)malloc(sizeof(uint8_t)*count);
    for (index=0; index<count; index++) {
        uint8_t text[3];
        uint8_t dec;
        readHex(text, index, 1, fp);
        dec = hex2dec(text);
        hex[index] = dec;
    }
    pHex = hex;
    sslheader = (struct ssl_header *)hex;
    while (status != FINISH) {
        switch (status) {
            case TYPE:
                status = processType(sslheader->type, 1);
                pHex+=sizeof(sslheader->type);
                break;
            case VERSION:
                status = processVersion(sslheader->version, 2);
                pHex+=sizeof(sslheader->version);
                break;
            case LENGTH:
                status = processLength(sslheader, 2);
                pHex+=sizeof(sslheader->length);
                break;
            case HS_TYPE:
                status = processHStype(sslheader->hs_type, 1);
                pHex+=sizeof(sslheader->hs_type);
                break;
            case HS_LENGTH:
                status = processHSlength(sslheader, 3);
                pHex+=sizeof(sslheader->hs_length);
                break;
            case HS_VERSION:
                status = processHSversion(sslheader->hs_version, 2);
                pHex+=sizeof(sslheader->hs_version);
                break;
            case HS_RANDOM:
                status = processHSrandom(sslheader->hs_random, 32);
                pHex+=sizeof(sslheader->hs_random);
                break;
            case HS_SESSION_ID:
                status = processHSsessionID(&pHex, 32);
                break;
            case HS_CIPHER_SUITES:
                status = processHSciphersuites(sslheader, &pHex, 2);
                break;
            case HS_CERT_LENGTH:
                status = processHScertLength(&pHex, 3);
                break;
            default:
                printf("Unsupported status\r\n");
                status = FINISH;
                break;
        }
    }
    printf("Data: ");
    for (index=pHex-hex; index<count; index++) {
        printf("%02X ", hex[index]);
    }
    printf("\r\n");
done:
    fclose(fp);
    free(hex);
    return 0;
}
