#include "net_http.h"

char *array_method_string[9] = {
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "DELETE",
        "TRACE",
        "OPTIONS",
        "CONNECT",
        "PATCH"
};

char *array_version_string[3] = {
        "0.9",
        "1.0",
        "1.1"
};

char *array_status_code_msg[80] = {
        "Continue",
        "Switching Protocols",
        "Processing",
        "OK",
        "Created",
        "Accepted",
        "Non-Authoritative Information",
        "No Content",
        "Reset Content",
        "Partial Content",
        "Multi-Status",
        "Already Reported",
        "IM Used",
        "Multiple Choices",
        "Moved Permanently",
        "Found",
        "See Other",
        "Not Modified",
        "Use Proxy",
        "Switch Proxy",
        "Temporary Redirect",
        "Permanent Redirect",
        "Bad Request",
        "Unauthorized",
        "Payment Required",
        "Forbidden",
        "Not Found",
        "Method Not Allowed",
        "Not Acceptable",
        "Proxy Authentication Required",
        "Request Timeout",
        "Conflict",
        "Gone",
        "Length Required",
        "Precondition Failed",
        "Request Entity Too Large",
        "Request-URI Too Long",
        "Unsupported Media Type",
        "Requested Range Not Satisfiable",
        "Expectation Failed",
        "I'm a teapot",
        "Authentication Timeout",
        "Method Failure",
        "Unprocessable Entity",
        "Locked",
        "Failed Dependency",
        "Upgrade Required",
        "Precondition Required",
        "Too Many Requests",
        "Request Header Fields Too Large",
        "Login Timeout",
        "No Response",
        "Retry With",
        "Blocked by Windows Parental Controls",
        "Unavailable For Legal Reasons",
        "Request Header Too Large",
        "Cert Error",
        "No Cert",
        "HTTP to HTTPS",
        "Token expired/invalid",
        "Client Closed Request",
        "Internal Server Error",
        "Not Implemented",
        "Bad Gateway",
        "Service Unavailable",
        "Gateway Timeout",
        "HTTP Version Not Supported",
        "Variant Also Negotiates",
        "Insufficient Storage",
        "Loop Detected",
        "Bandwidth Limit Exceeded",
        "Not Extended",
        "Network Authentication Required",
        "Origin Error",
        "Web server is down",
        "Connection timed out",
        "Proxy Declined Request",
        "A timeout occurred",
        "Network read timeout error",
        "Network connect timeout error"
};


int array_status_code[80] = {
        100,
        101,
        102,
        200,
        201,
        202,
        203,
        204,
        205,
        206,
        207,
        208,
        226,
        300,
        301,
        302,
        303,
        304,
        305,
        306,
        307,
        308,
        400,
        401,
        402,
        403,
        404,
        405,
        406,
        407,
        408,
        409,
        410,
        411,
        412,
        413,
        414,
        415,
        416,
        417,
        418,
        419,
        420,
        422,
        423,
        424,
        426,
        428,
        429,
        431,
        440,
        444,
        449,
        450,
        451,
        494,
        495,
        496,
        497,
        498,
        499,
        500,
        501,
        502,
        503,
        504,
        505,
        506,
        507,
        508,
        509,
        510,
        511,
        520,
        521,
        522,
        523,
        524,
        598,
        599
};

int http_parse_request_method(char *data, int data_size)
{
    if (data_size < 4) {
        return HTTP_METHOD_UNKNOWN;
    }

    switch (data[0])
    {
    case 'G':
        if (data[1] == 'E' && data[2] == 'T' && data[3] == ' ')
            return HTTP_GET;
        else
            return HTTP_METHOD_UNKNOWN;
        break;

    case 'D':
        if (data_size < 7)
            return HTTP_METHOD_UNKNOWN;
        else if (data[1] == 'E' && data[2] == 'L' && data[3] == 'E' && data[4] == 'T' && data[5] == 'E' && data[6] == ' ')
            return HTTP_DELETE;
        else
            return HTTP_METHOD_UNKNOWN;
        break;

    case 'C':
        if (data_size < 8)
            return HTTP_METHOD_UNKNOWN;
        else if (data[1] == 'O' && data[2] == 'N' && data[3] == 'N' && data[4] == 'E' && data[5] == 'C' && data[6] == 'T' && data[7] == ' ')
            return HTTP_CONNECT;
        else
            return HTTP_METHOD_UNKNOWN;
        break;

    case 'T':
        if (data_size < 6)
            return HTTP_METHOD_UNKNOWN;
        else if (data[1] == 'R' && data[2] == 'A' && data[3] == 'C' && data[4] == 'E' && data[5] == ' ')
            return HTTP_TRACE;
        else
            return HTTP_METHOD_UNKNOWN;
        break;


    case 'H':
        if (data_size < 5)
            return HTTP_METHOD_UNKNOWN;
        else if (data[1] == 'E' && data[2] == 'A' && data[3] == 'D' && data[4] == ' ')
            return HTTP_HEAD;
        else
            return HTTP_METHOD_UNKNOWN;
        break;

    case 'O':
        if (data_size < 8)
            return HTTP_METHOD_UNKNOWN;
        else if (data[1] == 'P' && data[2] == 'T' && data[3] == 'I' && data[4] == 'O' && data[5] == 'N' && data[6] == 'S' && data[7] == ' ')
            return HTTP_OPTIONS;
        else
            return HTTP_METHOD_UNKNOWN;
        break;

    case 'P':
        switch (data[1])
        {
        case 'U':
            if (data[2] == 'T' && data[3] == ' ')
                return HTTP_PUT;
            else
                return HTTP_METHOD_UNKNOWN;
            break;

        case 'O':
            if (data_size < 5)
                return HTTP_METHOD_UNKNOWN;
            else if (data[2] == 'S' && data[3] == 'T' && data[4] == ' ')
                return HTTP_POST;
            else
                return HTTP_METHOD_UNKNOWN;
            break;

        case 'A':
            if (data_size < 6)
                return HTTP_METHOD_UNKNOWN;
            else if (data[2] == 'T' && data[3] == 'C' && data[4] == 'H' && data[5] == ' ')
                return HTTP_PATCH;
            else
                return HTTP_METHOD_UNKNOWN;
            break;

        default:
            return HTTP_METHOD_UNKNOWN;
        }
        break;

    default:
        return HTTP_METHOD_UNKNOWN;
    }
}

static inline int http_parse_request_version(uint8_t *line, int len)
{
    int version = 0;
    int pos_len = 0;
    char *data = (char*)(line);
    char *position = strstr(data, " HTTP/");

    if (position == NULL){
        version = VERSION_UNKNOWN;
        pos_len = -1;
        return version;
    }

    // verify packet doesn't end before the version, meaning still left place for " HTTP/x.y" (9 chars)
    if ((uint16_t)(position + 9 - (char*)line) > len) {
        version = VERSION_UNKNOWN;
        pos_len = -1;
        return version;
    }

    //skip " HTTP/" (6 chars)
    position += 6;
    switch (position[0])
    {
    case '0':
        if (position[1] == '.' && position[2] == '9')
            version = VERSION_ZERO_DOT_NINE;
        else
            version = VERSION_UNKNOWN;
        break;

    case '1':
        if (position[1] == '.' && position[2] == '0')
            version = VERSION_ONE_DOT_ZERO;
        else if (position[1] == '.' && position[2] == '1')
            version = VERSION_ONE_DOT_ONE;
        else
            version = VERSION_UNKNOWN;
        break;

    default:
        version = VERSION_UNKNOWN;
    }
    return version;
}

static int http_parse_request_uri(uint8_t *line, int offset, char *out, int out_size)
{
    char *data = (char*)(line + offset);
    char *position = data;

    if (*position != '/') {
        return NET_EFORMAT_HTTP;
    }
    position ++;

    while(*position != ' ' && *position != 0x00) {
        position ++;
    }

    if (position - data > 0) {
        memcpy(out, data, MIN(out_size, (position - data)));
        return CMN_OK;
    }

    return CMN_OK;
}

static inline int http_response_status_code_int(int index)
{
    return array_status_code[index];
}

static inline char *http_response_status_code_string(int index)
{
    if (index < 0 || index >= 80) {
        return "";
    }

    return array_status_code_msg[index];
}

static inline int http_parse_response_version(char* data, int data_size)
{
    char *offset = data;
    char *position = data;

    if (data_size < 8) {   // "HTTP/x.y"
        log_error("HTTP response length < 8, cannot identify version");
        return VERSION_UNKNOWN;
    }

    if (*offset != 'H' || *++offset != 'T' || *++offset != 'T' || *++offset != 'P' || *++offset != '/') {
        log_error("HTTP response does not begin with 'HTTP/'");
        return VERSION_UNKNOWN;
    }

    position = offset + 5;
    switch (position[0]) {
    case '0':
        if (position[1] == '.' && position[2] == '9')
            return VERSION_ZERO_DOT_NINE;
        else
            return VERSION_UNKNOWN;
        break;

    case '1':
        if (position[1] == '.' && position[2] == '0')
            return VERSION_ONE_DOT_ZERO;
        else if (position[1] == '.' && position[2] == '1')
            return VERSION_ONE_DOT_ONE;
        else
            return VERSION_UNKNOWN;
        break;
    }
    return VERSION_UNKNOWN;
}



static inline int http_response_validate_status_code(char* data, int data_size, int status_code)
{
    if (data[0] != ' ')
        return HTTPSTATUSCODEUNKNOWN;

    return status_code;
}

int http_response_parse_status_code(char* data, int data_size, bool is_check_version)
{
    char* code_data = data + 9;
    int code_len = data_size - 9;


    if (is_check_version) {
        if (http_parse_response_version(data, data_size) == VERSION_UNKNOWN)
            return HTTPSTATUSCODEUNKNOWN;
    }

    // minimum data should be 12B long: "HTTP/x.y XXX"
    if (data_size < 12)
        return HTTPSTATUSCODEUNKNOWN;

    switch (code_data[0])
    {
    case '1':
        switch (code_data[1])
        {
        case '0':
            switch (code_data[2])
            {
            case '0':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP100CONTINUE);
            case '1':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP101SWITCHINGPROTOCOLS);
            case '2':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP102PROCESSING);
            default:
                return HTTPSTATUSCODEUNKNOWN;
            };

            break;

        default:
            return HTTPSTATUSCODEUNKNOWN;
        };

        break;
    case '2':
        switch (code_data[1])
        {
        case '0':
            switch (code_data[2])
            {
            case '0':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP200OK);
            case '1':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP201CREATED);
            case '2':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP202ACCEPTED);
            case '3':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP203NONAUTHORITATIVEINFORMATION);
            case '4':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP204NOCONTENT);
            case '5':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP205RESETCONTENT);
            case '6':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP206PARTIALCONTENT);
            case '7':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP207MULTISTATUS);
            case '8':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP208ALREADYREPORTED);
            default:
                return HTTPSTATUSCODEUNKNOWN;

            };

            break;
        case '2':
            switch (code_data[2])
            {
            case '6':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP226IMUSED);
            default:
                return HTTPSTATUSCODEUNKNOWN;
            };

            break;

        default:
            return HTTPSTATUSCODEUNKNOWN;

        };

        break;

    case '3':
        switch (code_data[1])
        {
        case '0':
            switch (code_data[2])
            {
            case '0':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP300MULTIPLECHOICES);
            case '1':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP301MOVEDPERMANENTLY);
            case '2':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP302);
            case '3':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP303SEEOTHER);
            case '4':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP304NOTMODIFIED);
            case '5':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP305USEPROXY);
            case '6':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP306SWITCHPROXY);
            case '7':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP307TEMPORARYREDIRECT);
            case '8':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP308PERMANENTREDIRECT);
            default:
                return HTTPSTATUSCODEUNKNOWN;

            };

            break;

        default:
            return HTTPSTATUSCODEUNKNOWN;
        };

        break;

    case '4':
        switch (code_data[1])
        {
        case '0':
            switch (code_data[2])
            {
            case '0':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP400BADREQUEST);
            case '1':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP401UNAUTHORIZED);
            case '2':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP402PAYMENTREQUIRED);
            case '3':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP403FORBIDDEN);
            case '4':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP404NOTFOUND);
            case '5':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP405METHODNOTALLOWED);
            case '6':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP406NOTACCEPTABLE);
            case '7':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP407PROXYAUTHENTICATIONREQUIRED);
            case '8':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP408REQUESTTIMEOUT);
            case '9':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP409CONFLICT);
            default:
                return HTTPSTATUSCODEUNKNOWN;

            };

            break;

        case '1':
            switch (code_data[2])
            {
            case '0':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP410GONE);
            case '1':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP411LENGTHREQUIRED);
            case '2':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP412PRECONDITIONFAILED);
            case '3':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP413REQUESTENTITYTOOLARGE);
            case '4':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP414REQUESTURITOOLONG);
            case '5':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP415UNSUPPORTEDMEDIATYPE);
            case '6':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP416REQUESTEDRANGENOTSATISFIABLE);
            case '7':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP417EXPECTATIONFAILED);
            case '8':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP418IMATEAPOT);
            case '9':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP419AUTHENTICATIONTIMEOUT);
            default:
                return HTTPSTATUSCODEUNKNOWN;

            };

            break;

        case '2':
            switch (code_data[2])
            {
            case '0':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP420);
            case '2':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP422UNPROCESSABLEENTITY);
            case '3':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP423LOCKED);
            case '4':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP424FAILEDDEPENDENCY);
            case '6':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP426UPGRADEREQUIRED);
            case '8':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP428PRECONDITIONREQUIRED);
            case '9':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP429TOOMANYREQUESTS);
            default:
                return HTTPSTATUSCODEUNKNOWN;

            };

            break;

        case '3':
            return http_response_validate_status_code(code_data+3, code_len-3, HTTP431REQUESTHEADERFIELDSTOOLARGE);

        case '4':
            switch (code_data[2])
            {
            case '0':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP440LOGINTIMEOUT);
            case '4':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP444NORESPONSE);
            case '9':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP449RETRYWITH);
            default:
                return HTTPSTATUSCODEUNKNOWN;
            };

            break;

        case '5':
            switch (code_data[2])
            {
            case '0':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP450BLOCKEDBYWINDOWSPARENTALCONTROLS);
            case '1':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP451);
            default:
                return HTTPSTATUSCODEUNKNOWN;
            };

            break;

        case '9':
            switch (code_data[2])
            {
            case '4':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP494REQUESTHEADERTOOLARGE);
            case '5':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP495CERTERROR);
            case '6':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP496NOCERT);
            case '7':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP497HTTPTOHTTPS);
            case '8':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP498TOKENEXPIREDINVALID);
            case '9':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP499);
            default:
                return HTTPSTATUSCODEUNKNOWN;
            };

            break;

        default:
            return HTTPSTATUSCODEUNKNOWN;
        };

        break;

    case '5':
        switch (code_data[1])
        {
        case '0':
            switch (code_data[2])
            {
            case '0':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP500INTERNALSERVERERROR);
            case '1':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP501NOTIMPLEMENTED);
            case '2':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP502BADGATEWAY);
            case '3':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP503SERVICEUNAVAILABLE);
            case '4':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP504GATEWAYTIMEOUT);
            case '5':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP505HTTPVERSIONNOTSUPPORTED);
            case '6':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP506VARIANTALSONEGOTIATES);
            case '7':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP507INSUFFICIENTSTORAGE);
            case '8':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP508LOOPDETECTED);
            case '9':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP509BANDWIDTHLIMITEXCEEDED);
            default:
                return HTTPSTATUSCODEUNKNOWN;

            };

            break;

        case '1':
            switch (code_data[2])
            {
            case '0':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP510NOTEXTENDED);
            case '1':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP511NETWORKAUTHENTICATIONREQUIRED);
            default:
                return HTTPSTATUSCODEUNKNOWN;
            };

            break;

        case '2':
            switch (code_data[2])
            {
            case '0':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP520ORIGINERROR);
            case '1':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP521WEBSERVERISDOWN);
            case '2':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP522CONNECTIONTIMEDOUT);
            case '3':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP523PROXYDECLINEDREQUEST);
            case '4':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP524ATIMEOUTOCCURRED);
            default:
                return HTTPSTATUSCODEUNKNOWN;
            };

            break;

        case '9':
            switch (code_data[2])
            {
            case '8':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP598NETWORKREADTIMEOUTERROR);
            case '9':
                return http_response_validate_status_code(code_data+3, code_len-3, HTTP599NETWORKCONNECTTIMEOUTERROR);
            default:
                return HTTPSTATUSCODEUNKNOWN;
            };

            break;

        default:
            return HTTPSTATUSCODEUNKNOWN;
        };

        break;

    default:
        return HTTPSTATUSCODEUNKNOWN;
    }

    return HTTPSTATUSCODEUNKNOWN;
}


int http_parse_request_first_line(char *data, int data_size)
{
    int method = 0;
    int version = 0;
    int offset = 0;
    int ret = 0;
    char *line = data;
    char uri[1024] = {0};
    char *end = NULL;

    method = http_parse_request_method(line, data_size);
    if (method == HTTP_METHOD_UNKNOWN) {
        log_error("couldn't parse HTTP request method, %d:%s", data_size, line);
        return NET_EFORMAT_HTTP;
    }

    offset = strlen(array_method_string[method]) + 1;
    ret = http_parse_request_uri((uint8_t *)line, offset, uri, sizeof(uri));
    if (ret != CMN_OK) {
        log_error("couldn't parse HTTP request uri, %d:%s", data_size, line);
        return NET_EFORMAT_HTTP;
    }

    version = http_parse_request_version((uint8_t *)line, data_size);
    if (version == VERSION_UNKNOWN) {
        log_error("couldn't parse HTTP request version, %d:%s", data_size, line);
        return NET_EFORMAT_HTTP;
    }


    if ((end = (char*)memchr((char*)(line + offset), '\n', data_size - (int)offset)) == NULL) {
        log_error("HTTP first line is not completed, %d:%s", data_size, line);
        return NET_EFORMAT_HTTP;
    }

    log_info("Method='%s'; HTTP version='%s'; URI='%s'",
            method == HTTP_METHOD_UNKNOWN? "Unknown" : array_method_string[method],
            array_version_string[version], uri);

    return CMN_OK;
}

//int http_get_content_length()
//{
//    std::string contentLengthFieldName(PCPP_HTTP_CONTENT_LENGTH_FIELD);
//    std::transform(contentLengthFieldName.begin(), contentLengthFieldName.end(), contentLengthFieldName.begin(), ::tolower);
//    HeaderField* contentLengthField = getFieldByName(contentLengthFieldName);
//    if (contentLengthField != NULL)
//        return atoi(contentLengthField->getFieldValue().c_str());
//    return 0;
//}


int http_parse_response_first_line(char* data, int data_size)
{
    int version = 0;
    int code = 0;
    char *end = NULL;

    version = http_parse_response_version(data, data_size);
    if (version == VERSION_UNKNOWN) {
        log_error("failed to parse http response version, %d: %s", data_size, data);
        return NET_EFORMAT_HTTP;
    }

    code = http_response_parse_status_code(data, data_size, false);
    if (code == HTTPSTATUSCODEUNKNOWN) {
        log_error("failed to parse http response status code, %d: %s", data_size, data);
        return NET_EFORMAT_HTTP;
    }

    if ((end = (char*)memchr((char*)(data), '\n', data_size)) == NULL) {
        log_error("failed to check http response first line, %d: %s", data_size, data);
        return NET_EFORMAT_HTTP;
    }

    log_info("http response version='%s'; status code=%d '%s'",
            version == VERSION_UNKNOWN ? "Unknown" : array_version_string[version],
            code == HTTPSTATUSCODEUNKNOWN ? 0 : array_status_code[code],
            array_status_code_msg[code]);

    return CMN_OK;
}


int http_parse_request_host(char* data, int data_size, char *host, int host_size)
{
    int len = 0;
    char *pos = NULL;
    char *end = NULL;

    if (data != NULL) {
        pos = (char*)strcasestr(data, NET_HTTP_HOST_FIELD);
        if (pos == NULL) {
            log_error("failed to check http request host, %d: %s", data_size, data);
            return NET_EFORMAT_HTTP;
        }

        if (pos - data >= data_size) {
            log_error("failed to check http request host, out of range, %p: %p %d", pos, data, data_size);
            return NET_EFORMAT_HTTP;
        }

        if (*(pos + 5) != ' ') {
            log_error("failed to check http request host space, %d: %s", data_size, pos+5);
            return NET_EFORMAT_HTTP;
        }

        end = pos + 6;
        
        while(*end != '\r' && *end != '\n' && *end != ' ') {
            end ++;
            len ++;
        }

        strncpy(host, (char *)pos +6, MIN(len, host_size));
        log_debug("parse http request host[%s]", out);
    }

    return CMN_OK;
}

int http_parse_response_status_code(char* data, int data_size, char *code, int code_size)
{
    int len = 0;
    char *pos = NULL;
    char *begin = NULL;
    char *end = NULL;

    if (data != NULL) {
        pos = (char*)strcasestr(data, NET_HTTP_FIELD);
        if (pos == NULL) {
            log_error("failed to check http response http, %d: %s", data_size, data);
            return NET_EFORMAT_HTTP;
        }

        if (pos - data >= data_size) {
            log_error("failed to check http response http, out of range, %p: %p %d", pos, data, data_size);
            return NET_EFORMAT_HTTP;
        }

        if (*(pos + 4) != '/') {
            log_error("failed to check http response http version, %d: %s", data_size, pos+4);
            return NET_EFORMAT_HTTP;
        }

        begin = pos + 5;
        
        while(*begin != '\r' && *begin != '\n' && *begin != ' ') {
            begin ++;
        }
        begin ++;

        end = begin;
        while(*end != '\r' && *end != '\n' && *end != ' ') {
            end ++;
            len ++;
        }

        strncpy(code, (char *)begin, MIN(len, code_size));
        log_debug("parse http response status code[%s]", code);
    }

    return CMN_OK;
}
