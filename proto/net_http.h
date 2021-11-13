#ifndef __NET_HTTP_H
#define __NET_HTTP_H

#include "net.h"

// some popular HTTP fields

    /** Host field */
#define NET_HTTP_HOST_FIELD                "Host"
    /** Connection field */
#define NET_HTTP_CONNECTION_FIELD          "Connection"
    /** User-Agent field */
#define NET_HTTP_USER_AGENT_FIELD          "User-Agent"
    /** Referer field */
#define NET_HTTP_REFERER_FIELD             "Referer"
    /** Accept field */
#define NET_HTTP_ACCEPT_FIELD              "Accept"
    /** Accept-Encoding field */
#define NET_HTTP_ACCEPT_ENCODING_FIELD     "Accept-Encoding"
    /** Accept-Language field */
#define NET_HTTP_ACCEPT_LANGUAGE_FIELD     "Accept-Language"
    /** Cookie field */
#define NET_HTTP_COOKIE_FIELD              "Cookie"
    /** Content-Length field */
#define NET_HTTP_CONTENT_LENGTH_FIELD      "Content-Length"
    /** Content-Encoding field */
#define NET_HTTP_CONTENT_ENCODING_FIELD    "Content-Encoding"
    /** Content-Type field */
#define NET_HTTP_CONTENT_TYPE_FIELD        "Content-Type"
    /** Transfer-Encoding field */
#define NET_HTTP_TRANSFER_ENCODING_FIELD   "Transfer-Encoding"
    /** Server field */
#define NET_HTTP_SERVER_FIELD              "Server"
    /** HTTP field */
#define NET_HTTP_FIELD                     "HTTP/"

enum HTTP_METHOD
{
    /** GET */
    HTTP_GET,
    /** HEAD */
    HTTP_HEAD,
    /** POST */
    HTTP_POST,
    /** PUT */
    HTTP_PUT,
    /** DELETE */
    HTTP_DELETE,
    /** TRACE */
    HTTP_TRACE,
    /** OPTIONS */
    HTTP_OPTIONS,
    /** CONNECT */
    HTTP_CONNECT,
    /** PATCH */
    HTTP_PATCH,
    /** Unknown HTTP method */
    HTTP_METHOD_UNKNOWN
};

/**
 * An enum for HTTP version
 */
enum HTTP_VERSION
{
    /** HTTP/0.9 */
    VERSION_ZERO_DOT_NINE,
    /** HTTP/1.0 */
    VERSION_ONE_DOT_ZERO,
    /** HTTP/1.1 */
    VERSION_ONE_DOT_ONE,
    /** Unknown HTTP version */
    VERSION_UNKNOWN
};

enum HTTP_RESPONSE_STATUS_CODE
{
    /** 100 Continue*/
    HTTP100CONTINUE,
    /** 101 Switching Protocols*/
    HTTP101SWITCHINGPROTOCOLS,
    /** 102 Processing */
    HTTP102PROCESSING,
    /** 200 OK */
    HTTP200OK,
    /** 201 Created */
    HTTP201CREATED,
    /** 202 Accepted */
    HTTP202ACCEPTED,
    /** 203 Non-Authoritative Information */
    HTTP203NONAUTHORITATIVEINFORMATION,
    /** 204 No Content*/
    HTTP204NOCONTENT,
    /** 205 Reset Content*/
    HTTP205RESETCONTENT,
    /** 206 Partial Content */
    HTTP206PARTIALCONTENT,
    /** 207 Multi-Status */
    HTTP207MULTISTATUS,
    /** 208 Already Reported */
    HTTP208ALREADYREPORTED,
    /** 226 IM Used */
    HTTP226IMUSED,
    /** 300 Multiple Choices */
    HTTP300MULTIPLECHOICES,
    /** 301 Moved Permanently */
    HTTP301MOVEDPERMANENTLY,
    /** 302 (various messages) */
    HTTP302,
    /** 303 See Other */
    HTTP303SEEOTHER,
    /** 304 Not Modified */
    HTTP304NOTMODIFIED,
    /** 305 Use Proxy */
    HTTP305USEPROXY,
    /** 306 Switch Proxy */
    HTTP306SWITCHPROXY,
    /** 307 Temporary Redirect */
    HTTP307TEMPORARYREDIRECT,
    /** 308 Permanent Redirect, */
    HTTP308PERMANENTREDIRECT,
    /** 400 Bad Request */
    HTTP400BADREQUEST,
    /** 401 Unauthorized */
    HTTP401UNAUTHORIZED,
    /** 402 Payment Required */
    HTTP402PAYMENTREQUIRED,
    /** 403 Forbidden */
    HTTP403FORBIDDEN,
    /** 404 Not Found */
    HTTP404NOTFOUND,
    /** 405 Method Not Allowed */
    HTTP405METHODNOTALLOWED,
    /** 406 Not Acceptable */
    HTTP406NOTACCEPTABLE,
    /** 407 Proxy Authentication Required */
    HTTP407PROXYAUTHENTICATIONREQUIRED,
    /** 408 Request Timeout */
    HTTP408REQUESTTIMEOUT,
    /** 409 Conflict */
    HTTP409CONFLICT,
    /** 410 Gone */
    HTTP410GONE,
    /** 411 Length Required */
    HTTP411LENGTHREQUIRED,
    /** 412 Precondition Failed */
    HTTP412PRECONDITIONFAILED,
    /** 413 RequestEntity Too Large */
    HTTP413REQUESTENTITYTOOLARGE,
    /** 414 Request-URI Too Long */
    HTTP414REQUESTURITOOLONG,
    /** 415 Unsupported Media Type */
    HTTP415UNSUPPORTEDMEDIATYPE,
    /** 416 Requested Range Not Satisfiable */
    HTTP416REQUESTEDRANGENOTSATISFIABLE,
    /** 417 Expectation Failed */
    HTTP417EXPECTATIONFAILED,
    /** 418 I'm a teapot */
    HTTP418IMATEAPOT,
    /** 419 Authentication Timeout */
    HTTP419AUTHENTICATIONTIMEOUT,
    /** 420 (various messages) */
    HTTP420,
    /** 422 Unprocessable Entity */
    HTTP422UNPROCESSABLEENTITY,
    /** 423 Locked */
    HTTP423LOCKED,
    /** 424 Failed Dependency */
    HTTP424FAILEDDEPENDENCY,
    /** 426 Upgrade Required */
    HTTP426UPGRADEREQUIRED,
    /** 428 Precondition Required */
    HTTP428PRECONDITIONREQUIRED,
    /** 429 Too Many Requests */
    HTTP429TOOMANYREQUESTS,
    /** 431 Request Header Fields Too Large */
    HTTP431REQUESTHEADERFIELDSTOOLARGE,
    /** 440 Login Timeout */
    HTTP440LOGINTIMEOUT,
    /** 444 No Response */
    HTTP444NORESPONSE,
    /** 449 Retry With */
    HTTP449RETRYWITH,
    /** 450 Blocked by Windows Parental Controls */
    HTTP450BLOCKEDBYWINDOWSPARENTALCONTROLS,
    /** 451 (various messages) */
    HTTP451,
    /** 494 Request Header Too Large */
    HTTP494REQUESTHEADERTOOLARGE,
    /** 495 Cert Error */
    HTTP495CERTERROR,
    /** 496 No Cert */
    HTTP496NOCERT,
    /** 497 HTTP to HTTPS */
    HTTP497HTTPTOHTTPS,
    /** 498 Token expired/invalid */
    HTTP498TOKENEXPIREDINVALID,
    /** 499 (various messages) */
    HTTP499,
    /** 500 Internal Server Error */
    HTTP500INTERNALSERVERERROR,
    /** 501 Not Implemented */
    HTTP501NOTIMPLEMENTED,
    /** 502 Bad Gateway */
    HTTP502BADGATEWAY,
    /** 503 Service Unavailable */
    HTTP503SERVICEUNAVAILABLE,
    /** 504 Gateway Timeout */
    HTTP504GATEWAYTIMEOUT,
    /** 505 HTTP Version Not Supported */
    HTTP505HTTPVERSIONNOTSUPPORTED,
    /** 506 Variant Also Negotiates */
    HTTP506VARIANTALSONEGOTIATES,
    /** 507 Insufficient Storage */
    HTTP507INSUFFICIENTSTORAGE,
    /** 508 Loop Detected */
    HTTP508LOOPDETECTED,
    /** 509 Bandwidth Limit Exceeded */
    HTTP509BANDWIDTHLIMITEXCEEDED,
    /** 510 Not Extended */
    HTTP510NOTEXTENDED,
    /** 511 Network Authentication Required */
    HTTP511NETWORKAUTHENTICATIONREQUIRED,
    /** 520 Origin Error */
    HTTP520ORIGINERROR,
    /** 521 Web server is down */
    HTTP521WEBSERVERISDOWN,
    /** 522 Connection timed out */
    HTTP522CONNECTIONTIMEDOUT,
    /** 523 Proxy Declined Request */
    HTTP523PROXYDECLINEDREQUEST,
    /** 524 A timeout occurred */
    HTTP524ATIMEOUTOCCURRED,
    /** 598 Network read timeout error */
    HTTP598NETWORKREADTIMEOUTERROR,
    /** 599 Network connect timeout error */
    HTTP599NETWORKCONNECTTIMEOUTERROR,
    /** Unknown status code */
    HTTPSTATUSCODEUNKNOWN
};


int http_parse_request_method(char *data, int data_size);
int http_parse_request_first_line(char *data, int data_size);

int http_parse_response_first_line(char *data, int data_size);
int http_response_parse_status_code(char *data, int data_size, bool is_check_version);

int http_parse_request_host(char* data, int data_size, char *host, int host_size);
int http_parse_response_status_code(char* data, int data_size, char *code, int code_size);

#endif
