#ifndef __NET_TLS_H
#define __NET_TLS_H

#include "cmn.h"

#define NET_INVALID_TLS_LENGTH 1
#define NET_INVALID_CONTENT_TYPE 2
#define NET_INVALID_VERSION 3
#define UNSUPPORTED_MESSAGE_TYPENET_ 4
#define INVALID_FILE_LENGTH_FOR_CLIENT_KEY_EXCHANGE 5

#define MIN_RECORD_LAYER_SIZE    3 // Has to be atleast (TLS_CONTENT_TYPE + TLS version)
#define MIN_CLIENT_HELLO_SIZE   38 // A client hello has to be atleast 38 bytes
#define MIN_SERVER_HELLO_SIZE   38 // A server hello has to be atleast 38 bytes
#define TLS_HELLO_RANDOM_SIZE 28 // As specified in RFC

// 'cipher_suites': {
//     0x010080: 'SSL_CK_RC4_128_WITH_MD5',
//     0x020080: 'SSL_CK_RC4_128_EXPORT40_WITH_MD5',
//     0x030080: 'SSL_CK_RC2_128_CBC_WITH_MD5	',
//     0x040080: 'SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5',
//     0x050080: 'SSL_CK_IDEA_128_CBC_WITH_MD5',
//     0x060040: 'SSL_CK_DES_64_CBC_WITH_MD5',
//     0x0700C0: 'SSL_CK_DES_192_EDE3_CBC_WITH_MD5',
//     0x080080: 'SSL_CK_RC4_64_WITH_MD5',
//     0x00: 'TLS_NULL_WITH_NULL_NULL',
//     0x01: 'TLS_RSA_WITH_NULL_MD5',
//     0x02: 'TLS_RSA_WITH_NULL_SHA',
//     0x03: 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
//     0x04: 'TLS_RSA_WITH_RC4_128_MD5',
//     0x05: 'TLS_RSA_WITH_RC4_128_SHA',
//     0x06: 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
//     0x07: 'TLS_RSA_WITH_IDEA_CBC_SHA',
//     0x08: 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
//     0x09: 'TLS_RSA_WITH_DES_CBC_SHA',
//     0x0A: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
//     0x0B: 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
//     0x0C: 'TLS_DH_DSS_WITH_DES_CBC_SHA',
//     0x0D: 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
//     0x0E: 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
//     0x0F: 'TLS_DH_RSA_WITH_DES_CBC_SHA',
//     0x10: 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
//     0x11: 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
//     0x12: 'TLS_DHE_DSS_WITH_DES_CBC_SHA',
//     0x13: 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
//     0x14: 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
//     0x15: 'TLS_DHE_RSA_WITH_DES_CBC_SHA',
//     0x16: 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
//     0x17: 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5',
//     0x18: 'TLS_DH_anon_WITH_RC4_128_MD5',
//     0x19: 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
//     0x1A: 'TLS_DH_anon_WITH_DES_CBC_SHA',
//     0x1B: 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',
//     0x1E: 'TLS_KRB5_WITH_DES_CBC_SHA',
//     0x1F: 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA',
//     0x20: 'TLS_KRB5_WITH_RC4_128_SHA',
//     0x21: 'TLS_KRB5_WITH_IDEA_CBC_SHA',
//     0x22: 'TLS_KRB5_WITH_DES_CBC_MD5',
//     0x23: 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5',
//     0x24: 'TLS_KRB5_WITH_RC4_128_MD5',
//     0x25: 'TLS_KRB5_WITH_IDEA_CBC_MD5',
//     0x26: 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA',
//     0x27: 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA',
//     0x28: 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA',
//     0x29: 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5',
//     0x2A: 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5',
//     0x2B: 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5',
//     0x2C: 'TLS_PSK_WITH_NULL_SHA',
//     0x2D: 'TLS_DHE_PSK_WITH_NULL_SHA',
//     0x2E: 'TLS_RSA_PSK_WITH_NULL_SHA',
//     0x2F: 'TLS_RSA_WITH_AES_128_CBC_SHA',
//     0x30: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
//     0x31: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
//     0x32: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
//     0x33: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
//     0x34: 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
//     0x35: 'TLS_RSA_WITH_AES_256_CBC_SHA',
//     0x36: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
//     0x37: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
//     0x38: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
//     0x39: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
//     0x3A: 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
//     0x3B: 'TLS_RSA_WITH_NULL_SHA256',
//     0x3C: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
//     0x3D: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
//     0x3E: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
//     0x3F: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
//     0x40: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
//     0x41: 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
//     0x42: 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
//     0x43: 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
//     0x44: 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
//     0x45: 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
//     0x46: 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA',
//     0x60: 'TLS_RSA_EXPORT1024_WITH_RC4_56_MD5',
//     0x61: 'TLS_RSA_EXPORT1024_WITH_RC2_56_MD5',
//     0x62: 'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA',
//     0x63: 'TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA',
//     0x64: 'TLS_RSA_EXPORT1024_WITH_RC4_56_SHA',
//     0x65: 'TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA',
//     0x66: 'TLS_DHE_DSS_WITH_RC4_128_SHA',
//     0x67: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
//     0x68: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
//     0x69: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
//     0x6A: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
//     0x6B: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
//     0x6C: 'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
//     0x6D: 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
//     0x80: 'TLS_GOSTR341094_WITH_28147_CNT_IMIT',
//     0x81: 'TLS_GOSTR341001_WITH_28147_CNT_IMIT',
//     0x82: 'TLS_GOSTR341094_WITH_NULL_GOSTR3411',
//     0x83: 'TLS_GOSTR341001_WITH_NULL_GOSTR3411',
//     0x84: 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
//     0x85: 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
//     0x86: 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
//     0x87: 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
//     0x88: 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
//     0x89: 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA',
//     0x8A: 'TLS_PSK_WITH_RC4_128_SHA',
//     0x8B: 'TLS_PSK_WITH_3DES_EDE_CBC_SHA',
//     0x8C: 'TLS_PSK_WITH_AES_128_CBC_SHA',
//     0x8D: 'TLS_PSK_WITH_AES_256_CBC_SHA',
//     0x8E: 'TLS_DHE_PSK_WITH_RC4_128_SHA',
//     0x8F: 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA',
//     0x90: 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',
//     0x91: 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA',
//     0x92: 'TLS_RSA_PSK_WITH_RC4_128_SHA',
//     0x93: 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA',
//     0x94: 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA',
//     0x95: 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA',
//     0x96: 'TLS_RSA_WITH_SEED_CBC_SHA',
//     0x97: 'TLS_DH_DSS_WITH_SEED_CBC_SHA',
//     0x98: 'TLS_DH_RSA_WITH_SEED_CBC_SHA',
//     0x99: 'TLS_DHE_DSS_WITH_SEED_CBC_SHA',
//     0x9A: 'TLS_DHE_RSA_WITH_SEED_CBC_SHA',
//     0x9B: 'TLS_DH_anon_WITH_SEED_CBC_SHA',
//     0x9C: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
//     0x9D: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
//     0x9E: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
//     0x9F: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
//     0xA0: 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
//     0xA1: 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
//     0xA2: 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
//     0xA3: 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
//     0xA4: 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',
//     0xA5: 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',
//     0xA6: 'TLS_DH_anon_WITH_AES_128_GCM_SHA256',
//     0xA7: 'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
//     0xA8: 'TLS_PSK_WITH_AES_128_GCM_SHA256',
//     0xA9: 'TLS_PSK_WITH_AES_256_GCM_SHA384',
//     0xAA: 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256',
//     0xAB: 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384',
//     0xAC: 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256',
//     0xAD: 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384',
//     0xAE: 'TLS_PSK_WITH_AES_128_CBC_SHA256',
//     0xAF: 'TLS_PSK_WITH_AES_256_CBC_SHA384',
//     0xB0: 'TLS_PSK_WITH_NULL_SHA256',
//     0xB1: 'TLS_PSK_WITH_NULL_SHA384',
//     0xB2: 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256',
//     0xB3: 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384',
//     0xB4: 'TLS_DHE_PSK_WITH_NULL_SHA256',
//     0xB5: 'TLS_DHE_PSK_WITH_NULL_SHA384',
//     0xB6: 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256',
//     0xB7: 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384',
//     0xB8: 'TLS_RSA_PSK_WITH_NULL_SHA256',
//     0xB9: 'TLS_RSA_PSK_WITH_NULL_SHA384',
//     0xBA: 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256',
//     0xBB: 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256',
//     0xBC: 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
//     0xBD: 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256',
//     0xBE: 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
//     0xBF: 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256',
//     0xC0: 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256',
//     0xC1: 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256',
//     0xC2: 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256',
//     0xC3: 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256',
//     0xC4: 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256',
//     0xC5: 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256',
//     0xFF: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
//     0x5600: 'TLS_FALLBACK_SCSV',
//     0xC001: 'TLS_ECDH_ECDSA_WITH_NULL_SHA',
//     0xC002: 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',
//     0xC003: 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
//     0xC004: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
//     0xC005: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
//     0xC006: 'TLS_ECDHE_ECDSA_WITH_NULL_SHA',
//     0xC007: 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
//     0xC008: 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
//     0xC009: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
//     0xC00A: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
//     0xC00B: 'TLS_ECDH_RSA_WITH_NULL_SHA',
//     0xC00C: 'TLS_ECDH_RSA_WITH_RC4_128_SHA',
//     0xC00D: 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
//     0xC00E: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',
//     0xC00F: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',
//     0xC010: 'TLS_ECDHE_RSA_WITH_NULL_SHA',
//     0xC011: 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
//     0xC012: 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
//     0xC013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
//     0xC014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
//     0xC015: 'TLS_ECDH_anon_WITH_NULL_SHA',
//     0xC016: 'TLS_ECDH_anon_WITH_RC4_128_SHA',
//     0xC017: 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',
//     0xC018: 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
//     0xC019: 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',
//     0xC01A: 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA',
//     0xC01B: 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',
//     0xC01C: 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA',
//     0xC01D: 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA',
//     0xC01E: 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA',
//     0xC01F: 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA',
//     0xC020: 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA',
//     0xC021: 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA',
//     0xC022: 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA',
//     0xC023: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
//     0xC024: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
//     0xC025: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
//     0xC026: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
//     0xC027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
//     0xC028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
//     0xC029: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
//     0xC02A: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
//     0xC02B: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
//     0xC02C: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
//     0xC02D: 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
//     0xC02E: 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
//     0xC02F: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
//     0xC030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
//     0xC031: 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
//     0xC032: 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
//     0xC033: 'TLS_ECDHE_PSK_WITH_RC4_128_SHA',
//     0xC034: 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA',
//     0xC035: 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA',
//     0xC036: 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA',
//     0xC037: 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
//     0xC038: 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384',
//     0xC039: 'TLS_ECDHE_PSK_WITH_NULL_SHA',
//     0xC03A: 'TLS_ECDHE_PSK_WITH_NULL_SHA256',
//     0xC03B: 'TLS_ECDHE_PSK_WITH_NULL_SHA384',
//     0xC03C: 'TLS_RSA_WITH_ARIA_128_CBC_SHA256',
//     0xC03D: 'TLS_RSA_WITH_ARIA_256_CBC_SHA384',
//     0xC03E: 'TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256',
//     0xC03F: 'TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384',
//     0xC040: 'TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256',
//     0xC041: 'TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384',
//     0xC042: 'TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256',
//     0xC043: 'TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384',
//     0xC044: 'TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256',
//     0xC045: 'TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384',
//     0xC046: 'TLS_DH_anon_WITH_ARIA_128_CBC_SHA256',
//     0xC047: 'TLS_DH_anon_WITH_ARIA_256_CBC_SHA384',
//     0xC048: 'TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256',
//     0xC049: 'TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384',
//     0xC04A: 'TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256',
//     0xC04B: 'TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384',
//     0xC04C: 'TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256',
//     0xC04D: 'TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384',
//     0xC04E: 'TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256',
//     0xC04F: 'TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384',
//     0xC050: 'TLS_RSA_WITH_ARIA_128_GCM_SHA256',
//     0xC051: 'TLS_RSA_WITH_ARIA_256_GCM_SHA384',
//     0xC052: 'TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256',
//     0xC053: 'TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384',
//     0xC054: 'TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256',
//     0xC055: 'TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384',
//     0xC056: 'TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256',
//     0xC057: 'TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384',
//     0xC058: 'TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256',
//     0xC059: 'TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384',
//     0xC05A: 'TLS_DH_anon_WITH_ARIA_128_GCM_SHA256',
//     0xC05B: 'TLS_DH_anon_WITH_ARIA_256_GCM_SHA384',
//     0xC05C: 'TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256',
//     0xC05D: 'TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384',
//     0xC05E: 'TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256',
//     0xC05F: 'TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384',
//     0xC060: 'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256',
//     0xC061: 'TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384',
//     0xC062: 'TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256',
//     0xC063: 'TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384',
//     0xC064: 'TLS_PSK_WITH_ARIA_128_CBC_SHA256',
//     0xC065: 'TLS_PSK_WITH_ARIA_256_CBC_SHA384',
//     0xC066: 'TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256',
//     0xC067: 'TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384',
//     0xC068: 'TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256',
//     0xC069: 'TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384',
//     0xC06A: 'TLS_PSK_WITH_ARIA_128_GCM_SHA256',
//     0xC06B: 'TLS_PSK_WITH_ARIA_256_GCM_SHA384',
//     0xC06C: 'TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256',
//     0xC06D: 'TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384',
//     0xC06E: 'TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256',
//     0xC06F: 'TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384',
//     0xC070: 'TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256',
//     0xC071: 'TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384',
//     0xC072: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
//     0xC073: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
//     0xC074: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
//     0xC075: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
//     0xC076: 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
//     0xC077: 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
//     0xC078: 'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
//     0xC079: 'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384',
//     0xC07A: 'TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256',
//     0xC07B: 'TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384',
//     0xC07C: 'TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
//     0xC07D: 'TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
//     0xC07E: 'TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
//     0xC07F: 'TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
//     0xC080: 'TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256',
//     0xC081: 'TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384',
//     0xC082: 'TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256',
//     0xC083: 'TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384',
//     0xC084: 'TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256',
//     0xC085: 'TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384',
//     0xC086: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
//     0xC087: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
//     0xC088: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
//     0xC089: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
//     0xC08A: 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
//     0xC08B: 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
//     0xC08C: 'TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
//     0xC08D: 'TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
//     0xC08E: 'TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256',
//     0xC08F: 'TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384',
//     0xC090: 'TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256',
//     0xC091: 'TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384',
//     0xC092: 'TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256',
//     0xC093: 'TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384',
//     0xC094: 'TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256',
//     0xC095: 'TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384',
//     0xC096: 'TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
//     0xC097: 'TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
//     0xC098: 'TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256',
//     0xC099: 'TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384',
//     0xC09A: 'TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
//     0xC09B: 'TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
//     0xC09C: 'TLS_RSA_WITH_AES_128_CCM',
//     0xC09D: 'TLS_RSA_WITH_AES_256_CCM',
//     0xC09E: 'TLS_DHE_RSA_WITH_AES_128_CCM',
//     0xC09F: 'TLS_DHE_RSA_WITH_AES_256_CCM',
//     0xC0A0: 'TLS_RSA_WITH_AES_128_CCM_8',
//     0xC0A1: 'TLS_RSA_WITH_AES_256_CCM_8',
//     0xC0A2: 'TLS_DHE_RSA_WITH_AES_128_CCM_8',
//     0xC0A3: 'TLS_DHE_RSA_WITH_AES_256_CCM_8',
//     0xC0A4: 'TLS_PSK_WITH_AES_128_CCM',
//     0xC0A5: 'TLS_PSK_WITH_AES_256_CCM',
//     0xC0A6: 'TLS_DHE_PSK_WITH_AES_128_CCM',
//     0xC0A7: 'TLS_DHE_PSK_WITH_AES_256_CCM',
//     0xC0A8: 'TLS_PSK_WITH_AES_128_CCM_8',
//     0xC0A9: 'TLS_PSK_WITH_AES_256_CCM_8',
//     0xC0AA: 'TLS_PSK_DHE_WITH_AES_128_CCM_8',
//     0xC0AB: 'TLS_PSK_DHE_WITH_AES_256_CCM_8',
//     0xC09C: 'TLS_RSA_WITH_AES_128_CCM',
//     0xC09D: 'TLS_RSA_WITH_AES_256_CCM',
//     0xC09E: 'TLS_DHE_RSA_WITH_AES_128_CCM',
//     0xC09F: 'TLS_DHE_RSA_WITH_AES_256_CCM',
//     0xC0A0: 'TLS_RSA_WITH_AES_128_CCM_8',
//     0xC0A1: 'TLS_RSA_WITH_AES_256_CCM_8',
//     0xC0A2: 'TLS_DHE_RSA_WITH_AES_128_CCM_8',
//     0xC0A3: 'TLS_DHE_RSA_WITH_AES_256_CCM_8',
//     0xC0A4: 'TLS_PSK_WITH_AES_128_CCM',
//     0xC0A5: 'TLS_PSK_WITH_AES_256_CCM',
//     0xC0A6: 'TLS_DHE_PSK_WITH_AES_128_CCM',
//     0xC0A7: 'TLS_DHE_PSK_WITH_AES_256_CCM',
//     0xC0A8: 'TLS_PSK_WITH_AES_128_CCM_8',
//     0xC0A9: 'TLS_PSK_WITH_AES_256_CCM_8',
//     0xC0AA: 'TLS_PSK_DHE_WITH_AES_128_CCM_8',
//     0xC0AB: 'TLS_PSK_DHE_WITH_AES_256_CCM_80',
//     0xC0AC: 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
//     0xC0AD: 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM',
//     0xC0AE: 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8',
//     0xC0AF: 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8',
//     0xCC13: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
//     0xCC14: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
//     0xCC15: 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
//     0xCCA8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
//     0xCCA9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
//     0xFEFE: 'SSL_RSA_FIPS_WITH_DES_CBC_SHA',
//     0xFEFE: 'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA',
//     0xFFE0: 'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA',
//     0xFFE1: 'SSL_RSA_FIPS_WITH_DES_CBC_SHA'
// },

// 'signature_algorithms_hash': {  #RFC 5246
//     0: 'none',
//     1: 'md5',
//     2: 'sha1',
//     3: 'sha224',
//     4: 'sha256',
//     5: 'sha384',
//     6: 'sha512'
// },

// 'signature_algorithms_signature': {
//     0: 'anonymous',
//     1: 'rsa',
//     2: 'dsa',
//     3: 'ecdsa'
// },

enum TLS_VERSION
{
    /** TLSv2.0 */
    TLS2   = 0x0200,
    /** TLSv3.0 */
    TLS3   = 0x0300,
    /** TLSv1.0 */
    TLS1_0 = 0x0301,
    /** TLSv1.1 */
    TLS1_1 = 0x0302,
    /** TLSv1.2 */
    TLS1_2 = 0x0303
};

enum TLS_CONTENT_TYPE
{
    TLS_CHANGE_CIPHER_SPEC = 20,  // 0x14
    TLS_ALERT = 21,               // 0x15
    TLS_HANDSHAKE = 22,           // 0x16
    TLS_APPLICATION_DATA = 23,    // 0x17
};

// This parser is capable of parsing messages 1, 2, 11, 12, 14 and 16
// Any other message is considered invalid
enum TLS_HANDSHAKE_TYPE
{
   /** Hello-request message type */
    TLS_HELLO_REQUEST       = 0,
    /** Client-hello message type */
    TLS_CLIENT_HELLO        = 1,
    /** Server-hello message type */
    TLS_SERVER_HELLO        = 2,
    /** New-session-ticket message type */
    TLS_NEW_SESSION_TICKET  = 4,
    /** Certificate message type */
    TLS_CERTIFICATE         = 11,
    /** Server-key-exchange message type */
    TLS_SERVER_KEY_EXCHANGE = 12,
    /** Certificate-request message type */
    TLS_CERTIFICATE_REQUEST = 13,
    /** Server-hello-done message type */
    TLS_SERVER_DONE         = 14,
    /** Certificate-verify message type */
    TLS_CERTIFICATE_VERIFY  = 15,
    /** Client-key-exchange message type */
    TLS_CLIENT_KEY_EXCHANGE = 16,
    /** Finish message type */
    TLS_FINISHED            = 20,
};

struct tls_random
{
    uint32_t time;
    uint8_t random_data[TLS_HELLO_RANDOM_SIZE];
};

struct tls_session_id
{
    uint8_t len;
    uint8_t *session_data;
};

struct tls_cipher_suite_collection
{
    uint16_t len;
    uint8_t *cipher_suite_data; // The individual suites are not in scope of the parser
};

struct tls_compresion_method
{
    uint8_t len;
    uint8_t method; // The individual method is not in scope of the parser
};

struct tls_client_hello
{
    uint8_t  is_extension;
    uint16_t version;
    uint16_t extension_len;
    struct tls_random random;
    struct tls_session_id session_id;
    struct tls_cipher_suite_collection collection;
    struct tls_compresion_method method;
    uint8_t  *extension_data;
};

struct tls_server_hello
{
    uint8_t  is_extension;
    uint8_t  method;
    uint16_t extension_len;
    uint16_t version;
    uint8_t cipherSuite[2];
    struct tls_random random;
    struct tls_session_id session_id;
    uint8_t  *extension_data; 
};

struct tls_extension
{
    uint16_t type;
    uint16_t len;
    uint8_t *raw;
};

struct tls_handshake_message
{
    uint8_t  tls_type;
    uint8_t  hs_type;
    uint16_t version;
    uint16_t len;         // Length of body + type (1 byte) + body_len (3 bytes)
    uint32_t body_len;         // Length of body
    uint8_t *body;
};

static inline bool is_tls_port(uint16_t port)
{
    bool ret = false;
    
    switch (port)
    {
    case 443:
        ret = true;
    }
    
    return ret;
}

static inline bool is_tls_version(uint16_t version)
{
    bool is_version = false;

    switch (version)
    {
    case TLS2:
        is_version = true;
        break;
    case TLS3:
        is_version = true;
        break;
    case TLS1_0:
        is_version = true;
        break;
    case TLS1_1:
        is_version = true;
        break;
    case TLS1_2:
        is_version = true;
        break;
    }
    return is_version;
}

static inline char *tls_version_string(uint16_t version)
{
    switch (version)
    {
    case TLS2:
        return "TLSv2";
    case TLS3:
        return "TLSv3";
    case TLS1_0:
        return "TLSv1.0";
    case TLS1_1:
        return "TLSv1.1";
    case TLS1_2:
        return "TLSv1.2";
    }

    return "TLS/TLS unknown";
}

static inline bool is_tls_handshake_msg(uint16_t sport, uint16_t dport, uint8_t *data, int32_t data_size, bool is_ignore)
{
    uint16_t version = 0;

    // check the port map first
    if (!is_ignore && (is_tls_port(sport) || is_tls_port(dport)))
        return false;

    if (data_size < MIN_RECORD_LAYER_SIZE)
        return false;

    if (GET_UINT8(data, 0) != TLS_HANDSHAKE) {
        return false;
    }

    version = GET_UINT16(data, 1);
    if (!is_tls_version(version)) {
        return false;
    }

    return true;
}


int parse_extension_sni(uint8_t *data, uint32_t size, char *out, uint32_t out_size);
int parse_extension_message(uint8_t *data, uint32_t size);
int parse_client_hello(uint8_t *msg, uint32_t size, struct tls_client_hello *client);
int parse_server_hello(uint8_t *msg, uint32_t size, struct tls_server_hello *server);
int parse_certificate(uint8_t *msg, uint32_t size);
int parse_server_key_exchange(uint8_t *msg, uint32_t size);
int parse_server_hello_done(uint8_t *msg, uint32_t size);
int parse_client_key_exchange(uint8_t *msg, uint32_t size);

int parse_tls_message(uint8_t *data, uint32_t data_size);
int parse_tls_sni_name(uint8_t *data, uint32_t data_size, uint8_t *out, uint32_t out_size);

int setup_tls_handshake_message(uint8_t *data, uint32_t size, struct tls_handshake_message *msg);

void client_hello_message_info(struct tls_client_hello *msg);
void server_hello_message_info(struct tls_server_hello *msg);
void tls_handshake_message_info(struct tls_handshake_message *msg);


#endif
