/*
 * Implements RFC 5389
 * https://tools.ietf.org/html/rfc5389
 */
#ifndef STUN_H_
#define STUN_H_

#include <stdbool.h>
#include <stdint.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STUN_MAGIC_COOKIE 0x2112A442

//section 6
typedef enum StunMessageClass {
	StunClassRequest = 0,
	StunClassIndication,
	StunClassSuccess,
	StunClassError
} StunMessageClass;

//section 18.1
typedef enum StunMessageMethod {
	StunBinding = 1,
	StunSharedSecret,	//reserved
} StunMessageMethod;

//section 18.2
typedef enum StunAttributeType {
	//Comprehension-required range (0x0000-0x7FFF)
	StunAttributeMappedAddress = 0x0001,
	StunAttributeResponseAddress = 0x0002,	//reserved
	StunAttributeChangeRequest = 0x0003,	//reserved
	StunAttributeSourceAddress = 0x0004,	//reserved
	StunAttributeChangedAddress = 0x0005,	//reserved
	StunAttributeUserName = 0x0006,
	StunAttributePassword = 0x0007,			//reserved
	StunAttributeMessageIntegrity = 0x0008,
	StunAttributeErrorCode = 0x0009,
	StunAttributeUnknownAttributes = 0x000A,
	StunAttributeReflectedFrom = 0x000B,	//reserved
	StunAttributeRealm = 0x0014,
	StunAttributeNonce = 0x0015,
	StunAttributeXorMappedAddress = 0x0020,

	//Comprehension-optional range (0x8000-0xFFFF)
	StunAttributeSoftware = 0x8022,
	StunAttributeAlternateServer = 0x8023,
	StunAttributeFingerprint = 0x8028,
} StunAttributeType;

//section 15.6
typedef enum StunErrorCode {
	StunErrorTryAlternate = 300,
	StunErrorBadRequest = 400,
	StunErrorUnauthorized = 401,
	StunErrorUnknownAtrribute = 420,
	StunErrorStaleNonce = 438,
	StunErrorServerError = 500,
} StunErrorCode;

/*
 *  0                     1
 *  0 1 2  3  4 5 6 7 8 9 0 1 2 3 4 5
 * +-+-+--+--+-+-+-+-+-+-+-+-+-+-+-+-+
 * | | |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
 * |0|0|11|10|9|8|7|1|6|5|4|0|3|2|1|0|
 * +-+-+--+--+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#define STUN_MESSAGE_TYPE(c,m)	((0x0001 & c) << 4 | (0x0002 & c) << 7) | ((0x000F & m) | (0x0070 & m) << 1 | (0x0F80 & m) << 2)

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |0 0|     STUN Message Type     |         Message Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Magic Cookie                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                     Transaction ID (96 bits)                  |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct StunMessageHeader {
	uint16_t type;
	uint16_t length;	//body length
	uint32_t magicCookie;
	uint8_t transactionId[12];
} StunMessageHeader;

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Type               |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            value (variable, 32-bit boundary)            ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct StunAttribute {
    uint16_t type;
	uint16_t length;
	uint8_t data[];
} StunAttribute;

typedef struct StunMessage {
	StunMessageHeader header;
	uint8_t body[];
} StunMessage;

StunMessage * stun_message_parse(uint8_t *buffer, int length);
bool stun_verify_message(StunMessage *msg);
GHashTable * stun_retrieve_attributes(StunMessage *msg);

/**
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |x x x x x x x x|    Family     |         X-Port                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                X-Address (Variable)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Family: 0x01->IPv4 0x02->IPv6
 */
void stun_add_xor_mappped_address(StunMessage *msg, struct sockaddr_in *addr);
void stun_add_message_integrity(StunMessage *msg, const char *key);
void stun_add_fingerprint(StunMessage *msg);

#ifdef __cplusplus
}
#endif

#endif
