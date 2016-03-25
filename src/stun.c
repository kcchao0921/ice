#include <string.h>
#include <zlib.h>
#include "util/log.h"
#include "stun.h"

#define STUN_FINGERPRINT_XOR	0x5354554E

#define MAKE_STUN_ATTRIBUTE(v, m, a, l) \
StunAttribute *v = (StunAttribute *)(m->body + m->header.length);\
v->type = htons(a);\
v->length = htons(l);\
m->header.length += sizeof(StunAttribute) + l;

StunMessage * stun_message_parse(uint8_t *buffer, int length) {
	if(length < (int)sizeof(StunMessageHeader)) {
		return NULL;
	}

	StunMessage *msg = (StunMessage *)buffer;
	msg->header.type = ntohs(msg->header.type);
	msg->header.length = ntohs(msg->header.length);
	msg->header.magicCookie = ntohl(msg->header.magicCookie);

	DEBUG("stun message type = %u, len = %u, magic = 0x%08x", msg->header.type, msg->header.length, msg->header.magicCookie);

	if(!stun_verify_message(msg)) {
		return NULL;
	}

	return msg;
}

bool stun_verify_message(StunMessage *msg) {
	if(msg->header.magicCookie != STUN_MAGIC_COOKIE) {
		return false;
	}

	return true;
}

GHashTable * stun_retrieve_attributes(StunMessage *msg) {
	GHashTable *attrs = g_hash_table_new(NULL, NULL);
	uint8_t *attrStart = msg->body;
	uint16_t len = msg->header.length;
	uint16_t offset = 0;

	while(len > 0) {
		StunAttribute *attr = (StunAttribute *)attrStart;
		attr->type = ntohs(attr->type);
		attr->length = ntohs(attr->length);

		g_hash_table_insert(attrs, (gpointer)attr->type, attr);

		//attr value is 4-bytes aligned
		offset = sizeof(StunAttribute) + attr->length;
		if((attr->length % 4) != 0) {
			offset += 4 - (attr->length % 4);
		}
		attrStart += offset;
		len -= offset;

		DEBUG("type = 0x%x, len = %u, offset = %u, remains = %u", attr->type, attr->length, offset, len);
	}

	return attrs;
}

void stun_add_xor_mappped_address(StunMessage *msg, struct sockaddr_in *addr) {
	MAKE_STUN_ATTRIBUTE(attr, msg, StunAttributeXorMappedAddress, 8)
	attr->data[1] = 0x01;
	*(uint16_t *)(&attr->data[2]) = addr->sin_port ^ htonl(STUN_MAGIC_COOKIE & 0xFFFF0000);
	*(uint32_t *)(&attr->data[4]) = addr->sin_addr.s_addr ^ htonl(STUN_MAGIC_COOKIE);
}

void stun_add_message_integrity(StunMessage *msg, const char *key) {
	MAKE_STUN_ATTRIBUTE(attr, msg, StunAttributeMessageIntegrity, 20)

	gssize textSize = sizeof(StunMessageHeader) + msg->header.length - (sizeof(StunAttribute) + 20);
	msg->header.length = htons(msg->header.length);

	DEBUG("key = %s, text size = %u", key, textSize);

	gsize digestLen = 20;
	GHmac *sha1 = g_hmac_new(G_CHECKSUM_SHA1, (guchar *)key, strlen(key));
	g_hmac_update(sha1, (guchar *)msg, textSize);
	g_hmac_get_digest(sha1, attr->data, &digestLen);
	g_hmac_unref(sha1);

	msg->header.length = ntohs(msg->header.length);
}

void stun_add_fingerprint(StunMessage *msg) {
	MAKE_STUN_ATTRIBUTE(attr, msg, StunAttributeFingerprint, 4)

	gssize textSize = sizeof(StunMessageHeader) + msg->header.length - (sizeof(StunAttribute) + 4);
	msg->header.length = htons(msg->header.length);

	uLong crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, (unsigned char *)msg, textSize);
	crc ^= STUN_FINGERPRINT_XOR;
	crc = htonl(crc);

	memcpy(attr->data, &crc, 4);

	msg->header.length = ntohs(msg->header.length);
}
