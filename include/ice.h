#ifndef YS_ICE_H_
#define YS_ICE_H_

#include <stdint.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum IceCandidateType
{
    /**
     * ICE host candidate. A host candidate represents the actual local
     * transport address in the host.
     */
	IceCandidateTypeHost,

    /**
     * ICE server reflexive candidate, which represents the public mapped
     * address of the local address, and is obtained by sending STUN
     * Binding request from the host candidate to a STUN server.
     */
	IceCandidateTypeServerReflexive,

    /**
     * ICE peer reflexive candidate, which is the address as seen by peer
     * agent during connectivity check.
     */
	IceCandidateTypePeerReflexive,

    /**
     * ICE relayed candidate, which represents the address allocated in
     * TURN server.
     */
	IIceCandidateTypeRelayed
} IceCandidateType;

typedef struct IceCandidate {
    /**
     * The foundation string, which is an identifier which value will be
     * equivalent for two candidates that are of the same type, share the
     * same base, and come from the same STUN server. The foundation is
     * used to optimize ICE performance in the Frozen algorithm.
     */
    char foundation[33];

    /**
     * The candidate's priority, a 32-bit unsigned value which value will be
     * calculated by the ICE session when a candidate is registered to the
     * ICE session.
     */
	uint32_t priority;

    /**
     * IP address of this candidate. For host candidates, this represents
     * the local address of the socket. For reflexive candidates, the value
     * will be the public address allocated in NAT router for the host
     * candidate and as reported in MAPPED-ADDRESS or XOR-MAPPED-ADDRESS
     * attribute of STUN Binding request. For relayed candidate, the value
     * will be the address allocated in the TURN server by STUN Allocate
     * request.
     */
    struct sockaddr_in address;

    IceCandidateType type;

    /**
     * Base address of this candidate. "Base" refers to the address an agent
     * sends from for a particular candidate.  For host candidates, the base
     * is the same as the host candidate itself. For reflexive candidates,
     * the base is the local IP address of the socket. For relayed candidates,
     * the base address is the transport address allocated in the TURN server
     * for this candidate.
     */
    struct sockaddr_in baseAddress;

    /**
     * Local preference value, which typically is 65535.
     */
   uint16_t		 localPreference;

} IceCandidate;

void ice_candidate_calculate_foundation(IceCandidate *ic);
void ice_candidate_calculate_priority(IceCandidate *ic, uint8_t componentId);
char * const ice_candidate_get_type_string(IceCandidate *ic);

#ifdef __cplusplus
}
#endif


#endif
