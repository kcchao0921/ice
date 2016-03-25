#include <stdio.h>
#include "ice.h"

static char *typeString[] = {
	"host", "srflx", "prflx", "relay"
};

/* Default ICE session preferences, according to draft-ice */
static uint8_t candidateTypePreferences[] = {
	126, 100, 110, 0
};


void ice_candidate_calculate_foundation(IceCandidate *ic) {
	snprintf(ic->foundation, sizeof(ic->foundation), "%c%x", typeString[ic->type][0], ntohl(ic->baseAddress.sin_addr.s_addr));
}

void ice_candidate_calculate_priority(IceCandidate *ic, uint8_t componentId) {
	ic->priority = ((candidateTypePreferences[ic->type] & 0xFF) << 24) + ((ic->localPreference & 0xFFFF) << 8) + ((256 - componentId) & 0xFF);
}

char * const ice_candidate_get_type_string(IceCandidate *ic) {
	return typeString[ic->type];
}
