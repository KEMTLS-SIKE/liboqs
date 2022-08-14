// SPDX-License-Identifier: MIT

#include <stdlib.h>

#include <oqs/kem_csidh.h>

#include "external/csidh.h"
#include "external/p512/params.h"
#include "oqs/common.h"


OQS_KEM *OQS_KEM_csidh_p512_new(void) {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = OQS_KEM_alg_csidh_p512;
	kem->alg_version = "";

	kem->claimed_nist_level = 1;
	kem->ind_cca = true;

	kem->length_public_key = sizeof(public_key);
	kem->length_secret_key = sizeof(private_key);
	kem->length_ciphertext = sizeof(public_key);
	kem->length_shared_secret = sizeof(public_key);

	kem->keypair = OQS_KEM_csidh_p512_keypair;
	kem->encaps = OQS_KEM_csidh_p512_encaps;
	kem->decaps = OQS_KEM_csidh_p512_decaps;

	return kem;
}

/* Forward KEM API calls to SIDH's API */
OQS_API OQS_STATUS OQS_KEM_csidh_p512_keypair(uint8_t *pkey, uint8_t *skey) {
	csidh_private((private_key*) skey);
	if (csidh((public_key*) pkey, &base, (private_key*) skey)) {
		return OQS_SUCCESS;
	}

	return OQS_ERROR;
}

OQS_API OQS_STATUS OQS_KEM_csidh_p512_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *pkey) {
	private_key ephemeralsk;
	csidh_private(&ephemeralsk);

	if (!csidh((public_key*) ciphertext, &base, &ephemeralsk)) {
		return OQS_ERROR;
	}

	if (!csidh((public_key*) shared_secret, (public_key*) pkey, &ephemeralsk)) {
		return OQS_ERROR;
	}
	
	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_KEM_csidh_p512_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *skey) {
	if (!csidh((public_key*) shared_secret, (public_key*) ciphertext, (private_key*) skey)) {
		return OQS_ERROR;
	}

	return OQS_SUCCESS;
}
