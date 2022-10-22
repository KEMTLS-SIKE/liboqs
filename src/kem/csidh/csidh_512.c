#include <pthread.h>
#include <oqs/kem_csidh.h>
#include "oqs/common.h"

// int.h
#undef uint_0
#undef uint_1
#undef uint_eq
#undef uint_set
#undef uint_len
#undef uint_bit
#undef uint_add3
#undef uint_sub3
#undef uint_mul3_64
#undef uint_eq
#undef uint_random

// mont.h
#undef is_infinity
#undef is_affine
#undef affinize
#undef xDBL
#undef xADD
#undef xDBLADD
#undef xMUL
#undef xISOG
#undef is_twist
#undef xmul_counters
#undef isog_counters

// fp.h
#undef fp_0
#undef fp_0
#undef fp_eq
#undef fp_set
#undef fp_enc
#undef fp_dec
#undef fp_add2
#undef fp_sub2
#undef fp_mul2
#undef fp_add3
#undef fp_sub3
#undef fp_mul3
#undef fp_sq1
#undef fp_sq2
#undef fp_inv
#undef fp_issquare
#undef fp_random

#undef fp_mul_counter
#undef fp_sq_counter
#undef fp_inv_counter
#undef fp_sqt_counter

// csidh.h
#undef private_key
#undef public_key
#undef base
#undef csidh_private
#undef csidh
#undef validate_basic

// constants.h
#undef pbits
#undef p
#undef p_cofactor
#undef r_squared_mod_p
#undef inv_min_p_mod_r
#undef p_minus_2
#undef p_minus_1_halves
#undef four_sqrt_p
#undef first_elligator_rand
#undef cost_ratio_inv_mul

// params.h
#undef uint
#undef fp
#undef proj

#include "external/mont.c"
#include "external/csidh.c"
#include "external/p512/constants.h"

// external/p512/*.s files are included from CMakeLists.txt

// set(SRCS ${SRCS} external/p512/uint.s)
// set(SRCS ${SRCS} external/p512/fp.s external/p512/inv/fpadd511.s external/p512/inv/fpcneg511.s external/p512/inv/fpinv511.c external/p512/inv/fpmul2x2_511_half.c external/p512/inv/fpmul511.s external/p512/inv/jump64divsteps2_s511.s external/p512/inv/muls64xs64.s external/p512/inv/muls128xs128.s external/p512/inv/muls256xs256.s external/p512/inv/norm500_511.s)
// set(SRCS ${SRCS} external/p512/constants.c)



/* Forward KEM API calls to SIDH's API */

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
	kem->length_ephemeral_secret = sizeof(private_key);

	kem->keypair = OQS_KEM_csidh_p512_keypair;
	kem->async_encaps = OQS_KEM_csidh_p512_encaps_async;
	kem->encaps = OQS_KEM_csidh_p512_encaps;
	kem->encaps_ciphertext = OQS_KEM_csidh_p512_keypair;
	kem->encaps_shared_secret = OQS_KEM_csidh_p512_encaps_shared_secret;
	kem->decaps = OQS_KEM_csidh_p512_decaps;

	return kem;
}

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

struct async_enc_pkey_arg {
  unsigned char *ephemeralsk;
  unsigned char *ct;
};

static
void *async_enc_public_key(void *arg)
{
	struct async_enc_pkey_arg *params = arg;
	csidh((public_key*) params->ct, &base, (private_key*) params->ephemeralsk);

	return NULL;
}

OQS_API OQS_STATUS OQS_KEM_csidh_p512_encaps_async(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *pkey) {
	private_key ephemeralsk;
	csidh_private(&ephemeralsk);

    pthread_t async_enc_keygen_b_th;
    struct async_enc_pkey_arg arg1 = {(unsigned char*) &ephemeralsk, ciphertext};
    if (pthread_create(&async_enc_keygen_b_th, NULL,
                &async_enc_public_key, (void*)&arg1)) {
        return OQS_ERROR;
    }

	if (!csidh((public_key*) shared_secret, (public_key*) pkey, &ephemeralsk)) {
		return OQS_ERROR;
	}

    if (pthread_join(async_enc_keygen_b_th, NULL)) {
      	return OQS_ERROR;
    }
	
	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_KEM_csidh_p512_encaps_shared_secret(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *ephemeral_secret, const uint8_t *pkey) {
	(void) ciphertext; // unused argument

	if (!csidh((public_key*) shared_secret, (public_key*) pkey, (private_key*) ephemeral_secret)) {
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
