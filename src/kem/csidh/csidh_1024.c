#include <pthread.h>
#include <oqs/kem_csidh.h>
#include "oqs/common.h"

#define CSIDH_1024

// int.h
#define uint_0 csidh_p1024_uint_0
#define uint_1 csidh_p1024_uint_1
#define uint_eq csidh_p1024_uint_eq
#define uint_set csidh_p1024_uint_set
#define uint_len csidh_p1024_uint_len
#define uint_bit csidh_p1024_uint_bit
#define uint_add3 csidh_p1024_uint_add3
#define uint_sub3 csidh_p1024_uint_sub3
#define uint_mul3_64 csidh_p1024_uint_mul3_64
#define uint_eq csidh_p1024_uint_eq
#define uint_random csidh_p1024_uint_random

// mont.h
#define is_infinity csidh_p1024_is_infinity
#define is_affine csidh_p1024_is_affine
#define affinize csidh_p1024_affinize
#define xDBL csidh_p1024_xDBL
#define xADD csidh_p1024_xADD
#define xDBLADD csidh_p1024_xDBLADD
#define xMUL csidh_p1024_xMUL
#define xISOG csidh_p1024_xISOG
#define is_twist csidh_p1024_is_twist
#define xmul_counters csidh_p1024_xmul_counters
#define isog_counters csidh_p1024_isog_counters

// fp.h
#define fp_0 csidh_p1024_fp_0
#define fp_0 csidh_p1024_fp_1
#define fp_eq csidh_p1024_fp_eq
#define fp_set csidh_p1024_fp_set
#define fp_env csidh_p1024_fp_env
#define fp_dec csidh_p1024_fp_dec
#define fp_add2 csidh_p1024_fp_add2
#define fp_sub2 csidh_p1024_fp_sub2
#define fp_mul2 csidh_p1024_fp_mul2
#define fp_add3 csidh_p1024_fp_add3
#define fp_sub3 csidh_p1024_fp_sub3
#define fp_mul3 csidh_p1024_fp_mul3
#define fp_sq1 csidh_p1024_fp_sq1
#define fp_sq2 csidh_p1024_fp_sq2
#define fp_inv csidh_p1024_fp_inv
#define fp_issquare csidh_p1024_fp_issquare
#define fp_random csidh_p1024_fp_random

#define fp_mul_counter csidh_p1024_fp_mul_counter
#define fp_sq_counter csidh_p1024_fp_sq_counter
#define fp_inv_counter csidh_p1024_fp_inv_counter
#define fp_sqt_counter csidh_p1024_fp_sqt_counter

// csidh.h
#define private_key csidh_p1024_private_key
#define public_key csidh_p1024_public_key
#define base csidh_p1024_base
#define csidh_private csidh_p1024_csidh_private
#define csidh csidh_p1024_csidh
#define validate_basic csidh_p1024_validate_basic

// constants.h
#define pbits csidh_p1024_pbits
#define p csidh_p1024_p
#define p_cofactor csidh_p1024_p_cofactor
#define r_squared_mod_p csidh_p1024_r_squared_mod_p
#define inv_min_p_mod_r csidh_p1024_inv_min_p_mod_r
#define p_minus_2 csidh_p1024_p_minus_2
#define p_minus_1_halves csidh_p1024_p_minus_1_halves
#define four_sqrt_p csidh_p1024_four_sqrt_p
#define first_elligator_rand csidh_p1024_first_elligator_rand
#define cost_ratio_inv_mul csidh_p1024_cost_ratio_inv_mul

// params.h
#define uint csidh_p1024_uint
#define fp csidh_p1024_fp
#define proj csidh_p1024_proj

#include "external/mont.c"
#include "external/csidh.c"
#include "external/p1024/constants.c"
#include "external/uint.c"
#include "external/fp.c"


/* Forward KEM API calls to SIDH's API */

OQS_KEM *OQS_KEM_csidh_p1024_new(void) {

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

	kem->keypair = OQS_KEM_csidh_p1024_keypair;
	kem->async_encaps = OQS_KEM_csidh_p1024_encaps_async;
	kem->encaps = OQS_KEM_csidh_p1024_encaps;
	kem->encaps_ciphertext = OQS_KEM_csidh_p1024_keypair;
	kem->encaps_shared_secret = OQS_KEM_csidh_p1024_encaps_shared_secret;
	kem->decaps = OQS_KEM_csidh_p1024_decaps;

	return kem;
}

OQS_API OQS_STATUS OQS_KEM_csidh_p1024_keypair(uint8_t *pkey, uint8_t *skey) {
	csidh_private((private_key*) skey);
	if (csidh((public_key*) pkey, &base, (private_key*) skey)) {
		return OQS_SUCCESS;
	}

	return OQS_ERROR;
}

OQS_API OQS_STATUS OQS_KEM_csidh_p1024_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *pkey) {
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

OQS_API OQS_STATUS OQS_KEM_csidh_p1024_encaps_async(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *pkey) {
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

OQS_API OQS_STATUS OQS_KEM_csidh_p1024_encaps_shared_secret(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *ephemeral_secret, const uint8_t *pkey) {
	(void) ciphertext; // unused argument

	if (!csidh((public_key*) shared_secret, (public_key*) pkey, (private_key*) ephemeral_secret)) {
		return OQS_ERROR;
	}

	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_KEM_csidh_p1024_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *skey) {
	if (!csidh((public_key*) shared_secret, (public_key*) ciphertext, (private_key*) skey)) {
		return OQS_ERROR;
	}

	return OQS_SUCCESS;
}

#undef CSIDH_1024