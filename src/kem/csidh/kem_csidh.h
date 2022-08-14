// SPDX-License-Identifier: MIT

#ifndef OQS_KEM_CSIDH_H
#define OQS_KEM_CSIDH_H

#include <oqs/oqs.h>

#define OQS_KEM_csidh_p512_length_public_key 512
#define OQS_KEM_csidh_p512_length_secret_key 74
#define OQS_KEM_csidh_p512_length_ciphertext 512
#define OQS_KEM_csidh_p512_length_shared_secret 512

OQS_KEM *OQS_KEM_csidh_p512_new(void);

OQS_API OQS_STATUS OQS_KEM_csidh_p512_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_csidh_p512_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_csidh_p512_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

#endif // OQS_KEM_CSIDH_H
