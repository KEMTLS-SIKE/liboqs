// SPDX-License-Identifier: MIT

#ifndef OQS_KEM_CSIDH_H
#define OQS_KEM_CSIDH_H

#include <oqs/oqs.h>

#define OQS_KEM_csidh_p512_length_public_key 512
#define OQS_KEM_csidh_p512_length_secret_key 74
#define OQS_KEM_csidh_p512_length_ciphertext 512
#define OQS_KEM_csidh_p512_length_shared_secret 512

OQS_KEM *OQS_KEM_csidh_p512_new(void);

OQS_API OQS_STATUS OQS_KEM_csidh_p512_async_init(void);
OQS_API OQS_STATUS OQS_KEM_csidh_p512_async_deinit(void);
OQS_API OQS_STATUS OQS_KEM_csidh_p512_async_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_csidh_p512_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_csidh_p512_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_csidh_p512_encaps_async(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_csidh_p512_encaps_ciphertext(uint8_t *ciphertext, uint8_t *ephemeral_secret);
OQS_API OQS_STATUS OQS_KEM_csidh_p512_encaps_shared_secret(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *ephemeral_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_csidh_p512_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);


#define OQS_KEM_csidh_p1024_length_public_key 1024
#define OQS_KEM_csidh_p1024_length_secret_key 130
#define OQS_KEM_csidh_p1024_length_ciphertext 1024
#define OQS_KEM_csidh_p1024_length_shared_secret 1024

OQS_KEM *OQS_KEM_csidh_p1024_new(void);

OQS_API OQS_STATUS OQS_KEM_csidh_p1024_async_init(void);
OQS_API OQS_STATUS OQS_KEM_csidh_p1024_async_deinit(void);
OQS_API OQS_STATUS OQS_KEM_csidh_p1024_async_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_csidh_p1024_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_csidh_p1024_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_csidh_p1024_encaps_async(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_csidh_p1024_encaps_ciphertext(uint8_t *ciphertext, uint8_t *ephemeral_secret);
OQS_API OQS_STATUS OQS_KEM_csidh_p1024_encaps_shared_secret(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *ephemeral_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_csidh_p1024_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

#endif // OQS_KEM_CSIDH_H
