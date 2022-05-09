/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: API header file for P503 using compression
*********************************************************************************************/

#ifndef P503_1CCA_COMPRESSED_API_H
#define P503_1CCA_COMPRESSED_API_H

/*********************** Key encapsulation mechanism API ***********************/

// OQS note: size #defines moved to P503_compressed.c to avoid redefinitions across parameters

int OQS_KEM_sike_p503_1cca_compressed_async_init(void);
int OQS_KEM_sike_p503_1cca_compressed_async_deinit(void);
int OQS_KEM_sike_p503_1cca_compressed_keypair_async(unsigned char *pk, unsigned char *sk);
// SIKE's key generation
// It produces a private key sk and computes the public key pk.
// Outputs: secret key sk (CRYPTO_SECRETKEYBYTES = 350 bytes)
//          public key pk (CRYPTO_PUBLICKEYBYTES = 197 bytes)
int OQS_KEM_sike_p503_1cca_compressed_keypair(unsigned char *pk, unsigned char *sk);

// SIKE's encapsulation
// Input:   public key pk         (CRYPTO_PUBLICKEYBYTES = 197 bytes)
// Outputs: shared secret ss      (CRYPTO_BYTES = 16 bytes)
//          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = 236 bytes)
int OQS_KEM_sike_p503_1cca_compressed_encaps(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int OQS_KEM_sike_p503_1cca_compressed_encaps_async(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int OQS_KEM_sike_p503_1cca_compressed_encaps_ciphertext(unsigned char *ct, unsigned char *ephemeralsk, const unsigned char *pk);
int OQS_KEM_sike_p503_1cca_compressed_shared_secret(unsigned char *ss, const unsigned char *ct, const char *ephemeralsk, const unsigned char *pk);

// SIKE's decapsulation
// Input:   secret key sk         (CRYPTO_SECRETKEYBYTES = 350 bytes)
//          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = 236 bytes)
// Outputs: shared secret ss      (CRYPTO_BYTES = 16 bytes)
int OQS_KEM_sike_p503_1cca_compressed_decaps(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

// Encoding of keys for KEM-based isogeny system "SIKEp503_compressed" (wire format):
// ---------------------------------------------------------------------------------
// Elements over GF(p503) are encoded in 55 octets in little endian format (i.e., the least significant octet is located in the lowest memory address).
// Elements (a+b*i) over GF(p503^2), where a and b are defined over GF(p503), are encoded as {a, b}, with a in the lowest memory portion.
//
// Private keys sk consist of the concatenation of a 16-byte random value, a value in the range [0, 2^216-1] and the public key pk. In the SIKE API,
// private keys are encoded in 350 octets in little endian format.
// Public keys pk consist of 3 values of length OBOB_BITS, one element in GF(p503^2) and 2 bytes. In the SIKE API, pk is encoded in 197 octets.
// Ciphertexts ct consist of the concatenation of 3 values of length OALICE_BITS, one element in GF(p503^2), 2 bytes and a 16-byte value. In the SIKE API,
// ct is encoded in 4*27 + 110 + 2 + 16 = 236 octets.
// Shared keys ss consist of a value of 16 octets.

#endif
