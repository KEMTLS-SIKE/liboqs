/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: supersingular isogeny key encapsulation (SIKE) protocol using compression
*********************************************************************************************/ 

#include <string.h>
#include <unistd.h>
#include <oqs/common.h>
#include <oqs/sha3.h>

#include "./async_batch_lib/batch.c"

int crypto_kem_keypair_async(unsigned char *pk, unsigned char *sk)
{
  KEM_KEYPAIR kp;
  kp.pk = pk;
  kp.sk = sk;
  //crypto_kem_async_batch_init();
  //fprintf(stderr, "End INIT %d\n");
  //sleep(1);
  crypto_kem_async_batch_get_keypair(&kp);
  return 0;
}
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{ // SIKE's key generation using compression
  // Outputs: secret key sk (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_A_BYTES + CRYPTO_PUBLICKEYBYTES + FP2_ENCODED_BYTES bytes)
  //          public key pk_comp (CRYPTO_PUBLICKEYBYTES bytes) 

  // Generate lower portion of secret key sk <- s||SK
  OQS_randombytes(sk, MSG_BYTES);   
  random_mod_order_A(sk + MSG_BYTES);    // Even random number

  // Generate public key pk
  EphemeralKeyGeneration_A_extended(sk + MSG_BYTES, pk);

  // Append public key pk to secret key sk
  memcpy(&sk[MSG_BYTES + SECRETKEY_A_BYTES], pk, CRYPTO_PUBLICKEYBYTES);

  return 0;
}


int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{ // 1-CCA SIKE's encapsulation using compression
  // Input:   public key pk              (CRYPTO_PUBLICKEYBYTES bytes)
  // Outputs: shared secret ss           (CRYPTO_BYTES bytes)
  //          ciphertext message ct      (CRYPTO_CIPHERTEXTBYTES = PARTIALLY_COMPRESSED_CHUNK_CT + MSG_BYTES bytes)
  unsigned char ephemeralsk[SECRETKEY_B_BYTES] = {0};
  unsigned char jinvariant[FP2_ENCODED_BYTES] = {0};
  unsigned char temp[FP2_ENCODED_BYTES + PARTIALLY_COMPRESSED_CHUNK_CT] = {0};
  KEM_KEYPAIR kp;

  // Encrypt: generate an ephemeral keypair (a, g^a)
  kp.pk = ct;
  kp.sk = ephemeralsk;

  crypto_kem_async_batch_get_keypair_B(&kp);

  // Compute ephemeral shared secret with other peer g^{ab}
  EphemeralSecretAgreement_B(ephemeralsk, pk, jinvariant);  

  // Generate shared secret ss <- H(g^{ab}||b)
  memcpy(temp, jinvariant, FP2_ENCODED_BYTES);
  memcpy(&temp[FP2_ENCODED_BYTES], ct, PARTIALLY_COMPRESSED_CHUNK_CT);      
  OQS_SHA3_shake256(ss, CRYPTO_BYTES, temp, PARTIALLY_COMPRESSED_CHUNK_CT + FP2_ENCODED_BYTES);

  return 0;
}

int crypto_kem_enc_ciphertext(unsigned char *ct, unsigned char *ephemeralsk, [[maybe_unused]] const unsigned char *pk)
{ // 1-CCA SIKE's encapsulation using compression
  // Input:   public key pk              (CRYPTO_PUBLICKEYBYTES bytes)
  // Outputs: ephemeral secret ss        (SECRETKEY_B_BYTES bytes)
  //          ciphertext message ct      (CRYPTO_CIPHERTEXTBYTES = PARTIALLY_COMPRESSED_CHUNK_CT + MSG_BYTES bytes)
  KEM_KEYPAIR kp;

  // Encrypt: generate an ephemeral keypair (a, g^a)
  kp.pk = ct;
  kp.sk = ephemeralsk;

  crypto_kem_async_batch_get_keypair_B(&kp);

  return 0;
}

int crypto_kem_enc_shared_secret(unsigned char *ss, const unsigned char *ct, const char *ephemeralsk, const unsigned char *pk)
{ // 1-CCA SIKE's encapsulation using compression
  // Input:   public key pk              (CRYPTO_PUBLICKEYBYTES bytes)
  //          ephemeral secret ss        (SECRETKEY_B_BYTES bytes)
  //          ciphertext message ct      (CRYPTO_CIPHERTEXTBYTES = PARTIALLY_COMPRESSED_CHUNK_CT + MSG_BYTES bytes)
  // Outputs: shared secret ss           (CRYPTO_BYTES bytes)
  unsigned char jinvariant[FP2_ENCODED_BYTES] = {0};
  unsigned char temp[FP2_ENCODED_BYTES + PARTIALLY_COMPRESSED_CHUNK_CT] = {0};

  // Compute ephemeral shared secret with other peer g^{ab}
  EphemeralSecretAgreement_B(ephemeralsk, pk, jinvariant);  

  // Generate shared secret ss <- H(g^{ab}||b)
  memcpy(temp, jinvariant, FP2_ENCODED_BYTES);
  memcpy(&temp[FP2_ENCODED_BYTES], ct, PARTIALLY_COMPRESSED_CHUNK_CT);      
  OQS_SHA3_shake256(ss, CRYPTO_BYTES, temp, PARTIALLY_COMPRESSED_CHUNK_CT + FP2_ENCODED_BYTES);

  return 0;
}

struct async_enc_keygen_b_arg {
  unsigned char *ephemeralsk;
  unsigned char *ct;
};


  static
void *async_enc_keygen_b(void *arg)
{
  struct async_enc_keygen_b_arg *params = arg;

  EphemeralKeyGeneration_B_extended(params->ephemeralsk, params->ct, 0);

  return NULL;
}

int crypto_kem_enc_parallel(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{ // SIKE's encapsulation using compression
  // Input:   public key pk              (CRYPTO_PUBLICKEYBYTES bytes)
  // Outputs: shared secret ss           (CRYPTO_BYTES bytes)
  //          ciphertext message ct      (CRYPTO_CIPHERTEXTBYTES = PARTIALLY_COMPRESSED_CHUNK_CT + MSG_BYTES bytes)
  unsigned char ephemeralsk[SECRETKEY_B_BYTES] = {0};
  unsigned char jinvariant[FP2_ENCODED_BYTES] = {0};
  unsigned char temp[FP2_ENCODED_BYTES + PARTIALLY_COMPRESSED_CHUNK_CT] = {0};

  // Generate ephemeralsk <- G(m||pk) mod oB 
  random_mod_order_B(ephemeralsk);

  // Encrypt: generate an ephemeral keypair (a, g^a)
  pthread_t async_enc_keygen_b_th;
  struct async_enc_keygen_b_arg arg1 = {ephemeralsk, ct};
  if (pthread_create(&async_enc_keygen_b_th, NULL,
	&async_enc_keygen_b, (void*)&arg1)) {
    fprintf(stderr, "pthread_create() failed\n");
    return 1;
  }

  // Compute ephemeral shared secret with other peer g^{ab}
  EphemeralSecretAgreement_B(ephemeralsk, pk, jinvariant);
  
  if (pthread_join(async_enc_keygen_b_th, NULL)) { // || pthread_join(async_enc_secret_agreement_th, NULL)) {
    fprintf(stderr, "pthread_join() failed\n");
    return 1;
  }

  // Generate shared secret ss <- H(g^{ab}||b)
  memcpy(temp, jinvariant, FP2_ENCODED_BYTES);
  memcpy(&temp[FP2_ENCODED_BYTES], ct, PARTIALLY_COMPRESSED_CHUNK_CT);      
  OQS_SHA3_shake256(ss, CRYPTO_BYTES, temp, PARTIALLY_COMPRESSED_CHUNK_CT + FP2_ENCODED_BYTES);

  return 0;
}

int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{ // SIKE's decapsulation using compression 
  // Input:   secret key sk                         (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_A_BYTES + CRYPTO_PUBLICKEYBYTES + FP2_ENCODED_BYTES bytes)
  //          compressed ciphertext message ct      (CRYPTO_CIPHERTEXTBYTES = PARTIALLY_COMPRESSED_CHUNK_CT + MSG_BYTES bytes) 
  // Outputs: shared secret ss                      (CRYPTO_BYTES bytes)
  unsigned char jinvariant_[FP2_ENCODED_BYTES + 2*FP2_ENCODED_BYTES + SECRETKEY_A_BYTES] = {0};
  unsigned char temp[FP2_ENCODED_BYTES+PARTIALLY_COMPRESSED_CHUNK_CT] = {0};

  // Decrypt: ct = g^b
  // Compute ephemeral shared secret jinvariant_ = g^{ab} from g^b and a
  EphemeralSecretAgreement_A_extended(sk + MSG_BYTES, ct, jinvariant_, 0);  

  // Compute shared secret: H(g^{ab}||b) with jinvariant_ = g^{ab} and b retrieved from ciphertext
  // No need to reencrypt as we provide only 1-CCA security
  memcpy(temp, jinvariant_, FP2_ENCODED_BYTES);
  memcpy(&temp[FP2_ENCODED_BYTES], ct, PARTIALLY_COMPRESSED_CHUNK_CT);
  OQS_SHA3_shake256(ss, CRYPTO_BYTES, temp, PARTIALLY_COMPRESSED_CHUNK_CT + FP2_ENCODED_BYTES);

  return 0;
}

