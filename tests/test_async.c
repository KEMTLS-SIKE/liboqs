#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>


void print_hex(uint8_t* str, size_t len){
  for(size_t i = 0; i < len; ++i){
    printf("%2x", str[i]);
  }
  printf("\n");
}
OQS_STATUS test_sike_async(void) {
#ifndef OQS_ENABLE_KEM_sike_p751_compressed // if FrodoKEM-640-AES was not enabled at compile-time
  printf("[example_stack] OQS_KEM_sike_p751_compressed was not enabled at "
      "compile-time.\n");
  return OQS_ERROR;
#else
  long start, end;
  struct timeval timecheck;


  uint8_t public_key[OQS_KEM_sike_p751_1cca_compressed_length_public_key];
  uint8_t secret_key[OQS_KEM_sike_p751_1cca_compressed_length_secret_key];
  uint8_t ciphertext[OQS_KEM_sike_p751_1cca_compressed_length_ciphertext];
  uint8_t shared_secret_e[OQS_KEM_sike_p751_1cca_compressed_length_shared_secret];
  uint8_t shared_secret_d[OQS_KEM_sike_p751_1cca_compressed_length_shared_secret];
  int cmp;
  OQS_STATUS rc;
  //sleep(1);
  gettimeofday(&timecheck, NULL);
  start = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;
  int err = OQS_KEM_sike_p751_1cca_compressed_async_init();
  gettimeofday(&timecheck, NULL);
  end = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;
  fprintf(stderr, "Init returned: %d\n", err);
  printf("%ld milliseconds elapsed\n", (end - start));

    rc = OQS_KEM_sike_p751_1cca_compressed_keypair_async(public_key, secret_key);
    rc = OQS_KEM_sike_p751_1cca_compressed_encaps(ciphertext, shared_secret_e, public_key);
    rc = OQS_KEM_sike_p751_1cca_compressed_decaps(shared_secret_d, ciphertext, secret_key);
    cmp = memcmp(shared_secret_e, shared_secret_d, OQS_KEM_sike_p751_1cca_compressed_length_shared_secret);
  gettimeofday(&timecheck, NULL);
  start = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;

  for (int i = 0; i < 100; i++) {
    rc = OQS_KEM_sike_p751_1cca_compressed_keypair_async(public_key, secret_key);
    rc = OQS_KEM_sike_p751_1cca_compressed_encaps_async(ciphertext, shared_secret_e, public_key);
    rc = OQS_KEM_sike_p751_1cca_compressed_decaps(shared_secret_d, ciphertext, secret_key);
    cmp = memcmp(shared_secret_e, shared_secret_d, OQS_KEM_sike_p751_1cca_compressed_length_shared_secret);
    //print_hex(shared_secret_e, OQS_KEM_sike_p751_1cca_compressed_length_shared_secret);
    //print_hex(shared_secret_d, OQS_KEM_sike_p751_1cca_compressed_length_shared_secret);

    /*
       for(int j=0; j < OQS_KEM_sike_p751_1cca_compressed_length_public_key; j++){
       fprintf(stderr, "%02x", public_key[j]);
       }
       fprintf(stderr, "\n");*/
    if (rc != OQS_SUCCESS || cmp != 0) {
      fprintf(stderr, "ERROR: OQS_KEM_frodokem_640_aes_keypair failed!\n");
      return OQS_ERROR;
    }
  }

  gettimeofday(&timecheck, NULL);
  end = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;
  printf("%ld milliseconds elapsed\n", (end - start));
  return OQS_SUCCESS;
#endif
}
int main(void)
{
  test_sike_async();
  fprintf(stderr, "Finished\n");
  int err = OQS_KEM_sike_p751_1cca_compressed_async_deinit();
  fprintf(stderr, "Deinit returned: %d\n", err);
  return 0;
}
