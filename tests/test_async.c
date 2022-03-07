#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>


static OQS_STATUS test_sike_async(void) {
#ifndef OQS_ENABLE_KEM_sike_p434_compressed // if FrodoKEM-640-AES was not enabled at compile-time
  printf("[example_stack] OQS_KEM_sike_p434_compressed was not enabled at "
      "compile-time.\n");
  return OQS_ERROR;
#else
  long start, end;
  struct timeval timecheck;


  uint8_t public_key[OQS_KEM_sike_p610_compressed_length_public_key];
  uint8_t secret_key[OQS_KEM_sike_p610_compressed_length_secret_key];
  OQS_STATUS rc;
  //sleep(1);
  gettimeofday(&timecheck, NULL);
  start = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;
  int err = OQS_KEM_sike_p610_compressed_async_init();
  gettimeofday(&timecheck, NULL);
  end = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;
  fprintf(stderr, "Init returned: %d\n", err);
  printf("%ld milliseconds elapsed\n", (end - start));

  gettimeofday(&timecheck, NULL);
  start = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;

  for (int i = 0; i < 30; i++) {
    rc = OQS_KEM_sike_p610_compressed_keypair_async(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
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
  return 0;
}
