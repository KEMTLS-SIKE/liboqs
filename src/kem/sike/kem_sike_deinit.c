// SPDX-License-Identifier: MIT

#include <oqs/kem_sike.h>
#include <oqs/kem_sike_deinit.h>

/**
 * Unitializes all sike async threads.
 */
OQS_API void OQS_KEM_sike_deinit(void) {
#ifdef OQS_ENABLE_KEM_sike_p434_compressed
  OQS_KEM_sike_p434_compressed_async_deinit();
#endif

#ifdef OQS_ENABLE_KEM_sike_p503_compressed
  OQS_KEM_sike_p503_compressed_async_deinit();
#endif

#ifdef OQS_ENABLE_KEM_sike_p610_compressed
  OQS_KEM_sike_p610_compressed_async_deinit();
#endif

#ifdef OQS_ENABLE_KEM_sike_p751_compressed
  OQS_KEM_sike_p751_compressed_async_deinit();
#endif

#ifdef OQS_ENABLE_KEM_sike_p434_1cca_compressed
  OQS_KEM_sike_p434_1cca_compressed_async_deinit();
#endif

#ifdef OQS_ENABLE_KEM_sike_p503_1cca_compressed
  OQS_KEM_sike_p503_1cca_compressed_async_deinit();
#endif

#ifdef OQS_ENABLE_KEM_sike_p610_compressed
  OQS_KEM_sike_p610_1cca_compressed_async_deinit();
#endif

#ifdef OQS_ENABLE_KEM_sike_p751_1cca_compressed
  OQS_KEM_sike_p751_1cca_compressed_async_deinit();
#endif

  return;
}