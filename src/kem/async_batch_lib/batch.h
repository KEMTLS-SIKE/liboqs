/*
 *  engNTRU - An engine for batch NTRU Prime PQC in OpenSSL.
 *  Copyright (C) 2019 Tampere University Foundation sr
 *
 *  This file is part of engNTRU.
 *
 *  engNTRU is free software: you can redistribute it and/or modify it under
 *  the terms of the GNU Lesser General Public License as published by the
 *  Free Software Foundation, either version 3 of the License, or (at your
 *  option) any later version.
 *
 *  engNTRU is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef PROVIDER_BATCH_H
#define PROVIDER_BATCH_H

#include <pthread.h>
#include <openssl/crypto.h>

#include <oqs/kem.h>

typedef struct batch_ctx_st BATCH_CTX;
typedef struct batch_store_st BATCH_STORE;
typedef struct kem_keypair KEM_KEYPAIR;

#define BATCH_STORE_N 2
struct kem_keypair {
    uint8_t *pk;
    uint8_t *sk;
} /* optional variable list */;

struct batch_ctx_st {
    size_t batch_size;

    BATCH_STORE *store;

    pthread_mutex_t mutex;

    pthread_cond_t emptied;
    pthread_cond_t filled;

    pthread_t filler_th;

    char destroy;

    BATCH_STORE *stores[BATCH_STORE_N];

    // KEM name, used as unique identifier to fail in case batch key generation is initiated with one kem, then called with another
	const char *method_name;
    int (*crypto_keypair) (unsigned char *pk, unsigned char *sk);
    int publickey_size;
    int privatekey_size;
};

struct batch_store_st {
    size_t available;
    size_t data_size;

    unsigned char *pks;
    unsigned char *sks;

    unsigned char _data[];
};

int crypto_kem_async_batch_init(const OQS_KEM* kem);
int crypto_kem_async_batch_deinit(void);
int crypto_kem_async_batch_get_keypair(const OQS_KEM* kem, KEM_KEYPAIR *kp);
int crypto_kem_async_batch_get_keypair_B(const OQS_KEM* kem, KEM_KEYPAIR *kp);

#endif /* !defined(PROVIDER_BATCH_H) */

