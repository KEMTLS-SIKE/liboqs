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

typedef struct batch_ctx_st BATCH_CTX;
typedef struct batch_store_st BATCH_STORE;
typedef struct kem_keypair KEM_KEYPAIR;

#define BATCH_STORE_N 2
struct kem_keypair {
    uint8_t *pk;
    uint8_t *sk;
} /* optional variable list */;

struct batch_ctx_st {
    const struct engntru_kem_nid_data_st *nid_data;
    size_t batch_size;

    BATCH_STORE *store;

    pthread_mutex_t mutex;

    pthread_cond_t emptied;
    pthread_cond_t filled;

    pthread_t filler_th;

    char destroy;

    BATCH_STORE *stores[BATCH_STORE_N];
    int key_gen_b; 
};

struct batch_store_st {
    size_t available;
    size_t data_size;

    unsigned char *pks;
    unsigned char *sks;

    unsigned char _data[];
};

#endif /* !defined(PROVIDER_BATCH_H) */

