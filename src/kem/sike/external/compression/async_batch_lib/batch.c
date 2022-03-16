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

#include <string.h>
#include <stdint.h>

#include "batch.h"

#include <pthread.h>

#define BATCH_SIZE 10

static void *crypto_kem_async_batch_filler_routine(void *arg);
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

static void *zalloc(size_t size){
  void *ptr = malloc(size);
  if(ptr == NULL) return NULL;
  return memset(ptr, 0, size);
}

static pthread_mutex_t global_mut = PTHREAD_MUTEX_INITIALIZER; 
static struct {
    int ref_count;

    BATCH_CTX *ctx;
} crypto_kem_async_batch_global_ctx = {0, NULL};

/* Returns 0 on success, 1 otherwise */
static int crypto_kem_async_batch_keypair(unsigned char *pk,
                                                   unsigned char *sk,
                                                   unsigned n) {
  unsigned i;

  for (i = 0; i < n; i++) {
    int ret;
    ret = crypto_kem_keypair(pk + i * CRYPTO_PUBLICKEYBYTES,
                             sk + i * CRYPTO_SECRETKEYBYTES);
    if (ret != 0) {
      return 1;
    }
  }

  return 0;
}

static inline
int BATCH_STORE_fill(BATCH_STORE *store, size_t batch_size)
{
    int (*crypto_kem_batch_keygen_fn)(unsigned char *pk, unsigned char *sk, unsigned n) = crypto_kem_async_batch_keypair;
    
    if (crypto_kem_batch_keygen_fn(store->pks, store->sks, batch_size) == 0) { // success
        store->available = batch_size;
        return 0;
    }
    return 1;
}

static inline
BATCH_STORE *BATCH_STORE_new(size_t batch_size)
{
    int ok = 0;
    BATCH_STORE *store = NULL;
    size_t data_size = 0, sks_len = 0, pks_len = 0;

    pks_len = batch_size * CRYPTO_PUBLICKEYBYTES;
    sks_len = batch_size * CRYPTO_SECRETKEYBYTES;
    data_size = pks_len + sks_len;

    if (data_size <= 0
            || NULL == (store = zalloc(sizeof(*store)+data_size)))
        goto end;

    store->data_size = data_size;
    store->pks = &(store->_data[0]);
    store->sks = &(store->_data[pks_len]);
/*
    if (BATCH_STORE_fill(store, batch_size))
        goto end;*/

    ok = 1;

 end:
    if (!ok) {
        OQS_MEM_insecure_free(store);
        store = NULL;
    }
    return store;
}

static inline
void BATCH_STORE_free(BATCH_STORE *store)
{
    size_t data_size = 0;

    if (store == NULL)
        return;

    data_size = store->data_size;

    OQS_MEM_secure_free(store, sizeof(*store) + data_size);
}

static inline
BATCH_CTX *BATCH_CTX_new(void)
{
    int i;
    int ok = 0;
    size_t batch_size = 0;
    BATCH_CTX *ctx = NULL;

    if (NULL == (ctx = zalloc(sizeof(*ctx))))
        goto err;

    batch_size = ctx->batch_size = BATCH_SIZE;

    if (batch_size == 0)
        goto err;

    if (pthread_mutex_init(&ctx->mutex, NULL)
            || pthread_cond_init(&ctx->emptied, NULL)
            || pthread_cond_init(&ctx->filled, NULL))
        goto err;
    for (i = 0; i < BATCH_STORE_N; i++) {
        if (NULL == (ctx->stores[i] = BATCH_STORE_new(batch_size)))
            goto err;
    }

    if (pthread_create(&ctx->filler_th, NULL,
                &crypto_kem_async_batch_filler_routine, (void*)ctx)) {
        goto err;
    }

    pthread_mutex_lock(&ctx->mutex);

    while (ctx->store == NULL) {
        pthread_cond_wait(&ctx->filled, &ctx->mutex);
    }


    pthread_mutex_unlock(&ctx->mutex);

    ok = 1;

 err:
    if (!ok) {
        for (i=0; i<BATCH_STORE_N; i++) {
            BATCH_STORE_free(ctx->stores[i]);
        }
        if (pthread_cond_destroy(&ctx->filled)) {
            fprintf(stderr, "Failed destroying filled cond\n");
        }
        if (pthread_cond_destroy(&ctx->emptied)) {
            fprintf(stderr, "Failed destroying emptied cond\n");
        }
        if (pthread_mutex_destroy(&ctx->mutex)) {
            fprintf(stderr, "Failed destroying mutex\n");
        }
        OQS_MEM_insecure_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

static inline
void BATCH_CTX_free(BATCH_CTX *ctx)
{
    /* This should be called while holding the parent lock */
    void *tret;
    int i;

    if (ctx == NULL)
        return;


    pthread_mutex_lock(&ctx->mutex);

    ctx->destroy = 1;
    ctx->store = NULL;

    pthread_cond_signal(&ctx->emptied);

    pthread_mutex_unlock(&ctx->mutex);

    if (pthread_join(ctx->filler_th, &tret)) {
        fprintf(stderr, "pthread_join() failed\n");
    } else {
        intptr_t ret = (intptr_t)tret;
        if (ret != 0)
            fprintf(stderr, "filler thread returned %" PRIxPTR "\n", ret);
    }

    for (i=0; i<BATCH_STORE_N; i++) {
        BATCH_STORE_free(ctx->stores[i]);
    }

    if (pthread_cond_destroy(&ctx->filled)
            || pthread_cond_destroy(&ctx->emptied)
            || pthread_mutex_destroy(&ctx->mutex))
        fprintf(stderr, "failure destroying cond or mutex\n");

    OQS_MEM_insecure_free(ctx);
}

static inline
int BATCH_STORE_get_keypair(BATCH_STORE *store, KEM_KEYPAIR *kp)
{
    int ret = 1;
    size_t i;

    if (store->available == 0) {
        /* This branch should never be taken */
        return 1;
    }
    i = --store->available;

    memcpy(kp->pk, store->pks + i * CRYPTO_PUBLICKEYBYTES, CRYPTO_PUBLICKEYBYTES);
    memcpy(kp->sk, store->sks + i * CRYPTO_SECRETKEYBYTES, CRYPTO_SECRETKEYBYTES);

    /* Erase keypair from buffer for PFS */
    OQS_MEM_cleanse(store->sks + i * CRYPTO_SECRETKEYBYTES, CRYPTO_SECRETKEYBYTES);
    OQS_MEM_cleanse(store->pks + i * CRYPTO_PUBLICKEYBYTES, CRYPTO_PUBLICKEYBYTES);

    if (store->available == 0) {
        /*
         * We took the last key!
         */
        ret = -1;
    } else {
        ret = 0;
    }

    return ret;
}

static inline
int BATCH_CTX_get_keypair(BATCH_CTX *ctx, KEM_KEYPAIR *kp)
{
    int ret = 1, r;

    pthread_mutex_lock(&ctx->mutex);

    while (ctx->store == NULL) {
        pthread_cond_wait(&ctx->filled, &ctx->mutex);
    }

    r = BATCH_STORE_get_keypair(ctx->store, kp);
    if (r == -1) {
        /*
         * The store has been emptied.
         */
        ctx->store = NULL;

        pthread_cond_signal(&ctx->emptied);
    } else if (r != 0) {
        goto end;
    }

    ret = 0;
 end:
    pthread_mutex_unlock(&ctx->mutex);

    return ret;
}


static
int crypto_kem_async_batch_get_keypair(KEM_KEYPAIR *kp)
{
    BATCH_CTX *ctx = NULL;

    int err;

    /* This is always called only internally, assume kp is valid */

    if ((err = pthread_mutex_lock(&global_mut)) != 0) {
        //fprintf(stderr, "keypair %d", err);
        return 1;
    }
    if (crypto_kem_async_batch_global_ctx.ctx == NULL) {
        ctx = crypto_kem_async_batch_global_ctx.ctx = BATCH_CTX_new();
        if (ctx == NULL)
            return 1;
    } else {
        ctx = crypto_kem_async_batch_global_ctx.ctx;
    }
    if (pthread_mutex_unlock(&global_mut) != 0) {
        return 1;
    }

    if (BATCH_CTX_get_keypair(ctx, kp)) {
        return 1;
    }

    return 0;
}

int crypto_kem_async_batch_init(void)
{
    BATCH_CTX *ctx = NULL;

    if (pthread_mutex_lock(&global_mut) != 0) {
        return 1;
    }

    crypto_kem_async_batch_global_ctx.ref_count++;

    if (crypto_kem_async_batch_global_ctx.ctx == NULL) {
        ctx = crypto_kem_async_batch_global_ctx.ctx = BATCH_CTX_new();
        if (ctx == NULL)
            return 1;
    } else {
        ctx = crypto_kem_async_batch_global_ctx.ctx;
    }

    if (pthread_mutex_unlock(&global_mut) != 0) {
        return 1;
    }
    
    return 0;
}

/**
 * Should be called at the very end of the process, global deinitialization.
 */
int crypto_kem_async_batch_deinit(void)
{
    if (pthread_mutex_lock(&global_mut) != 0) {
        return 1;
    }

    crypto_kem_async_batch_global_ctx.ref_count--;

    // if (crypto_kem_async_batch_global_ctx.ref_count == 0) {
        BATCH_CTX_free(crypto_kem_async_batch_global_ctx.ctx);
        if (pthread_mutex_unlock(&global_mut) != 0) {
            return 1;
        }
    // } else {
    //     if (pthread_mutex_unlock(&global_mut) != 0) {
    //         return 1;
    //     }
    // }

    return 0;
}

static inline
int crypto_kem_async_batch_filler(BATCH_CTX *ctx)
{
    int ret = 1;
    int i, j;
    // int nid = ctx->nid_data->nid;
    //int nid = 0;
    size_t batch_size = ctx->batch_size;
    BATCH_STORE *q[BATCH_STORE_N] = { NULL };


    while (1) {
        pthread_mutex_lock(&ctx->mutex);

        while (ctx->store != NULL && ctx->destroy != 1) {
            pthread_cond_wait(&ctx->emptied, &ctx->mutex);
        }

        if (ctx->destroy) {
            break;
        }

        /* assert(ctx->store == NULL); */

        for (i = 0, j = 0; i < BATCH_STORE_N; i++) {
            if (ctx->stores[i]->available == 0) {
                q[j++] = ctx->stores[i];
            } else {
                ctx->store = ctx->stores[i];
            }
        }

        if (ctx->store != NULL) {
            pthread_cond_broadcast(&ctx->filled);
        }

        pthread_mutex_unlock(&ctx->mutex);

        for (--j; j >= 0; j--) {
            if (BATCH_STORE_fill(q[j], batch_size)) {
                goto end;
            }
            q[j] = NULL;
        }
    }

    pthread_mutex_unlock(&ctx->mutex);

    ret = 0;

 end:
    return ret;
}

static
void *crypto_kem_async_batch_filler_routine(void *arg)
{
    intptr_t ret;
    BATCH_CTX *ctx = arg;

    ret = (intptr_t) crypto_kem_async_batch_filler(ctx);

    return (void*)ret;
}
