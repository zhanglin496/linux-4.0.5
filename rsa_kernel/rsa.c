/*
 *  The RSA public-key cryptosystem
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The following sources were referenced in the design of this implementation
 *  of the RSA algorithm:
 *
 *  [1] A method for obtaining digital signatures and public-key cryptosystems
 *      R Rivest, A Shamir, and L Adleman
 *      http://people.csail.mit.edu/rivest/pubs.html#RSA78
 *
 *  [2] Handbook of Applied Cryptography - 1997, Chapter 8
 *      Menezes, van Oorschot and Vanstone
 *
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_RSA_C)

#include "mbedtls/rsa.h"
#include "mbedtls/oid.h"

#include <linux/string.h>

#if defined(MBEDTLS_PKCS1_V21)
#include "mbedtls/md.h"
#endif

#if defined(MBEDTLS_PKCS1_V15) && !defined(__OpenBSD__)
//#include <stdlib.h>
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
//#include <stdio.h>
#define mbedtls_printf printf
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

/*
 * Initialize an RSA context
 */
void mbedtls_rsa_init( mbedtls_rsa_context *ctx,
               int padding,
               int hash_id )
{
    memset( ctx, 0, sizeof( mbedtls_rsa_context ) );

    mbedtls_rsa_set_padding( ctx, padding, hash_id );

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_init( &ctx->mutex );
#endif
}

/*
 * Set padding for an existing RSA context
 */
void mbedtls_rsa_set_padding( mbedtls_rsa_context *ctx, int padding, int hash_id )
{
    ctx->padding = padding;
    ctx->hash_id = hash_id;
}

#if defined(MBEDTLS_GENPRIME)

/*
 * Generate an RSA keypair
 */
int mbedtls_rsa_gen_key( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 unsigned int nbits, int exponent )
{
    int ret;
    mbedtls_mpi P1, Q1, H, G;

    if( f_rng == NULL || nbits < 128 || exponent < 3 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    mbedtls_mpi_init( &P1 ); mbedtls_mpi_init( &Q1 ); 
    mbedtls_mpi_init( &H ); mbedtls_mpi_init( &G );

    /*
     * find primes P and Q with Q < P so that:
     * GCD( E, (P-1)*(Q-1) ) == 1
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &ctx->E, exponent ) );

    do
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_gen_prime( &ctx->P, nbits >> 1, 0,
                                f_rng, p_rng ) );

        if( nbits % 2 )
        {
            MBEDTLS_MPI_CHK( mbedtls_mpi_gen_prime( &ctx->Q, ( nbits >> 1 ) + 1, 0,
                                f_rng, p_rng ) );
        }
        else
        {
            MBEDTLS_MPI_CHK( mbedtls_mpi_gen_prime( &ctx->Q, nbits >> 1, 0,
                                f_rng, p_rng ) );
        }

        if( mbedtls_mpi_cmp_mpi( &ctx->P, &ctx->Q ) == 0 )
            continue;

        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->N, &ctx->P, &ctx->Q ) );
        if( mbedtls_mpi_bitlen( &ctx->N ) != nbits )
            continue;

        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &P1, &ctx->P, 1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &Q1, &ctx->Q, 1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &H, &P1, &Q1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_gcd( &G, &ctx->E, &H  ) );
    }
    while( mbedtls_mpi_cmp_int( &G, 1 ) != 0 );

    /*
     * D  = E^-1 mod ((P-1)*(Q-1))
     * DP = D mod (P - 1)
     * DQ = D mod (Q - 1)
     * QP = Q^-1 mod P
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &ctx->D , &ctx->E, &H  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->DP, &ctx->D, &P1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->DQ, &ctx->D, &Q1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &ctx->QP, &ctx->Q, &ctx->P ) );

    ctx->len = ( mbedtls_mpi_bitlen( &ctx->N ) + 7 ) >> 3;

cleanup:

    mbedtls_mpi_free( &P1 ); mbedtls_mpi_free( &Q1 ); mbedtls_mpi_free( &H ); mbedtls_mpi_free( &G );

    if( ret != 0 )
    {
        mbedtls_rsa_free( ctx );
        return( MBEDTLS_ERR_RSA_KEY_GEN_FAILED + ret );
    }

    return( 0 );
}

#endif /* MBEDTLS_GENPRIME */

/*
 * Check a public RSA key
 */
int mbedtls_rsa_check_pubkey( const mbedtls_rsa_context *ctx )
{
    if( !ctx->N.p || !ctx->E.p )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

    if( ( ctx->N.p[0] & 1 ) == 0 ||
        ( ctx->E.p[0] & 1 ) == 0 )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

    if( mbedtls_mpi_bitlen( &ctx->N ) < 128 ||
        mbedtls_mpi_bitlen( &ctx->N ) > MBEDTLS_MPI_MAX_BITS )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

    if( mbedtls_mpi_bitlen( &ctx->E ) < 2 ||
        mbedtls_mpi_cmp_mpi( &ctx->E, &ctx->N ) >= 0 )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

    return( 0 );
}

/*
 * Check a private RSA key
 */
int mbedtls_rsa_check_privkey( const mbedtls_rsa_context *ctx )
{
    int ret;
    mbedtls_mpi PQ, DE, P1, Q1, H, I, G, G2, L1, L2, DP, DQ, QP;

    if( ( ret = mbedtls_rsa_check_pubkey( ctx ) ) != 0 )
        return( ret );

    if( !ctx->P.p || !ctx->Q.p || !ctx->D.p )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

    mbedtls_mpi_init( &PQ ); mbedtls_mpi_init( &DE ); mbedtls_mpi_init( &P1 ); mbedtls_mpi_init( &Q1 );
    mbedtls_mpi_init( &H  ); mbedtls_mpi_init( &I  ); mbedtls_mpi_init( &G  ); mbedtls_mpi_init( &G2 );
    mbedtls_mpi_init( &L1 ); mbedtls_mpi_init( &L2 ); mbedtls_mpi_init( &DP ); mbedtls_mpi_init( &DQ );
    mbedtls_mpi_init( &QP );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &PQ, &ctx->P, &ctx->Q ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &DE, &ctx->D, &ctx->E ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &P1, &ctx->P, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &Q1, &ctx->Q, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &H, &P1, &Q1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_gcd( &G, &ctx->E, &H  ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_gcd( &G2, &P1, &Q1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_div_mpi( &L1, &L2, &H, &G2 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &I, &DE, &L1  ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &DP, &ctx->D, &P1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &DQ, &ctx->D, &Q1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &QP, &ctx->Q, &ctx->P ) );
    /*
     * Check for a valid PKCS1v2 private key
     */
    if( mbedtls_mpi_cmp_mpi( &PQ, &ctx->N ) != 0 ||
        mbedtls_mpi_cmp_mpi( &DP, &ctx->DP ) != 0 ||
        mbedtls_mpi_cmp_mpi( &DQ, &ctx->DQ ) != 0 ||
        mbedtls_mpi_cmp_mpi( &QP, &ctx->QP ) != 0 ||
        mbedtls_mpi_cmp_int( &L2, 0 ) != 0 ||
        mbedtls_mpi_cmp_int( &I, 1 ) != 0 ||
        mbedtls_mpi_cmp_int( &G, 1 ) != 0 )
    {
        ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }

cleanup:
    mbedtls_mpi_free( &PQ ); mbedtls_mpi_free( &DE ); mbedtls_mpi_free( &P1 ); mbedtls_mpi_free( &Q1 );
    mbedtls_mpi_free( &H  ); mbedtls_mpi_free( &I  ); mbedtls_mpi_free( &G  ); mbedtls_mpi_free( &G2 );
    mbedtls_mpi_free( &L1 ); mbedtls_mpi_free( &L2 ); mbedtls_mpi_free( &DP ); mbedtls_mpi_free( &DQ );
    mbedtls_mpi_free( &QP );

    if( ret == MBEDTLS_ERR_RSA_KEY_CHECK_FAILED )
        return( ret );

    if( ret != 0 )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED + ret );

    return( 0 );
}

/*
 * Check if contexts holding a public and private key match
 */
int mbedtls_rsa_check_pub_priv( const mbedtls_rsa_context *pub, const mbedtls_rsa_context *prv )
{
    if( mbedtls_rsa_check_pubkey( pub ) != 0 ||
        mbedtls_rsa_check_privkey( prv ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    if( mbedtls_mpi_cmp_mpi( &pub->N, &prv->N ) != 0 ||
        mbedtls_mpi_cmp_mpi( &pub->E, &prv->E ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    return( 0 );
}

/*
 * Do an RSA public key operation
 */
int mbedtls_rsa_public( mbedtls_rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output )
{
    int ret;
    size_t olen;
    mbedtls_mpi T;

    mbedtls_mpi_init( &T );

#if defined(MBEDTLS_THREADING_C)
    if( ( ret = mbedtls_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &T, input, ctx->len ) );

    if( mbedtls_mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    olen = ctx->len;
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T, &T, &ctx->E, &ctx->N, &ctx->RN ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &T, output, olen ) );

cleanup:
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &ctx->mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif

    mbedtls_mpi_free( &T );

    if( ret != 0 )
        return( MBEDTLS_ERR_RSA_PUBLIC_FAILED + ret );

    return( 0 );
}

/*
 * Generate or update blinding values, see section 10 of:
 *  KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
 *  DSS, and other systems. In : Advances in Cryptology-CRYPTO'96. Springer
 *  Berlin Heidelberg, 1996. p. 104-113.
 */
static int rsa_prepare_blinding( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret, count = 0;

    if( ctx->Vf.p != NULL )
    {
        /* We already have blinding values, just update them by squaring */
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->Vi, &ctx->Vi, &ctx->Vi ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->Vi, &ctx->Vi, &ctx->N ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->Vf, &ctx->Vf, &ctx->Vf ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->Vf, &ctx->Vf, &ctx->N ) );

        goto cleanup;
    }

    /* Unblinding value: Vf = random number, invertible mod N */
    do {
        if( count++ > 10 )
            return( MBEDTLS_ERR_RSA_RNG_FAILED );

        MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &ctx->Vf, ctx->len - 1, f_rng, p_rng ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_gcd( &ctx->Vi, &ctx->Vf, &ctx->N ) );
    } while( mbedtls_mpi_cmp_int( &ctx->Vi, 1 ) != 0 );

    /* Blinding value: Vi =  Vf^(-e) mod N */
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &ctx->Vi, &ctx->Vf, &ctx->N ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &ctx->Vi, &ctx->Vi, &ctx->E, &ctx->N, &ctx->RN ) );


cleanup:
    return( ret );
}

/*
 * Do an RSA private key operation
 */
int mbedtls_rsa_private( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 const unsigned char *input,
                 unsigned char *output )
{
    int ret;
    size_t olen;
    mbedtls_mpi T, T1, T2;

    /* Make sure we have private key info, prevent possible misuse */
    if( ctx->P.p == NULL || ctx->Q.p == NULL || ctx->D.p == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    mbedtls_mpi_init( &T ); mbedtls_mpi_init( &T1 ); mbedtls_mpi_init( &T2 );

#if defined(MBEDTLS_THREADING_C)
    if( ( ret = mbedtls_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &T, input, ctx->len ) );
    if( mbedtls_mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    if( f_rng != NULL )
    {
        /*
         * Blinding
         * T = T * Vi mod N
         */
        MBEDTLS_MPI_CHK( rsa_prepare_blinding( ctx, f_rng, p_rng ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T, &T, &ctx->Vi ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &T, &T, &ctx->N ) );
    }

#if defined(MBEDTLS_RSA_NO_CRT)
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T, &T, &ctx->D, &ctx->N, &ctx->RN ) );
#else
    /*
     * faster decryption using the CRT
     *
     * T1 = input ^ dP mod P
     * T2 = input ^ dQ mod Q
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T1, &T, &ctx->DP, &ctx->P, &ctx->RP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T2, &T, &ctx->DQ, &ctx->Q, &ctx->RQ ) );

    /*
     * T = (T1 - T2) * (Q^-1 mod P) mod P
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &T, &T1, &T2 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T1, &T, &ctx->QP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &T, &T1, &ctx->P ) );

    /*
     * T = T2 + T * Q
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T1, &T, &ctx->Q ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &T, &T2, &T1 ) );
#endif /* MBEDTLS_RSA_NO_CRT */

    if( f_rng != NULL )
    {
        /*
         * Unblind
         * T = T * Vf mod N
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T, &T, &ctx->Vf ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &T, &T, &ctx->N ) );
    }

    olen = ctx->len;
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &T, output, olen ) );

cleanup:
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &ctx->mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif

    mbedtls_mpi_free( &T ); mbedtls_mpi_free( &T1 ); mbedtls_mpi_free( &T2 );

    if( ret != 0 )
        return( MBEDTLS_ERR_RSA_PRIVATE_FAILED + ret );

    return( 0 );
}

#if defined(MBEDTLS_PKCS1_V21)
/**
 * Generate and apply the MGF1 operation (from PKCS#1 v2.1) to a buffer.
 *
 * \param dst       buffer to mask
 * \param dlen      length of destination buffer
 * \param src       source of the mask generation
 * \param slen      length of the source buffer
 * \param md_ctx    message digest context to use
 */
static void mgf_mask( unsigned char *dst, size_t dlen, unsigned char *src,
                      size_t slen, mbedtls_md_context_t *md_ctx )
{
    unsigned char mask[MBEDTLS_MD_MAX_SIZE];
    unsigned char counter[4];
    unsigned char *p;
    unsigned int hlen;
    size_t i, use_len;

    memset( mask, 0, MBEDTLS_MD_MAX_SIZE );
    memset( counter, 0, 4 );

    hlen = mbedtls_md_get_size( md_ctx->md_info );

    // Generate and apply dbMask
    //
    p = dst;

    while( dlen > 0 )
    {
        use_len = hlen;
        if( dlen < hlen )
            use_len = dlen;

        mbedtls_md_starts( md_ctx );
        mbedtls_md_update( md_ctx, src, slen );
        mbedtls_md_update( md_ctx, counter, 4 );
        mbedtls_md_finish( md_ctx, mask );

        for( i = 0; i < use_len; ++i )
            *p++ ^= mask[i];

        counter[3]++;

        dlen -= use_len;
    }
}
#endif /* MBEDTLS_PKCS1_V21 */

#if defined(MBEDTLS_PKCS1_V21)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-ENCRYPT function
 */
int mbedtls_rsa_rsaes_oaep_encrypt( mbedtls_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t ilen,
                            const unsigned char *input,
                            unsigned char *output )
{
    size_t olen;
    int ret;
    unsigned char *p = output;
    unsigned int hlen;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;

    if( mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V21 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    if( f_rng == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    md_info = mbedtls_md_info_from_type( (mbedtls_md_type_t) ctx->hash_id );
    if( md_info == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;
    hlen = mbedtls_md_get_size( md_info );

    if( olen < ilen + 2 * hlen + 2 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    memset( output, 0, olen );

    *p++ = 0;

    // Generate a random octet string seed
    //
    if( ( ret = f_rng( p_rng, p, hlen ) ) != 0 )
        return( MBEDTLS_ERR_RSA_RNG_FAILED + ret );

    p += hlen;

    // Construct DB
    //
    mbedtls_md( md_info, label, label_len, p );
    p += hlen;
    p += olen - 2 * hlen - 2 - ilen;
    *p++ = 1;
    memcpy( p, input, ilen );

    mbedtls_md_init( &md_ctx );
    mbedtls_md_setup( &md_ctx, md_info, 0 );

    // maskedDB: Apply dbMask to DB
    //
    mgf_mask( output + hlen + 1, olen - hlen - 1, output + 1, hlen,
               &md_ctx );

    // maskedSeed: Apply seedMask to seed
    //
    mgf_mask( output + 1, hlen, output + hlen + 1, olen - hlen - 1,
               &md_ctx );

    mbedtls_md_free( &md_ctx );

    return( ( mode == MBEDTLS_RSA_PUBLIC )
            ? mbedtls_rsa_public(  ctx, output, output )
            : mbedtls_rsa_private( ctx, f_rng, p_rng, output, output ) );
}
#endif /* MBEDTLS_PKCS1_V21 */

#if defined(MBEDTLS_PKCS1_V15)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-ENCRYPT function
 */
int mbedtls_rsa_rsaes_pkcs1_v15_encrypt( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode, size_t ilen,
                                 const unsigned char *input,
                                 unsigned char *output )
{
    size_t nb_pad, olen;
    int ret;
    unsigned char *p = output;

    if( mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V15 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    // We don't check p_rng because it won't be dereferenced here
    if( f_rng == NULL || input == NULL || output == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;

    if( olen < ilen + 11 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    nb_pad = olen - 3 - ilen;

    *p++ = 0;
    if( mode == MBEDTLS_RSA_PUBLIC )
    {
        *p++ = MBEDTLS_RSA_CRYPT;

        while( nb_pad-- > 0 )
        {
            int rng_dl = 100;

            do {
                ret = f_rng( p_rng, p, 1 );
            } while( *p == 0 && --rng_dl && ret == 0 );

            // Check if RNG failed to generate data
            //
            if( rng_dl == 0 || ret != 0 )
                return( MBEDTLS_ERR_RSA_RNG_FAILED + ret );

            p++;
        }
    }
    else
    {
        *p++ = MBEDTLS_RSA_SIGN;

        while( nb_pad-- > 0 )
            *p++ = 0xFF;
    }

    *p++ = 0;
    memcpy( p, input, ilen );

    return( ( mode == MBEDTLS_RSA_PUBLIC )
            ? mbedtls_rsa_public(  ctx, output, output )
            : mbedtls_rsa_private( ctx, f_rng, p_rng, output, output ) );
}
#endif /* MBEDTLS_PKCS1_V15 */

/*
 * Add the message padding, then do an RSA operation
 */
int mbedtls_rsa_pkcs1_encrypt( mbedtls_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       int mode, size_t ilen,
                       const unsigned char *input,
                       unsigned char *output )
{
    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            return mbedtls_rsa_rsaes_pkcs1_v15_encrypt( ctx, f_rng, p_rng, mode, ilen,
                                                input, output );
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            return mbedtls_rsa_rsaes_oaep_encrypt( ctx, f_rng, p_rng, mode, NULL, 0,
                                           ilen, input, output );
#endif

        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
}

#if defined(MBEDTLS_PKCS1_V21)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-DECRYPT function
 */
int mbedtls_rsa_rsaes_oaep_decrypt( mbedtls_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t *olen,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t output_max_len )
{
    int ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    size_t ilen, i, pad_len;
    unsigned char *p, bad, pad_done;
    unsigned char *lhash;
    unsigned char *buf;
    unsigned int hlen;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;

    buf = mbedtls_malloc(MBEDTLS_MPI_MAX_SIZE*2);
    if (!buf)
	return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    lhash = buf + MBEDTLS_MPI_MAX_SIZE;

    /*
     * Parameters sanity checks
     */
    if( mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V21 )
        goto out;

    ilen = ctx->len;

    if( ilen < 16 || ilen > sizeof( buf ) )
        goto out;

    md_info = mbedtls_md_info_from_type( (mbedtls_md_type_t) ctx->hash_id );
    if( md_info == NULL )
        goto out;

    /*
     * RSA operation
     */
    ret = ( mode == MBEDTLS_RSA_PUBLIC )
          ? mbedtls_rsa_public(  ctx, input, buf )
          : mbedtls_rsa_private( ctx, f_rng, p_rng, input, buf );

    if( ret != 0 )
        goto out;

    /*
     * Unmask data and generate lHash
     */
    hlen = mbedtls_md_get_size( md_info );

    mbedtls_md_init( &md_ctx );
    mbedtls_md_setup( &md_ctx, md_info, 0 );

    /* Generate lHash */
    mbedtls_md( md_info, label, label_len, lhash );

    /* seed: Apply seedMask to maskedSeed */
    mgf_mask( buf + 1, hlen, buf + hlen + 1, ilen - hlen - 1,
               &md_ctx );

    /* DB: Apply dbMask to maskedDB */
    mgf_mask( buf + hlen + 1, ilen - hlen - 1, buf + 1, hlen,
               &md_ctx );

    mbedtls_md_free( &md_ctx );

    /*
     * Check contents, in "constant-time"
     */
    p = buf;
    bad = 0;

    bad |= *p++; /* First byte must be 0 */

    p += hlen; /* Skip seed */

    /* Check lHash */
    for( i = 0; i < hlen; i++ )
        bad |= lhash[i] ^ *p++;

    /* Get zero-padding len, but always read till end of buffer
     * (minus one, for the 01 byte) */
    pad_len = 0;
    pad_done = 0;
    for( i = 0; i < ilen - 2 * hlen - 2; i++ )
    {
        pad_done |= p[i];
        pad_len += ((pad_done | (unsigned char)-pad_done) >> 7) ^ 1;
    }

    p += pad_len;
    bad |= *p++ ^ 0x01;

    /*
     * The only information "leaked" is whether the padding was correct or not
     * (eg, no data is copied if it was not correct). This meets the
     * recommendations in PKCS#1 v2.2: an opponent cannot distinguish between
     * the different error conditions.
     */
    if( bad != 0 ) {
	 ret = MBEDTLS_ERR_RSA_INVALID_PADDING;
	 goto out;
    }

    if( ilen - ( p - buf ) > output_max_len ) {
	ret = MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
	goto out;
    }

    *olen = ilen - (p - buf);
    memcpy( output, p, *olen );
	ret = 0;

out:
    mbedtls_free(buf);
    return( ret );
}
#endif /* MBEDTLS_PKCS1_V21 */

#if defined(MBEDTLS_PKCS1_V15)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-DECRYPT function
 */
int mbedtls_rsa_rsaes_pkcs1_v15_decrypt( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode, size_t *olen,
                                 const unsigned char *input,
                                 unsigned char *output,
                                 size_t output_max_len)
{
    int error = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    int ret;
    size_t ilen, pad_count = 0, i;
    unsigned char *p, bad, pad_done = 0;
    unsigned char *buf = mbedtls_malloc(MBEDTLS_MPI_MAX_SIZE);
    if (!buf)
	return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    if( mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V15 )
        goto out;

    ilen = ctx->len;
    if( ilen < 16 || ilen > MBEDTLS_MPI_MAX_SIZE)
        goto out;
    
    ret = ( mode == MBEDTLS_RSA_PUBLIC )
          ? mbedtls_rsa_public(  ctx, input, buf )
          : mbedtls_rsa_private( ctx, f_rng, p_rng, input, buf );

    if( ret != 0 )
        goto out;

    p = buf;
    bad = 0;

    /*
     * Check and get padding len in "constant-time"
     */
    bad |= *p++; /* First byte must be 0 */

    /* This test does not depend on secret data */
    if( mode == MBEDTLS_RSA_PRIVATE )
    {
        bad |= *p++ ^ MBEDTLS_RSA_CRYPT;

        /* Get padding len, but always read till end of buffer
         * (minus one, for the 00 byte) */
        for( i = 0; i < ilen - 3; i++ )
        {
            pad_done  |= ((p[i] | (unsigned char)-p[i]) >> 7) ^ 1;
            pad_count += ((pad_done | (unsigned char)-pad_done) >> 7) ^ 1;
        }

        p += pad_count;
        bad |= *p++; /* Must be zero */
    }
    else
    {
        bad |= *p++ ^ MBEDTLS_RSA_SIGN;

        /* Get padding len, but always read till end of buffer
         * (minus one, for the 00 byte) */
        for( i = 0; i < ilen - 3; i++ )
        {
            pad_done |= ( p[i] != 0xFF );
            pad_count += ( pad_done == 0 );
        }

        p += pad_count;
        bad |= *p++; /* Must be zero */
    }

    if( bad ) {
        error = MBEDTLS_ERR_RSA_INVALID_PADDING;
	 goto out;
    }

    if( ilen - ( p - buf ) > output_max_len ) {
        error = MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
	 goto out;
    }

    *olen = ilen - (p - buf);
    memcpy( output, p, *olen );
    error  = 0;
	
out:
    mbedtls_free(buf);
    return( error );
}
#endif /* MBEDTLS_PKCS1_V15 */

/*
 * Do an RSA operation, then remove the message padding
 */
int mbedtls_rsa_pkcs1_decrypt( mbedtls_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       int mode, size_t *olen,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t output_max_len)
{
    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            return mbedtls_rsa_rsaes_pkcs1_v15_decrypt( ctx, f_rng, p_rng, mode, olen,
                                                input, output, output_max_len );
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            return mbedtls_rsa_rsaes_oaep_decrypt( ctx, f_rng, p_rng, mode, NULL, 0,
                                           olen, input, output,
                                           output_max_len );
#endif

        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
}

#if defined(MBEDTLS_PKCS1_V21)
/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-SIGN function
 */
int mbedtls_rsa_rsassa_pss_sign( mbedtls_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         int mode,
                         mbedtls_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         unsigned char *sig )
{
    size_t olen;
    unsigned char *p = sig;
    unsigned char salt[MBEDTLS_MD_MAX_SIZE];
    unsigned int slen, hlen, offset = 0;
    int ret;
    size_t msb;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;

    if( mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V21 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    if( f_rng == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;

    if( md_alg != MBEDTLS_MD_NONE )
    {
        // Gather length of hash to sign
        //
        md_info = mbedtls_md_info_from_type( md_alg );
        if( md_info == NULL )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

        hashlen = mbedtls_md_get_size( md_info );
    }

    md_info = mbedtls_md_info_from_type( (mbedtls_md_type_t) ctx->hash_id );
    if( md_info == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    hlen = mbedtls_md_get_size( md_info );
    slen = hlen;

    if( olen < hlen + slen + 2 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    memset( sig, 0, olen );

    // Generate salt of length slen
    //
    if( ( ret = f_rng( p_rng, salt, slen ) ) != 0 )
        return( MBEDTLS_ERR_RSA_RNG_FAILED + ret );

    // Note: EMSA-PSS encoding is over the length of N - 1 bits
    //
    msb = mbedtls_mpi_bitlen( &ctx->N ) - 1;
    p += olen - hlen * 2 - 2;
    *p++ = 0x01;
    memcpy( p, salt, slen );
    p += slen;

    mbedtls_md_init( &md_ctx );
    mbedtls_md_setup( &md_ctx, md_info, 0 );

    // Generate H = Hash( M' )
    //
    mbedtls_md_starts( &md_ctx );
    mbedtls_md_update( &md_ctx, p, 8 );
    mbedtls_md_update( &md_ctx, hash, hashlen );
    mbedtls_md_update( &md_ctx, salt, slen );
    mbedtls_md_finish( &md_ctx, p );

    // Compensate for boundary condition when applying mask
    //
    if( msb % 8 == 0 )
        offset = 1;

    // maskedDB: Apply dbMask to DB
    //
    mgf_mask( sig + offset, olen - hlen - 1 - offset, p, hlen, &md_ctx );

    mbedtls_md_free( &md_ctx );

    msb = mbedtls_mpi_bitlen( &ctx->N ) - 1;
    sig[0] &= 0xFF >> ( olen * 8 - msb );

    p += hlen;
    *p++ = 0xBC;

    return( ( mode == MBEDTLS_RSA_PUBLIC )
            ? mbedtls_rsa_public(  ctx, sig, sig )
            : mbedtls_rsa_private( ctx, f_rng, p_rng, sig, sig ) );
}
#endif /* MBEDTLS_PKCS1_V21 */

#if defined(MBEDTLS_PKCS1_V15)
/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-V1_5-SIGN function
 */
/*
 * Do an RSA operation to sign the message digest
 */
int mbedtls_rsa_rsassa_pkcs1_v15_sign( mbedtls_rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               int mode,
                               mbedtls_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               unsigned char *sig )
{
    size_t nb_pad, olen, oid_size = 0;
    unsigned char *p = sig;
    const char *oid = NULL;
    unsigned char *sig_try = NULL, *verif = NULL;
    size_t i;
    unsigned char diff;
    volatile unsigned char diff_no_optimize;
    int ret;

    if( mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V15 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;
    nb_pad = olen - 3;

    if( md_alg != MBEDTLS_MD_NONE )
    {
        const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type( md_alg );
        if( md_info == NULL )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

        if( mbedtls_oid_get_oid_by_md( md_alg, &oid, &oid_size ) != 0 )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

        nb_pad -= 10 + oid_size;

        hashlen = mbedtls_md_get_size( md_info );
    }

    nb_pad -= hashlen;

    if( ( nb_pad < 8 ) || ( nb_pad > olen ) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    *p++ = 0;
    *p++ = MBEDTLS_RSA_SIGN;
    memset( p, 0xFF, nb_pad );
    p += nb_pad;
    *p++ = 0;

    if( md_alg == MBEDTLS_MD_NONE )
    {
        memcpy( p, hash, hashlen );
    }
    else
    {
        /*
         * DigestInfo ::= SEQUENCE {
         *   digestAlgorithm DigestAlgorithmIdentifier,
         *   digest Digest }
         *
         * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
         *
         * Digest ::= OCTET STRING
         */
        *p++ = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;
        *p++ = (unsigned char) ( 0x08 + oid_size + hashlen );
        *p++ = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;
        *p++ = (unsigned char) ( 0x04 + oid_size );
        *p++ = MBEDTLS_ASN1_OID;
        *p++ = oid_size & 0xFF;
        memcpy( p, oid, oid_size );
        p += oid_size;
        *p++ = MBEDTLS_ASN1_NULL;
        *p++ = 0x00;
        *p++ = MBEDTLS_ASN1_OCTET_STRING;
        *p++ = hashlen;
        memcpy( p, hash, hashlen );
    }

    if( mode == MBEDTLS_RSA_PUBLIC )
        return( mbedtls_rsa_public(  ctx, sig, sig ) );

    /*
     * In order to prevent Lenstra's attack, make the signature in a
     * temporary buffer and check it before returning it.
     */
    sig_try = mbedtls_calloc( 1, ctx->len );
    if( sig_try == NULL )
        return( MBEDTLS_ERR_MPI_ALLOC_FAILED );

    verif   = mbedtls_calloc( 1, ctx->len );
    if( verif == NULL )
    {
        mbedtls_free( sig_try );
        return( MBEDTLS_ERR_MPI_ALLOC_FAILED );
    }

    MBEDTLS_MPI_CHK( mbedtls_rsa_private( ctx, f_rng, p_rng, sig, sig_try ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_public( ctx, sig_try, verif ) );

    /* Compare in constant time just in case */
    for( diff = 0, i = 0; i < ctx->len; i++ )
        diff |= verif[i] ^ sig[i];
    diff_no_optimize = diff;

    if( diff_no_optimize != 0 )
    {
        ret = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
        goto cleanup;
    }

    memcpy( sig, sig_try, ctx->len );

cleanup:
    mbedtls_free( sig_try );
    mbedtls_free( verif );

    return( ret );
}
#endif /* MBEDTLS_PKCS1_V15 */

/*
 * Do an RSA operation to sign the message digest
 */
int mbedtls_rsa_pkcs1_sign( mbedtls_rsa_context *ctx,
                    int (*f_rng)(void *, unsigned char *, size_t),
                    void *p_rng,
                    int mode,
                    mbedtls_md_type_t md_alg,
                    unsigned int hashlen,
                    const unsigned char *hash,
                    unsigned char *sig )
{
    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            return mbedtls_rsa_rsassa_pkcs1_v15_sign( ctx, f_rng, p_rng, mode, md_alg,
                                              hashlen, hash, sig );
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            return mbedtls_rsa_rsassa_pss_sign( ctx, f_rng, p_rng, mode, md_alg,
                                        hashlen, hash, sig );
#endif

        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
}

#if defined(MBEDTLS_PKCS1_V21)
/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-VERIFY function
 */
int mbedtls_rsa_rsassa_pss_verify_ext( mbedtls_rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               int mode,
                               mbedtls_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               mbedtls_md_type_t mgf1_hash_id,
                               int expected_salt_len,
                               const unsigned char *sig )
{
    int ret;
    int error = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    size_t siglen;
    unsigned char *p;
    unsigned char *result;
    unsigned char *buf;
    unsigned char zeros[8];
    unsigned int hlen;
    size_t slen, msb;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;

    buf = mbedtls_malloc(MBEDTLS_MPI_MAX_SIZE*2);
    if (!buf)
	return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    result = buf + MBEDTLS_MPI_MAX_SIZE;

    if( mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V21 )
        goto out;

    siglen = ctx->len;

    if( siglen < 16 || siglen > MBEDTLS_MPI_MAX_SIZE)
        goto out;

    ret = ( mode == MBEDTLS_RSA_PUBLIC )
          ? mbedtls_rsa_public(  ctx, sig, buf )
          : mbedtls_rsa_private( ctx, f_rng, p_rng, sig, buf );

    if( ret != 0 )
        goto out;

    p = buf;

    if( buf[siglen - 1] != 0xBC ) {
	error = MBEDTLS_ERR_RSA_INVALID_PADDING;
	goto out;
    }

    if( md_alg != MBEDTLS_MD_NONE )
    {
        // Gather length of hash to sign
        //
        md_info = mbedtls_md_info_from_type( md_alg );
        if( md_info == NULL )
            goto out;
        hashlen = mbedtls_md_get_size( md_info );
    }

    md_info = mbedtls_md_info_from_type( mgf1_hash_id );
    if( md_info == NULL )
        goto out;
    hlen = mbedtls_md_get_size( md_info );
    slen = siglen - hlen - 1; /* Currently length of salt + padding */

    memset( zeros, 0, 8 );

    // Note: EMSA-PSS verification is over the length of N - 1 bits
    //
    msb = mbedtls_mpi_bitlen( &ctx->N ) - 1;

    // Compensate for boundary condition when applying mask
    //
    if( msb % 8 == 0 )
    {
        p++;
        siglen -= 1;
    }
    if( buf[0] >> ( 8 - siglen * 8 + msb ) )
        goto out;

    mbedtls_md_init( &md_ctx );
    mbedtls_md_setup( &md_ctx, md_info, 0 );

    mgf_mask( p, siglen - hlen - 1, p + siglen - hlen - 1, hlen, &md_ctx );

    buf[0] &= 0xFF >> ( siglen * 8 - msb );

    while( p < buf + siglen && *p == 0 )
        p++;

    if( p == buf + siglen ||
        *p++ != 0x01 )
    {
        mbedtls_md_free( &md_ctx );
	error = MBEDTLS_ERR_RSA_INVALID_PADDING;
	goto out;
    }

    /* Actual salt len */
    slen -= p - buf;

    if( expected_salt_len != MBEDTLS_RSA_SALT_LEN_ANY &&
        slen != (size_t) expected_salt_len )
    {
        mbedtls_md_free( &md_ctx );
	error = MBEDTLS_ERR_RSA_INVALID_PADDING;
	goto out;
    }

    // Generate H = Hash( M' )
    //
    mbedtls_md_starts( &md_ctx );
    mbedtls_md_update( &md_ctx, zeros, 8 );
    mbedtls_md_update( &md_ctx, hash, hashlen );
    mbedtls_md_update( &md_ctx, p, slen );
    mbedtls_md_finish( &md_ctx, result );

    mbedtls_md_free( &md_ctx );

    if( memcmp( p + slen, result, hlen ) == 0 )
        error = 0;
    else
        error = MBEDTLS_ERR_RSA_VERIFY_FAILED;

out:
	mbedtls_free(buf);
	return error;
}

/*
 * Simplified PKCS#1 v2.1 RSASSA-PSS-VERIFY function
 */
int mbedtls_rsa_rsassa_pss_verify( mbedtls_rsa_context *ctx,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng,
                           int mode,
                           mbedtls_md_type_t md_alg,
                           unsigned int hashlen,
                           const unsigned char *hash,
                           const unsigned char *sig )
{
    mbedtls_md_type_t mgf1_hash_id = ( ctx->hash_id != MBEDTLS_MD_NONE )
                             ? (mbedtls_md_type_t) ctx->hash_id
                             : md_alg;

    return( mbedtls_rsa_rsassa_pss_verify_ext( ctx, f_rng, p_rng, mode,
                                       md_alg, hashlen, hash,
                                       mgf1_hash_id, MBEDTLS_RSA_SALT_LEN_ANY,
                                       sig ) );

}
#endif /* MBEDTLS_PKCS1_V21 */

#if defined(MBEDTLS_PKCS1_V15)
/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-v1_5-VERIFY function
 */
int mbedtls_rsa_rsassa_pkcs1_v15_verify( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode,
                                 mbedtls_md_type_t md_alg,
                                 unsigned int hashlen,
                                 const unsigned char *hash,
                                 const unsigned char *sig )
{
    int error = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    int ret;
    size_t len, siglen, asn1_len;
    unsigned char *p, *end;
    mbedtls_md_type_t msg_md_alg;
    const mbedtls_md_info_t *md_info;
    mbedtls_asn1_buf oid;
    unsigned char *buf = mbedtls_malloc(MBEDTLS_MPI_MAX_SIZE);
    if (!buf)
	return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    if( mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V15 )
        goto out;

    siglen = ctx->len;

    if( siglen < 16 || siglen > MBEDTLS_MPI_MAX_SIZE )
        goto out;

    ret = ( mode == MBEDTLS_RSA_PUBLIC )
          ? mbedtls_rsa_public(  ctx, sig, buf )
          : mbedtls_rsa_private( ctx, f_rng, p_rng, sig, buf );

    if( ret != 0 )
        goto out;

    p = buf;

    if( *p++ != 0 || *p++ != MBEDTLS_RSA_SIGN ) {
        error = MBEDTLS_ERR_RSA_INVALID_PADDING;
	 goto out;
    }

    while( *p != 0 )
    {
        if( p >= buf + siglen - 1 || *p != 0xFF ) {
            error = MBEDTLS_ERR_RSA_INVALID_PADDING;
	     goto out;
        }
        p++;
    }
    p++;

    len = siglen - ( p - buf );

    if( len == hashlen && md_alg == MBEDTLS_MD_NONE )
    {
        if( memcmp( p, hash, hashlen ) == 0 ) {
	     error = 0;
            goto out;
        } else {
	     error = MBEDTLS_ERR_RSA_VERIFY_FAILED;
	     goto out;
        }
    }

    md_info = mbedtls_md_info_from_type( md_alg );
    if( md_info == NULL )
        goto out;
    hashlen = mbedtls_md_get_size( md_info );

    end = p + len;

    // Parse the ASN.1 structure inside the PKCS#1 v1.5 structure
    //
    error = MBEDTLS_ERR_RSA_VERIFY_FAILED;
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &asn1_len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        goto out;

    if( asn1_len + 2 != len )
        goto out;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &asn1_len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        goto out;

    if( asn1_len + 6 + hashlen != len )
        goto out;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &oid.len, MBEDTLS_ASN1_OID ) ) != 0 )
        goto out;

    oid.p = p;
    p += oid.len;

    if( mbedtls_oid_get_md_alg( &oid, &msg_md_alg ) != 0 )
        goto out;;

    if( md_alg != msg_md_alg )
        goto out;

    /*
     * assume the algorithm parameters must be NULL
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &asn1_len, MBEDTLS_ASN1_NULL ) ) != 0 )
        goto out;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &asn1_len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        goto out;

    if( asn1_len != hashlen )
        goto out;

    if( memcmp( p, hash, hashlen ) != 0 )
        goto out;

    p += hashlen;

    if( p != end )
        goto out;

    error = 0;

out:
    mbedtls_free(buf);
    return( error );
}
#endif /* MBEDTLS_PKCS1_V15 */

/*
 * Do an RSA operation and check the message digest
 */
int mbedtls_rsa_pkcs1_verify( mbedtls_rsa_context *ctx,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng,
                      int mode,
                      mbedtls_md_type_t md_alg,
                      unsigned int hashlen,
                      const unsigned char *hash,
                      const unsigned char *sig )
{
    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            return mbedtls_rsa_rsassa_pkcs1_v15_verify( ctx, f_rng, p_rng, mode, md_alg,
                                                hashlen, hash, sig );
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            return mbedtls_rsa_rsassa_pss_verify( ctx, f_rng, p_rng, mode, md_alg,
                                          hashlen, hash, sig );
#endif

        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
}

/*
 * Copy the components of an RSA key
 */
int mbedtls_rsa_copy( mbedtls_rsa_context *dst, const mbedtls_rsa_context *src )
{
    int ret;

    dst->ver = src->ver;
    dst->len = src->len;

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->N, &src->N ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->E, &src->E ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->D, &src->D ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->P, &src->P ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->Q, &src->Q ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->DP, &src->DP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->DQ, &src->DQ ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->QP, &src->QP ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->RN, &src->RN ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->RP, &src->RP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->RQ, &src->RQ ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->Vi, &src->Vi ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->Vf, &src->Vf ) );

    dst->padding = src->padding;
    dst->hash_id = src->hash_id;

cleanup:
    if( ret != 0 )
        mbedtls_rsa_free( dst );

    return( ret );
}

/*
 * Free the components of an RSA key
 */
void mbedtls_rsa_free( mbedtls_rsa_context *ctx )
{
    mbedtls_mpi_free( &ctx->Vi ); mbedtls_mpi_free( &ctx->Vf );
    mbedtls_mpi_free( &ctx->RQ ); mbedtls_mpi_free( &ctx->RP ); mbedtls_mpi_free( &ctx->RN );
    mbedtls_mpi_free( &ctx->QP ); mbedtls_mpi_free( &ctx->DQ ); mbedtls_mpi_free( &ctx->DP );
    mbedtls_mpi_free( &ctx->Q  ); mbedtls_mpi_free( &ctx->P  ); mbedtls_mpi_free( &ctx->D );
    mbedtls_mpi_free( &ctx->E  ); mbedtls_mpi_free( &ctx->N  );

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_free( &ctx->mutex );
#endif
}

//#if defined(MBEDTLS_SELF_TEST)

#if 1
#include "mbedtls/sha1.h"

/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN 128

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                "7130B9CED7ACDF54CFC7555AC14EEBAB" \
                "93A89813FBF3C4F8066D2D800F7C38A8" \
                "1AE31942917403FF4946B0A83D3D3E05" \
                "EE57C6F5F5606FB5D4BC6CD34EE0801A" \
                "5E94BB77B07507233A0BC7BAC8F90F79"

#define RSA_E   "10001"

#define RSA_D   "24BF6185468786FDD303083D25E64EFC" \
                "66CA472BC44D253102F8B4A9D3BFA750" \
                "91386C0077937FE33FA3252D28855837" \
                "AE1B484A8A9A45F7EE8C0C634F99E8CD" \
                "DF79C5CE07EE72C7F123142198164234" \
                "CABB724CF78B8173B9F880FC86322407" \
                "AF1FEDFDDE2BEB674CA15F3E81A1521E" \
                "071513A1E85B5DFA031F21ECAE91A34D"

#define RSA_P   "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
                "2C01CAD19EA484A87EA4377637E75500" \
                "FCB2005C5C7DD6EC4AC023CDA285D796" \
                "C3D9E75E1EFC42488BB4F1D13AC30A57"

#define RSA_Q   "C000DF51A7C77AE8D7C7370C1FF55B69" \
                "E211C2B9E5DB1ED0BF61D0D9899620F4" \
                "910E4168387E3C30AA1E00C339A79508" \
                "8452DD96A9A5EA5D9DCA68DA636032AF"

#define RSA_DP  "C1ACF567564274FB07A0BBAD5D26E298" \
                "3C94D22288ACD763FD8E5600ED4A702D" \
                "F84198A5F06C2E72236AE490C93F07F8" \
                "3CC559CD27BC2D1CA488811730BB5725"

#define RSA_DQ  "4959CBF6F8FEF750AEE6977C155579C7" \
                "D8AAEA56749EA28623272E4F7D0592AF" \
                "7C1F1313CAC9471B5C523BFE592F517B" \
                "407A1BD76C164B93DA2D32A383E58357"

#define RSA_QP  "9AE7FBC99546432DF71896FC239EADAE" \
                "F38D18D2B2F0E2DD275AA977E2BF4411" \
                "F5A3B2A5D33605AEBBCCBA7FEB9F2D2F" \
                "A74206CEC169D74BF5A8C50D6F48EA08"

#define PT_LEN  24
#define RSA_PT  "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD"

#if defined(MBEDTLS_PKCS1_V15)
static int myrand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;
    uint8_t byte;
    get_random_bytes(&byte, sizeof(byte));

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = byte;
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD */

    return( 0 );
}
#endif /* MBEDTLS_PKCS1_V15 */


static void print_mbedtls_mpi(mbedtls_mpi *X)
{
	int i = 0;
	for (i = X->n - 1; i >= 0; i--)
		printk("%08x ", X->p[i]);
	printk("\n\n");
}

/*
 * Checkup routine
 */
//int mbedtls_rsa_self_test( int verbose )
static int __init rsa_init(void)
{
     int verbose = 0;
    int ret = 0;
#if defined(MBEDTLS_PKCS1_V15)
    size_t len;
    mbedtls_rsa_context rsa;
    unsigned char rsa_plaintext[PT_LEN];
    unsigned char rsa_decrypted[PT_LEN];
    unsigned char rsa_ciphertext[KEY_LEN];
#if defined(MBEDTLS_SHA1_C)
    unsigned char sha1sum[20];
#endif

    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
#if 0
    rsa.len = KEY_LEN;
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.N , 16, RSA_N  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.E , 16, RSA_E  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.D , 16, RSA_D  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.P , 16, RSA_P  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.Q , 16, RSA_Q  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.DP, 16, RSA_DP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.DQ, 16, RSA_DQ ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.QP, 16, RSA_QP ) );
#endif

#if 1
{
	//jsut for test
	mbedtls_rsa_context rsa1;
	mbedtls_rsa_init( &rsa1, MBEDTLS_RSA_PKCS_V15, 0 );
	rsa1.len = KEY_LEN;
	
	#if 1
	char *N = "d2c5a0e0b846c1228093e5aa5c23818e"
	"39df47b444c239b9cc29b368bb989c9d"
	"72f0b39a3b86e8da7a43984f931a6c6b"
	"a98b32105e1c30255e68f574a6580557"
	"cdfbda42a964bd16327043db7b70c298"
	"d12fb54b00d70811b47f76eb060f1eb8"
	"376def1ab084ce0a2cd4011f1bad223f"
	"69e6c9bb954dbeaf80027df5ecd4c253";
	char *D = "791ac4cd5a148d745d9c9d21bdbf48f9"
		"87971b8420ddd87d4129d4c420c61777"
		"004bfd66693da31da592a13957b49f07"
		"5d6b7560a2326017989f8629784aab06"
		"350614e455e5b88c6b9538d259340352"
		"ae4b9e8abf5ba755157eeeccaaefe84c"
		"074ffd26fb32cb1e0fe779f130e13223"
		"b0b5b79cde693903e64329f248000341";
	#define P1 "f753099a9dd08acd5cd8196a28ea2f9a"\
		"aa5fad6d3961c4e5b98c1cc4a4f0d236"\
		"0f92b78a1818c11dad116f6293f763e8"\
		"fc4f242e786eb76fa0e314a5c0e3b195"
	#define Q1 "da2a5a216b1191b822f9de935adba8c1"\
		"a9842ea7c97b33117600524b3007b4cb"\
		"cc678160067d4d79b8c6414b1d263ff6"\
		"9424ab92134fe2aaa3697c33ee77fa47"
	#define DP1 "4f158250aa7df0a45237d78896a4abac"\
		"2d2682f21613293ebbe20da0e38d0dea"\
		"b3781ab0519c38c4207f1ebacacda468"\
		"efa4eed0dd39a9f64bdfd0ce5fab6f31"
	#define DQ1 "4369d0de00b2b61f7b1750f2a1a1bc9c"\
		"d31fd836daa86a185c292f44b27bbf1f"\
		"36734963fdbd5c625f794b95c5551b70"\
		"bb483587f6d5b989d6e2f2912d7fff63"
	#define QP1 "2ad5eadd48e13368c4f1d1b1d059b94b"\
		"581f3a1bb5caae247b96a6b380306a2b"\
		"6f2754a169d2288a24d8fb5fd7de692c"\
		"ec8a5a0a8844d01a576e27b83f6b6494"

	#else
	char *N = "d3229199a7b95ff0d3b02c8f4e0fa681"
	"4149f3076fa6af0540264079376a66c8"
	"d765aa1fbcd0d6a9ca3d9e8594effaa3"
	"6336a29f911ef9b3ab36bca2fa8ce718"
	"18ac1bb3d0a5a184e2d8351b6ca75c0c"
	"a937be4970c442e422d3784b78749952"
	"5008066c72be1ab9c4e784feaf540bdb"
	"c215c9a01a0f652c63a751507bc0c9a7";
	#endif
	printk("jiffis=%lu\n", jiffies);
	char *e = "010001";
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa1.N , 16, N  ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa1.E , 16, e  ) );
//	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa1.D , 16, D  ) );
//	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa1.P , 16, P1  ) );
//	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa1.Q , 16, Q1  ) );
//	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa1.DP, 16, DP1 ) );
//	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa1.DQ, 16, DQ1 ) );
//	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa1.QP, 16, QP1 ) );
//	print_mbedtls_mpi(&rsa1.N);
//	if( mbedtls_rsa_check_pubkey(  &rsa1 ) != 0)
//		mbedtls_printf("mbedtls_rsa_check_pubkey falied\n");
//	else
//		mbedtls_printf("mbedtls_rsa_check_pubkey success\n");
	//encrypt 
	memcpy( rsa_plaintext, RSA_PT, PT_LEN );
	if( mbedtls_rsa_pkcs1_encrypt( &rsa1, myrand, NULL, MBEDTLS_RSA_PUBLIC, PT_LEN,
                           rsa_plaintext, rsa_ciphertext ) != 0 )
		mbedtls_printf("mbedtls_rsa_pkcs1_encrypt failed\n");
	else
		mbedtls_printf("mbedtls_rsa_pkcs1_encrypt success\n");

	printk("after jiffis=%lu\n", jiffies);
//	if( mbedtls_rsa_pkcs1_encrypt( &rsa1, myrand, NULL, MBEDTLS_RSA_PUBLIC, PT_LEN,
//                           rsa_plaintext, rsa_ciphertext ) != 0 )
//		mbedtls_printf("mbedtls_rsa_pkcs1_encrypt failed\n");
//	else
//		mbedtls_printf("mbedtls_rsa_pkcs1_encrypt success\n");

	//decrypt
//	if( mbedtls_rsa_pkcs1_decrypt( &rsa1, myrand, NULL, MBEDTLS_RSA_PRIVATE, &len,
  //                         rsa_ciphertext, rsa_decrypted,
    //                       sizeof(rsa_decrypted) ) != 0 )
//		mbedtls_printf("mbedtls_rsa_pkcs1_decrypt failed\n");
//	else
//		mbedtls_printf("mbedtls_rsa_pkcs1_decrypt success, len=%d\n", len);

//	 if( mbedtls_rsa_pkcs1_decrypt( &rsa1, myrand, NULL, MBEDTLS_RSA_PRIVATE, &len,
    //                       rsa_ciphertext, rsa_decrypted,
  //                         sizeof(rsa_decrypted) ) != 0 )
//		mbedtls_printf("mbedtls_rsa_pkcs1_decrypt failed\n");
//	else
//		mbedtls_printf("mbedtls_rsa_pkcs1_decrypt success, len=%d\n", len);
	mbedtls_rsa_free(&rsa1);

}
#endif

#if 0
    if( verbose != 0 )
        mbedtls_printf( "  RSA key validation: " );

    if( mbedtls_rsa_check_pubkey(  &rsa ) != 0 ||
        mbedtls_rsa_check_privkey( &rsa ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n  PKCS#1 encryption : " );

    memcpy( rsa_plaintext, RSA_PT, PT_LEN );

    if( mbedtls_rsa_pkcs1_encrypt( &rsa, myrand, NULL, MBEDTLS_RSA_PUBLIC, PT_LEN,
                           rsa_plaintext, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n  PKCS#1 decryption : " );

    if( mbedtls_rsa_pkcs1_decrypt( &rsa, myrand, NULL, MBEDTLS_RSA_PRIVATE, &len,
                           rsa_ciphertext, rsa_decrypted,
                           sizeof(rsa_decrypted) ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        return( 1 );
    }

    if( memcmp( rsa_decrypted, rsa_plaintext, len ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

#if defined(MBEDTLS_SHA1_C)
    if( verbose != 0 )
        mbedtls_printf( "  PKCS#1 data sign  : " );

    mbedtls_sha1( rsa_plaintext, PT_LEN, sha1sum );

    if( mbedtls_rsa_pkcs1_sign( &rsa, myrand, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA1, 0,
                        sha1sum, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n  PKCS#1 sig. verify: " );

    if( mbedtls_rsa_pkcs1_verify( &rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA1, 0,
                          sha1sum, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );
#endif /* MBEDTLS_SHA1_C */

    if( verbose != 0 )
        mbedtls_printf( "\n" );

cleanup:
    mbedtls_rsa_free( &rsa );
#else /* MBEDTLS_PKCS1_V15 */
    ((void) verbose);
#endif /* MBEDTLS_PKCS1_V15 */
#endif
cleanup:
    mbedtls_rsa_free( &rsa );
    return( ret );
}

static void __exit rsa_exit(void)
{
}

module_init(rsa_init);
module_exit(rsa_exit);
MODULE_LICENSE("GPL");
#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_RSA_C */
