#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"
#include "jwt.h"

#define RSA_N ""

#define RSA_E ""

#define RSA_D ""

#define RSA_P ""

#define RSA_Q ""

uint8_t jwt_create(char **jwt)
{
    char header[] = "{\"typ\":\"JWT\",\"alg\":\"RS256\"}";
    char payload[64];

    char *iat = GSM_iat();
    char *exp = GSM_exp();

    strcpy(payload, "{\"iat\": ");
    strcat(payload, iat);
    strcat(payload, ",\"exp\": ");
    strcat(payload, exp);
    strcat(payload, ",\"aud\": \"");
    strcat(payload, PROJECT_ID);
    strcat(payload, "\"}");

    free(iat);
    free(exp);

    size_t p_len = strlen(payload);
    size_t pb64_len;
    mbedtls_base64url_encode(NULL, 0, &pb64_len, (const unsigned char*)payload, p_len);
    char *pb64 = (char*)malloc(sizeof(char)*pb64_len);
    size_t pb64_w;
    mbedtls_base64url_encode((unsigned char *)pb64, pb64_len, &pb64_w, (const unsigned char*)payload, p_len);

    size_t h_len = strlen(header);
    size_t hb64_len;
    mbedtls_base64url_encode(NULL, 0, &hb64_len, (const unsigned char*)header, h_len);
    char *hb64 = (char*)malloc(sizeof(char)*hb64_len);
    size_t hb64_w;
    mbedtls_base64url_encode((unsigned char*)hb64, hb64_len, &hb64_w, (const unsigned char*)header, h_len);

    size_t hpb64_len = hb64_len+pb64_len;
    char hpb64[hpb64_len];
    memset(hpb64, 0, hpb64_len);

    strcpy(hpb64, hb64);
    strcat(hpb64, ".");
    strcat(hpb64, pb64);

    free(pb64);
    free(hb64);

    unsigned char hash[33];
    memset(hash, 0, 33);
    mbedtls_sha256_ret((const unsigned char*)hpb64, (hpb64_len-1), hash, 0);

    /* /1* TODO: Possibily remove sprintf *1/ */
    /* unsigned char hash_str[65]; */
    /* int i; */
    /* for(i = 0; i < 32; i++) */
    /*     sprintf((char*)&hash_str[i*2], "%02x ", hash[i]); */


    unsigned char rsa_buf[MBEDTLS_MPI_MAX_SIZE];
    mbedtls_rsa_context rsa_cntx;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;

    mbedtls_rsa_init(&rsa_cntx, MBEDTLS_RSA_PKCS_V15, 0);

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E); mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ); mbedtls_mpi_init(&QP);

    int ret = 1;
    if((ret = mbedtls_mpi_read_string(&N, 16, RSA_N) ) != 0 ||
            (ret = mbedtls_mpi_read_string(&E, 16, RSA_E) ) != 0 ||
            (ret = mbedtls_mpi_read_string(&D, 16, RSA_D) ) != 0 ||
            (ret = mbedtls_mpi_read_string(&P, 16, RSA_P) ) != 0 ||
            (ret = mbedtls_mpi_read_string(&Q, 16, RSA_Q) ) != 0)
        goto CLEANUP;

    if((ret = mbedtls_rsa_import(&rsa_cntx, &N, &P, &Q, &D, &E )) != 0)
        goto CLEANUP;
    if((ret = mbedtls_rsa_complete(&rsa_cntx)) != 0)
        goto CLEANUP;
    if((ret = mbedtls_rsa_check_privkey(&rsa_cntx)) != 0)
        goto CLEANUP;

    if((ret = mbedtls_rsa_pkcs1_sign(&rsa_cntx, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 32, hash, rsa_buf)) != 0)
        goto CLEANUP;

    /* size_t s_len = strlen((const char*)rsa_buf); */
    size_t s_len = RSA_LEN;
    size_t sb64_len;
    mbedtls_base64url_encode(NULL, 0, &sb64_len, (const unsigned char*)rsa_buf, s_len);
    char *sb64 = (char*)malloc(sizeof(char)*sb64_len);
    memset(sb64, 0, RSA_LEN);
    size_t sb64_w;
    mbedtls_base64url_encode((unsigned char *)sb64, sb64_len, &sb64_w, (const unsigned char*)rsa_buf, s_len);
    
    *jwt = (char*)realloc(*jwt, sizeof(char)*(hpb64_len+sb64_len));
    strcpy(*jwt, hpb64);
    strcat(*jwt, ".");
    strcat(*jwt, sb64);

CLEANUP:
    mbedtls_rsa_free(&rsa_cntx);
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&E); mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ); mbedtls_mpi_free(&QP);

    return ret;
}
