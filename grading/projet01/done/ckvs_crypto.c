// ckvs_crypto

#include "ckvs.h"
#include "ckvs_crypto.h"
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <string.h>
#include <assert.h>

#define AUTH_MESSAGE "Auth Key"
#define C1_MESSAGE   "Master Key Encryption"
#define STRETCHED_KEY_SEP "|"

// ==========================================================================================
int ckvs_client_encrypt_pwd(ckvs_memrecord_t *mr, const char *key, const char *pwd) {
    M_REQUIRE_NON_NULL(mr);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);
    M_REQUIRE_MSG(key[0] != '\0',
                  ERR_INVALID_ARGUMENT,
                  "%s", "The given key is empty (length of 0)");

    ckvs_memrecord_t res;
    memset(&res, 0, sizeof(res));

    //---------- STRETCHED_KEY BLOCK ----------
    {
#define STRETCHED_KEYLEN 2 * CKVS_MAXKEYLEN + 2
        char stretched_raw_key[STRETCHED_KEYLEN] = "";

        strncat(stretched_raw_key, key, CKVS_MAXKEYLEN);
        strcat(stretched_raw_key, STRETCHED_KEY_SEP);
        strcat(stretched_raw_key, pwd);

        SHA256((unsigned char*)stretched_raw_key, strnlen(stretched_raw_key, STRETCHED_KEYLEN), res.stretched_key.sha);
    }

    //---------- AUTH BLOCK ----------
    {
        unsigned int res_length = 0;
        unsigned char* hmac_res = HMAC(EVP_sha256(),
                                       res.stretched_key.sha,
                                       SHA256_DIGEST_LENGTH,
                                       (const unsigned char*)AUTH_MESSAGE,
                                       strlen(AUTH_MESSAGE),
                                       res.auth_key.sha,
                                       &res_length);

        M_REQUIRE_MSG(hmac_res != NULL && res_length == SHA256_DIGEST_LENGTH,
                  ERR_IO,
                  "%s",
                  "Impossible to compute the auth HMAC with the given key and password");
    }

    //---------- C1 BLOCK ----------
    {
        unsigned int res_length = 0;
        unsigned char* hmac_res = HMAC(EVP_sha256(),
                                       res.stretched_key.sha,
                                       SHA256_DIGEST_LENGTH,
                                       (const unsigned char*)C1_MESSAGE,
                                       strlen(C1_MESSAGE),
                                       res.c1.sha,
                                       &res_length);
                              
        M_REQUIRE_MSG(hmac_res != NULL && res_length == SHA256_DIGEST_LENGTH,
                  ERR_IO,
                  "%s",
                  "Impossible to compute the c1 HMAC with the given key and password");
    }

    *mr = res;
    M_EXIT(ERR_NONE);
}

// ==========================================================================================
int ckvs_client_compute_masterkey(struct ckvs_memrecord *mr, const struct ckvs_sha *c2) {
    M_REQUIRE_NON_NULL(mr);
    M_REQUIRE_NON_NULL(c2);

    ckvs_memrecord_t res = *mr;

    //---------- HMAC COMPUTATION ----------
    unsigned int res_length = 0;
    unsigned char* hmac_res = HMAC(EVP_sha256(),
                                   res.c1.sha,
                                   SHA256_DIGEST_LENGTH,
                                   c2->sha,
                                   SHA256_DIGEST_LENGTH,
                                   res.master_key.sha,
                                   &res_length);
    M_REQUIRE_MSG(hmac_res != NULL && res_length == SHA256_DIGEST_LENGTH,
              ERR_IO,
              "%s",
              "Impossible to compute the master key HMAC with the given key and password");

    *mr = res;
    M_EXIT(ERR_NONE);
}


int ckvs_client_crypt_value(const struct ckvs_memrecord *mr, const int do_encrypt,
                            const unsigned char *inbuf, size_t inbuflen,
                            unsigned char *outbuf, size_t *outbuflen )
{
    /* ======================================
     * Implementation adapted from the web:
     *     https://man.openbsd.org/EVP_EncryptInit.3
     * Man page: EVP_EncryptInit
     * Reference:
     *    https://www.coder.work/article/6383682
     * ======================================
     */

    // constant IV -- ok given the entropy in c2
    unsigned char iv[16];
    bzero(iv, 16);

    // Don't set key or IV right away; we want to check lengths
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL, do_encrypt);

    assert(EVP_CIPHER_CTX_key_length(ctx) == 32);
    assert(EVP_CIPHER_CTX_iv_length(ctx)  == 16);

    // Now we can set key and IV
    const unsigned char* const key = (const unsigned char*) mr->master_key.sha;
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    int outlen = 0;
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, (int) inbuflen)) {
        // Error
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    int tmplen = 0;
    if (!EVP_CipherFinal_ex(ctx, outbuf+outlen, &tmplen)) {
        // Error
        debug_printf("crypt inbuflen %ld outlen %d tmplen %d", inbuflen, outlen, tmplen);
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);

    *outbuflen = (size_t) outlen;

    return ERR_NONE;
}
