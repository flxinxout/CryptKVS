// ckvs_crypto

#include "ckvs.h"
#include "ckvs_crypto.h"
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <string.h>
#include <assert.h>

/**
 * @brief Message set for the HMAC of a message content
 */
#define AUTH_MESSAGE "Auth Key"

/**
 * @brief Message set for the HMAC of a C1 content
 */
#define C1_MESSAGE   "Master Key Encryption"

/**
 * @brief Separator for the stretched key
 */
#define STRETCHED_KEY_SEP "|"

/**
 * @brief Computes the hmac of a SHA256 key using the given message of length mess_len.
 * The key must have a maximal length of SHA256_DIGEST_LENGTH characters.
 * Place the result in buf, only if no error occurs.
 *
 * @param key (const void*) used key for HMAC
 * @param mess (const unsigned char*) used message for HMAC
 * @param mess_len (size_t) length of the message
 * @param buf (unsigned char*) buffer where the result is stored if no error occurs
 * @return int, error code
 */
static int compute_HMAC_SHA256(const unsigned char* key, const unsigned char* mess, size_t mess_len, unsigned char* buf);

/**
 * @brief Computes the stretched key of the given key and password and stores it inside the given memrecord if no
 * error occurs.
 *
 * @param key (const char*) the key used for the stretched key
 * @param pwd (const char*) the password used for the stretched key
 * @param mr (ckvs_memrecord_t*) the memrecord where to store the stretched key
 * @return int, error code
 */
static int compute_stretched_key(const char* key, const char* pwd, ckvs_memrecord_t* mr);

// ==========================================================================================
int ckvs_client_encrypt_pwd(ckvs_memrecord_t *mr, const char *key, const char *pwd) {
    M_REQUIRE_NON_NULL(mr);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);
    M_REQUIRE_MSG(key[0] != '\0',
                  ERR_INVALID_ARGUMENT,
                  "%s", "The given key is empty (length of 0)");

    int err_code = ERR_NONE;

    ckvs_memrecord_t mr_copy;
    memset(&mr_copy, 0, sizeof(mr_copy));

    //---------- STRETCHED_KEY BLOCK ----------
    {
        err_code = compute_stretched_key(key, pwd, &mr_copy);
        M_REQUIRE_NO_ERROR(err_code);
    }

    //---------- AUTH BLOCK ----------
    {
        err_code = compute_HMAC_SHA256(mr_copy.stretched_key.sha, (const unsigned char*)AUTH_MESSAGE, strlen(AUTH_MESSAGE),mr_copy.auth_key.sha);
        M_REQUIRE(err_code == ERR_NONE, err_code);
    }

    //---------- C1 BLOCK ----------
    {
        err_code = compute_HMAC_SHA256(mr_copy.stretched_key.sha, (const unsigned char*)C1_MESSAGE, strlen(C1_MESSAGE), mr_copy.c1.sha);
        M_REQUIRE(err_code == ERR_NONE, err_code);
    }

    *mr = mr_copy;
    M_EXIT(ERR_NONE);
}

// ==========================================================================================
int ckvs_client_compute_masterkey(struct ckvs_memrecord *mr, const struct ckvs_sha *c2) {
    M_REQUIRE_NON_NULL(mr);
    M_REQUIRE_NON_NULL(c2);

    ckvs_memrecord_t res = *mr;

    //---------- HMAC COMPUTATION ----------
    int err_code = compute_HMAC_SHA256(res.c1.sha, c2->sha, SHA256_DIGEST_LENGTH, res.master_key.sha);
    M_REQUIRE(err_code == ERR_NONE, err_code);

    *mr = res;
    M_EXIT(ERR_NONE);
}

// ==========================================================================================
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

// ==========================================================================================
static int compute_HMAC_SHA256(const unsigned char* key, const unsigned char* mess, size_t mess_len, unsigned char* buf) {
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(mess);
    M_REQUIRE_NON_NULL(buf);

    unsigned char buf_copy[SHA256_DIGEST_LENGTH];
    memset(buf_copy, 0, sizeof(buf_copy));

    unsigned int res_length = 0;
    unsigned char* hmac_res = HMAC(EVP_sha256(),
                                   key,
                                   SHA256_DIGEST_LENGTH,
                                   mess,
                                   mess_len,
                                   buf_copy,
                                   &res_length);

    M_REQUIRE_MSG(hmac_res != NULL && res_length == SHA256_DIGEST_LENGTH,
                  ERR_IO,
                  "%s",
                  "Impossible to compute the HMAC with the given key and password");

    memcpy(buf, buf_copy, sizeof(buf_copy));
    M_EXIT(ERR_NONE);
}

// ==========================================================================================
static int compute_stretched_key(const char* key, const char* pwd, ckvs_memrecord_t* mr) {
#define STRETCHED_KEYLEN strnlen(key, CKVS_MAXKEYLEN) + strlen(STRETCHED_KEY_SEP) + strnlen(pwd, CKVS_MAXKEYLEN) + 1

    char* stretched_raw_key = calloc(STRETCHED_KEYLEN, sizeof(stretched_raw_key[0]));
    M_REQUIRE(stretched_raw_key != NULL, ERR_OUT_OF_MEMORY);

    strncat(stretched_raw_key, key, CKVS_MAXKEYLEN);
    strcat(stretched_raw_key, STRETCHED_KEY_SEP);
    strncat(stretched_raw_key, pwd, CKVS_MAXKEYLEN);

    SHA256((unsigned char*)stretched_raw_key, strlen(stretched_raw_key), mr->stretched_key.sha);

    free(stretched_raw_key);
    M_EXIT(ERR_NONE);
}