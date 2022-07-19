#include <stdio.h>
#include <stdlib.h>

#include "openssl/rand.h"
#include "openssl/evp.h"
#include "ckvs_local.h"
#include "error.h"
#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include "util.h"

/**
 * @brief Applies a get or a set command depending on the value of set_value.
 * If it is NULL, it reads the entry corresponding to the given key in the given filename.
 * Otherwise, it overwrites the content of the given key in the given filename.
 *
 * @param filename (const char*) the path to the CKVS database to read or write
 * @param key (const char*) the key of the entry to get or set
 * @param pwd (const char*) the password of the entry to get or set
 * @param set_value (const char*) the value to set, NULL for a get
 * @return int, an error code
 */
int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char* set_value);

//===========================================================================
int ckvs_local_stats(const char *filename) {
    M_REQUIRE_NON_NULL(filename);

    struct CKVS ckvs;
    int err_code = ckvs_open(filename, &ckvs);
    M_REQUIRE_NO_ERROR(err_code);

    //---------- PRINT HEADER ----------
    print_header(&ckvs.header);

    //---------- PRINT ENTRIES ----------
    for (size_t i = 0; i < ckvs.header.table_size; ++i) {
        if (ckvs.entries[i].key[0] != '\0') {
            print_entry(&ckvs.entries[i]);
        }
    }

    ckvs_close(&ckvs);
    M_EXIT(ERR_NONE);
}

//===========================================================================
int ckvs_local_get(const char *filename, const char *key, const char *pwd) {
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);
    M_REQUIRE_MSG(key[0] != '\0',
                  ERR_INVALID_ARGUMENT,
                  "%s", "The given key is empty (length of 0)");

    int err_code = ckvs_local_getset(filename, key, pwd, NULL);
    M_EXIT(err_code);
}

//===========================================================================
int ckvs_local_set(const char *filename, const char *key, const char *pwd, const char *valuefilename) {
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);
    M_REQUIRE_NON_NULL(valuefilename);
    M_REQUIRE_MSG(key[0] != '\0',
                  ERR_INVALID_ARGUMENT,
                  "%s", "The given key is empty (length of 0)");

    char* content = NULL;
    size_t content_size = 0;

    int err_code = ERR_NONE;
    //---------- READ VALUE FILE ----------
    err_code = read_value_file_content(valuefilename, &content, &content_size);
    M_REQUIRE_NO_ERROR(err_code);

    //---------- OVERWRITES ENTRY IN FILE ----------
    err_code = ckvs_local_getset(filename, key, pwd, content);
    if(err_code != ERR_NONE) {
        free(content);
        M_EXIT(err_code);
    }

    free(content);
    M_EXIT(ERR_NONE);
}

//===========================================================================
int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char* set_value) {
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);
    M_REQUIRE_MSG(key[0] != '\0',
                  ERR_INVALID_ARGUMENT,
                  "%s", "The given key is empty (length of 0)");

    int err_code = ERR_NONE;

    //---------- MEMRECORD ----------
    ckvs_memrecord_t mr;
    err_code = ckvs_client_encrypt_pwd(&mr, key, pwd);
    M_REQUIRE_NO_ERROR(err_code);

    //---------- DISK DATABASE ----------
    CKVS_t ckvs;
    err_code = ckvs_open(filename, &ckvs);
    M_REQUIRE_NO_ERROR(err_code);

    //---------- ENTRY ----------
    ckvs_entry_t* p_entry;
    err_code = ckvs_find_entry(&ckvs, key, &mr.auth_key, &p_entry);
    if(err_code != ERR_NONE) {
        ckvs_close(&ckvs);
        M_EXIT(err_code);
    }

    //---------- C2 ----------
    if(set_value != NULL) {
        err_code = RAND_bytes(p_entry->c2.sha, SHA256_DIGEST_LENGTH);
        if(err_code != 1) {
            ckvs_close(&ckvs);
            M_EXIT(ERR_IO);
        }
    }

    //---------- MASTER KEY ----------
    err_code = ckvs_client_compute_masterkey(&mr, &p_entry->c2);
    if(err_code != ERR_NONE) {
        ckvs_close(&ckvs);
        M_EXIT(err_code);
    }

    if(set_value == NULL)
    {
        //=============== GET ===============
        err_code = fseek(ckvs.file,
                         (long int) p_entry->value_off,
                         SEEK_SET);
        if(err_code != 0) {
            ckvs_close(&ckvs);
            M_EXIT(ERR_IO);
        }

        //---------- READ CIPHER ----------
        unsigned char* cipher = calloc(1, p_entry->value_len + 1); //+1 to ensure the last '\0' char
        if(cipher == NULL) {
            ckvs_close(&ckvs);
            M_EXIT(ERR_OUT_OF_MEMORY);
        }

        size_t read_size = fread(cipher,
                                 p_entry->value_len,
                                 1,
                                 ckvs.file);
        if(read_size != 1) {
            ckvs_close(&ckvs);
            free(cipher);
            M_EXIT(ERR_IO);
        }

        //---------- COMPUTE PLAINTEXT ----------
        unsigned char* plaintext = calloc(1, p_entry->value_len + 1 + EVP_MAX_BLOCK_LENGTH); //+1 to ensure the last '\0' char
        if(plaintext == NULL) {
            ckvs_close(&ckvs);
            free(cipher);
            M_EXIT(ERR_OUT_OF_MEMORY);
        }

        size_t written_size = 0;
        err_code = ckvs_client_crypt_value(&mr,
                                           0,
                                           cipher,
                                           p_entry->value_len,
                                           plaintext,
                                           &written_size);
        if(err_code != ERR_NONE) {
            ckvs_close(&ckvs);
            free(cipher);
            free(plaintext);
            M_EXIT(err_code);
        }

        pps_printf("%s", plaintext);
        free(cipher);
        free(plaintext);
    }
    else
    {
        //=============== SET ===============
        unsigned char* cipher = calloc(1, strlen(set_value) + 1 + EVP_MAX_BLOCK_LENGTH); // + 1 for '\0'
        if(cipher == NULL) {
            ckvs_close(&ckvs);
            M_EXIT(ERR_OUT_OF_MEMORY);
        }

        size_t written_size = 0;
        err_code = ckvs_client_crypt_value(&mr,
                                           1,
                                           (const unsigned char*) set_value,
                                           strlen(set_value) + 1,
                                           cipher,
                                           &written_size);
        if(err_code != ERR_NONE) {
            free(cipher);
            ckvs_close(&ckvs);
            M_EXIT(err_code);
        }

        //---------- WRITE ENCRYPTED VALUE ----------
        err_code = ckvs_write_encrypted_value(&ckvs, p_entry, cipher, (uint64_t) written_size);
        if(err_code != ERR_NONE) {
            free(cipher);
            ckvs_close(&ckvs);
            M_EXIT(err_code);
        }

#ifdef DEBUG
        {
            unsigned char* plaintext = calloc(1, written_size + 1 + EVP_MAX_BLOCK_LENGTH);
            M_REQUIRE(plaintext != NULL, ERR_IO);

            size_t debug_written_size = 0;
            err_code = ckvs_client_crypt_value(&mr,
                                               0,
                                               cipher,
                                               written_size,
                                               plaintext,
                                               &debug_written_size);
            if(err_code != ERR_NONE) {
                free(cipher);
                free(plaintext);
                M_EXIT(err_code);
            }
            debug_printf("Decrypted version of the encrypted value just written: \n%s", plaintext);

            free(plaintext);
            plaintext = NULL;
        }
#endif
        free(cipher);
    }

    ckvs_close(&ckvs);
    M_EXIT(ERR_NONE);
}

