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

/**
 * @brief Fetches and prints the content of the given entry in the given ckvs database with the given memrecord.
 * DO NOT CLOSE THE CKVS DATABASE UNDER ANY CIRCUMSTANCES.
 *
 * @param p_entry (const ckvs_entry*) the entry from which the content should be read
 * @param ckvs (const CKVS_t*) the ckvs database from which the content should be read
 * @param mr (const ckvs_memrecord_t*) the memrecord containing the correct keys to access the database
 * @return int, error code
 */
static int do_get(const ckvs_entry_t* p_entry, const CKVS_t* ckvs, const ckvs_memrecord_t* mr);

/**
 * @brief Replaces the content of the given entry in the given ckvs database with the given memrecord with the given
 * value.
 * DO NOT CLOSE THE CKVS DATABASE UNDER ANY CIRCUMSTANCES.
 *
 * @param p_entry (const ckvs_entry*) the entry from which the content should be replaced
 * @param ckvs (const CKVS_t*) the ckvs database from which the content should be replaced
 * @param mr (const ckvs_memrecord_t*) the memrecord containing the correct keys to access the database
 * @param set_value (const char*) the new content to write inside the entry
 * @return int, error code
 */
static int do_set(ckvs_entry_t* p_entry, CKVS_t* ckvs, const ckvs_memrecord_t* mr, const char* set_value);

//===========================================================================
int ckvs_local_stats(const char* filename, int optargc, _unused char* optargv[]) {
#define STATS_ARGC 0
    M_REQUIRE_NON_NULL(filename);
    M_CHECK_ARG_COUNT(optargc, STATS_ARGC);

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
int ckvs_local_get(const char* filename, int optargc, char* optargv[]) {
#define GET_ARGC 2
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(optargv);
    M_CHECK_ARG_COUNT(optargc, GET_ARGC);

    const char* key = optargv[0];
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_MSG(key[0] != '\0',
                  ERR_INVALID_ARGUMENT,
                  "%s", "The given key is empty (length of 0)");
    const char* pwd = optargv[1];
    M_REQUIRE_NON_NULL(pwd);

    int err_code = ckvs_local_getset(filename, key, pwd, NULL);
    M_EXIT(err_code);
}

//===========================================================================
int ckvs_local_set(const char* filename, int optargc, char* optargv[]) {
#define SET_ARGC 3
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(optargv);
    M_CHECK_ARG_COUNT(optargc, SET_ARGC);

    const char* key = optargv[0];
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_MSG(key[0] != '\0',
                  ERR_INVALID_ARGUMENT,
                  "%s", "The given key is empty (length of 0)");
    const char* pwd = optargv[1];
    M_REQUIRE_NON_NULL(pwd);
    const char* valuefilename = optargv[2];
    M_REQUIRE_NON_NULL(valuefilename);

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
int ckvs_local_new(const char* filename, int optargc, char* optargv[]) {
#define NEW_ARGC 2
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(optargv);
    M_CHECK_ARG_COUNT(optargc, NEW_ARGC);

    const char* key = optargv[0];
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_MSG(key[0] != '\0',
                  ERR_INVALID_ARGUMENT,
                  "%s", "The given key is empty (length of 0)");
    const char* pwd = optargv[1];
    M_REQUIRE_NON_NULL(pwd);

    int err_code = ERR_NONE;

    //---------- GENERATE AUTH KEY ----------
    ckvs_memrecord_t mr;
    err_code = ckvs_client_encrypt_pwd(&mr, key, pwd);
    M_REQUIRE_NO_ERROR(err_code);

    //---------- OPEN DISK DATABASE ----------
    CKVS_t ckvs;
    err_code = ckvs_open(filename, &ckvs);
    M_REQUIRE_NO_ERROR(err_code);

    ckvs_entry_t* e = NULL;

    err_code = ckvs_new_entry(&ckvs, key, &mr.auth_key, &e);
    if(err_code != ERR_NONE) {
        ckvs_close(&ckvs);
        M_EXIT(err_code);
    }

    ckvs_close(&ckvs);
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

    if(set_value == NULL) {
        //---------- GET ----------
        err_code = do_get(p_entry, &ckvs, &mr);
        if (err_code != ERR_NONE) {
            ckvs_close(&ckvs);
            M_EXIT(err_code);
        }
    } else {
        //---------- SET ----------
        err_code = do_set(p_entry, &ckvs, &mr, set_value);
        if(err_code != ERR_NONE) {
            ckvs_close(&ckvs);
            M_EXIT(err_code);
        }
    }

    ckvs_close(&ckvs);
    M_EXIT(ERR_NONE);
}

//===========================================================================
static int do_get(const ckvs_entry_t* p_entry, const CKVS_t* ckvs, const ckvs_memrecord_t* mr) {
    M_REQUIRE_NON_NULL(p_entry);
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(ckvs->file);
    M_REQUIRE_NON_NULL(mr);

    if(p_entry->value_len == 0) {
        pps_printf("NO VALUE");
        M_EXIT(ERR_NO_VALUE);
    }
    int err_code = fseek(ckvs->file,
                     (long int) p_entry->value_off,
                     SEEK_SET);
    M_REQUIRE(err_code == 0, ERR_IO);

    //---------- READ CIPHER ----------
    unsigned char* cipher = calloc(p_entry->value_len + 1, sizeof(cipher[0])); //+1 to ensure the last '\0' char
    M_REQUIRE(cipher != NULL, ERR_OUT_OF_MEMORY);

    size_t read_size = fread(cipher,
                             sizeof(cipher[0]),
                             p_entry->value_len,
                             ckvs->file);
    if(read_size != p_entry->value_len) {
        free(cipher);
        M_EXIT(ERR_IO);
    }

    //---------- COMPUTE PLAINTEXT ----------
    unsigned char* plaintext = calloc(p_entry->value_len + 1 + EVP_MAX_BLOCK_LENGTH, sizeof(plaintext[0])); //+1 to ensure the last '\0' char
    if(plaintext == NULL) {
        free(cipher);
        M_EXIT(ERR_OUT_OF_MEMORY);
    }

    size_t written_size = 0;
    err_code = ckvs_client_crypt_value(mr,
                                       0,
                                       cipher,
                                       p_entry->value_len,
                                       plaintext,
                                       &written_size);
    if(err_code != ERR_NONE) {
        free(cipher);
        free(plaintext);
        M_EXIT(err_code);
    }

    pps_printf("%s\n", plaintext);
    free(cipher);
    free(plaintext);

    M_EXIT(ERR_NONE);
}

//===========================================================================
static int do_set(ckvs_entry_t* p_entry, CKVS_t* ckvs, const ckvs_memrecord_t* mr, const char* set_value) {
    unsigned char* cipher = calloc(1, strlen(set_value) + 1 + EVP_MAX_BLOCK_LENGTH); // + 1 for '\0'
    M_REQUIRE(cipher != NULL, ERR_OUT_OF_MEMORY);

    //---------- ENCRYPT VALUE ----------
    size_t written_size = 0;
    int err_code = ckvs_client_crypt_value(mr,
                                       1,
                                       (const unsigned char*) set_value,
                                       strlen(set_value) + 1,
                                       cipher,
                                       &written_size);
    if(err_code != ERR_NONE) {
        free(cipher);
        M_EXIT(err_code);
    }

    //---------- WRITE ENCRYPTED VALUE ----------
    err_code = ckvs_write_encrypted_value(ckvs, p_entry, cipher, (uint64_t) written_size);
    if(err_code != ERR_NONE) {
        free(cipher);
        M_EXIT(err_code);
    }

    free(cipher);
    M_EXIT(ERR_NONE);
}

