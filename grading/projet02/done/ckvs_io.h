/**
 * @file ckvs_io.h
 * @brief ckvs_io - IO operations for a local database
 * @author E Bugnion, A. Clergeot
 */
#pragma once

#include <stdint.h> // for uint64_t
#include "ckvs.h"

/**
 * Disk format of a database.
 */
typedef struct CKVS {
    ckvs_header_t header;
    ckvs_entry_t* entries;
    FILE* file;
} CKVS_t;

/**
 * @brief Opens the CKVS database at filename.
 * Also checks that the database is valid, as described in 04.stats.md.
 * Does not modify the given CKVS database if an error occurs.
 * DO NOT FORGET TO CALL CKVS_CLOSE AFTERWARDS.
 *
 * @param filename (const char*) the path to the database to open
 * @param ckvs (struct CKVS*) the struct that will be initialized
 * @return int, error code
 */
int ckvs_open(const char *filename, struct CKVS *ckvs);

/**
 * @brief Closes the CKVS database and releases its resources.
 * If the given pointer or the pointed CKVS databse is NULL, nothing is done.
 *
 * @param ckvs (struct CKVS*) the ckvs database to close
 */
void ckvs_close(struct CKVS *ckvs);

/**
 * @brief Finds the entry with the given (key, auth_key) pair in the ckvs database. If an entry is found, e_out points
 * to a pointer pointing at this entry. If no entry is found but the ckvs database is not full, then it points
 * to the first empty entry encountered. Otherwise it is set to NULL.
 *
 * @param ckvs (struct CKVS*) the ckvs database to search
 * @param key (const char*) the key of the entry
 * @param auth_key (const struct ckvs_sha*) the auth_key of the entry
 * @param e_out (struct ckvs_entry**) points to a pointer to an entry. If an entry is found, it points to a pointer
 * pointing at this entry. If no entry is found but the ckvs database is not full, then it points to the first empty
 * entry encountered. Otherwise it is set to NULL.
 * @return int, error code
 */
int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out);

/**
 * @brief Writes the already encrypted value at the end of the CKVS database,
 * then updates and overwrites the entry accordingly. Does not close the database
 * under any circumstances.
 *
 * @param ckvs (struct CKVS*) the ckvs database to search
 * @param e (struct ckvs_entry *e) the entry to which the secret belongs
 * @param buf (const unsigned char*) the encrypted value to write
 * @param buflen (uint64_t) the length of buf
 * @return int, error code
 */
int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e, const unsigned char *buf, uint64_t buflen);

/**
 * @brief Reads the file at filename, then allocates a buffer to dumps the file content into.
 * Do not forget to free the allocated pointed buffer.
 * If an error occurs, the parameters are not modified and the allocated buffer is freed.
 * The buffer pointed by buffer_ptr is always null-terminated at buffer_size
 *
 * @param filename (const char*) the name of the file to open
 * @param buffer_ptr (char**) the pointer to the content of the file
 * @param buffer_size (size_t*) the size of the read content
 * @return int, error code
 */
int read_value_file_content(const char* filename, char** buffer_ptr, size_t* buffer_size);

/**
 * @brief Creates a new entry in ckvs with the given (key, auth_key) pair, if possible.
 *
 * @param ckvs (struct CKVS*) the ckvs database to search
 * @param key (const char*) the key of the new entry
 * @param auth_key (const struct ckvs_sha*) the auth_key of the new entry
 * @param e_out (struct ckvs_entry**) points to a pointer to an entry. Used to store the pointer to the created entry, if any.
 * @return int, error code
 */
int ckvs_new_entry(struct CKVS *ckvs, const char *key, struct ckvs_sha *auth_key, struct ckvs_entry **e_out);

