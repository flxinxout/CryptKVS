#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "ckvs.h"
#include "ckvs_io.h"

/**
 * @brief Checks if an unsigned 32 bits integer is a power of 2
 * 
 * @param n (uint32_t) the unsigned 32 bits number
 * @return iff the number n is a power of 2
 */
bool is_power_of_2(uint32_t n);

/**
 * @brief Initializes and reads the header of a CKVS database file (input) and places it in header.
 * Does not close the file under any circumstances.
 * The pointed header isn't modified if an error has occured.
 *
 * @param header (ckvs_header_t*) the header in which the read content will be placed
 * @param input (FILE*) the file where to read
 * @return int, an error code
 */
int read_header(ckvs_header_t* header, FILE* input);

/**
 * @brief Initilizes and reads the entries_nb entries of a CKVS database file (input) and places it in entries.
 * Does not close the file under any circumstances. Allocates a new chunk of memory: DO NOT FORGET TO FREE IT.
 * The pointed entries aren't modified and the allocated chunk is already freed if an error has occured.
 *
 * @param entries (ckvs_entry_t**) the pointer to the entries in which the read content will be placed
 * @param input (FILE*) the file where to read
 * @param entries_nb (const size_t) the number of entries to read
 * @return int, an error code
 */
int read_entries(ckvs_entry_t** entries, FILE* input, const size_t entries_nb);

/**
 * @brief Rewrites the entry in the file of the given CKVS database according to the current state of this database.
 * If the given index is not does not represent an actual entry index in the database, an error code is returned.
 *
 * @param ckvs (struct CKVS*) the database
 * @param idx (uint_32_t) the index of the entry that needs to be modified
 * @return int, an error code
 */
static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx);

/**
 * @brief Hashes the key to store it in the given ckvs database later (the store operation is not done in this function.
 *
 * @param ckvs (struct CKVS*) the database
 * @param key (const char*) the key to hash
 * @return uint32_t, the value
 */
static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key);

// ==========================================================================================
int ckvs_open(const char *filename, struct CKVS *ckvs) {
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(ckvs);

    int err_code = ERR_NONE;

    //---------- FILE OPENING ----------
    FILE* input = NULL;
    input = fopen(filename, "r+b");
    M_REQUIRE_FILE_OPENED(input, filename);

    //---------- HEADER BLOCK ----------
    ckvs_header_t header;
    {
        err_code = read_header(&header, input);

        if(err_code != ERR_NONE) {
            fclose(input);
            M_EXIT(err_code);
        }
    }

    //---------- ENTRIES BLOCK ----------
    size_t entries_nb = header.table_size;
    ckvs_entry_t* entries = NULL;
    {
        err_code = read_entries(&entries, input, entries_nb);

        if(err_code != ERR_NONE) {
            fclose(input);
            M_EXIT(err_code);
        }
    }

    //---------- AFFECT PARAMS ----------
    memset(ckvs, 0, sizeof(*ckvs));
    ckvs->file = input;
    ckvs->header = header;
    ckvs->entries = entries;

    M_EXIT(ERR_NONE);
}

// ==========================================================================================
void ckvs_close(struct CKVS *ckvs) {
    M_CHECK_NON_NULL(ckvs);

    if(ckvs->file != NULL) {
        fclose(ckvs->file);
        ckvs->file = NULL;
    }

    M_CHECK_NON_NULL(ckvs->entries);
    free(ckvs->entries);
    ckvs->entries = NULL;
}

// ==========================================================================================
int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out) {
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);
    M_REQUIRE_MSG(key[0] != '\0',
                  ERR_INVALID_ARGUMENT,
                  "%s", "The given key is empty (length of 0)");

    uint32_t hash = ckvs_hashkey(ckvs, key);

    for (size_t i = 0; i < ckvs->header.table_size; ++i) {
        size_t idx = (i + hash) & (ckvs->header.table_size - 1);
        char* cur_key = ckvs->entries[idx].key;

        if(strncmp(key, cur_key, CKVS_MAXKEYLEN) == 0) {
            ckvs_sha_t curr_auth = ckvs->entries[idx].auth_key;

            // Check that the auth_key is correct
            M_REQUIRE(ckvs_cmp_sha(&curr_auth, auth_key) == 0,
                      ERR_DUPLICATE_ID);

            *e_out = &(ckvs->entries[idx]);
            M_EXIT(ERR_NONE);

        } else if (cur_key[0] == '\0') {
            *e_out = &(ckvs->entries[idx]);
            M_EXIT(ERR_KEY_NOT_FOUND);
        }
    }

    *e_out = NULL;
    M_EXIT(ERR_KEY_NOT_FOUND);
}

// ==========================================================================================
int read_value_file_content(const char* filename, char** buffer_ptr, size_t* buffer_size) {
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(buffer_ptr);
    M_REQUIRE_NON_NULL(buffer_size);

    //---------- FILE OPENING ----------
    FILE* file = NULL;
    file = fopen(filename, "rb");
    M_REQUIRE_FILE_OPENED(file, filename);

    //---------- SIZE OF FILE ----------
    if(fseek(file, 0L, SEEK_END) != 0) {            // Go to end of file
        fclose(file);
        M_EXIT(ERR_IO);
    }

    long size_of_file = ftell(file);                // Save the current position in the file
    if(size_of_file < 0) {
        fclose(file);
        M_EXIT(ERR_IO);
    }
    size_t content_size = (size_t) size_of_file;

    if(fseek(file, 0L, SEEK_SET) != 0) {            // Go back to start of file
        fclose(file);
        M_EXIT(ERR_IO);
    }

    //---------- ALLOCATE CONTENT ----------
    char* content = calloc(content_size + 1, sizeof(char)); // +1 to ensure the last '\0' char
    if(content == NULL) {
        fclose(file);
        M_EXIT(ERR_OUT_OF_MEMORY);
    }

    //---------- READ CONTENT ----------
    size_t read_size = fread(content, sizeof(char), content_size, file);
    if(read_size != content_size) {
        fclose(file);
        free(content);
        M_EXIT(ERR_IO);
    }

    //---------- AFFECT PARAMS ----------
    *buffer_size = content_size + 1; // +1 to ensure the last '\0' char
    *buffer_ptr = content;

    fclose(file);
    M_EXIT(ERR_NONE);
}

// ==========================================================================================
int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e, const unsigned char *buf, uint64_t buflen) {
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(ckvs->file);
    M_REQUIRE_NON_NULL(ckvs->entries);
    M_REQUIRE_NON_NULL(e);
    M_REQUIRE_NON_NULL(buf);

    // Check that e is indeed a valid entry in ckvs->entries
    M_REQUIRE_MSG(e >= ckvs->entries && e < ckvs->entries + ckvs->header.table_size,
              ERR_INVALID_ARGUMENT,
              "%s", "the given entry pointer doesn't point inside the given ckvs database");
    M_REQUIRE_MSG(e->key[0] != '\0',
                  ERR_INVALID_ARGUMENT,
                  "%s", "the given entry pointer doesn't point to a valid entry");

    //---------- WRITE CONTENT ----------
    M_REQUIRE(fseek(ckvs->file, 0L, SEEK_END) == 0, ERR_IO);  // Go to the end of the file

    long value_off = ftell(ckvs->file);
    M_REQUIRE(value_off >= 0, ERR_IO);

    size_t written_size = fwrite(buf, sizeof(char),buflen,  ckvs->file);
    M_REQUIRE(written_size == buflen, ERR_IO);

    //---------- WRITE ENTRY ----------
    e->value_off = (uint64_t) value_off;
    e->value_len = buflen;
    uint32_t idx = (unsigned int) (e - ckvs->entries);
    error_code err_code = ckvs_write_entry_to_disk(ckvs, idx);
    M_REQUIRE_NO_ERROR(err_code);

    M_EXIT(ERR_NONE);
}

// ==========================================================================================
static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx) {
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(ckvs->file);
    M_REQUIRE_NON_NULL(ckvs->entries);
    M_REQUIRE_MSG(idx < CKVS_MAX_ENTRIES,
                  ERR_INVALID_ARGUMENT,
                  "Trying to write an entry to an index bigger than the max entries table size (%u >= %u).",
                  idx, CKVS_MAX_ENTRIES);

    /*
     * DATABASE STRUCTURE:
     * HEADER               =   48B
     * ONE ENTRY            =   112B
     * SIZE_TABLE ENTRIES   =   112B * SIZE_TABLE (112B * 64 FOR EXAMPLE)
     * ENTRIES CONTENT      =   REST OF THE FILE, CAN BE FOUND BY EACH ENTRY "VALUE_OFF" ATTRIBUTE
     */

    ckvs_entry_t entry = ckvs->entries[idx];

    size_t entry_offset = sizeof(ckvs_header_t) + sizeof(ckvs_entry_t) * idx;
    M_REQUIRE(fseek(ckvs->file, (long int) entry_offset, SEEK_SET) == 0, ERR_IO);

    size_t written_size = fwrite(&entry, sizeof(entry), 1, ckvs->file);
    M_REQUIRE(written_size == 1, ERR_IO);

    M_EXIT(ERR_NONE);
}

// ==========================================================================================
int ckvs_new_entry(struct CKVS *ckvs, const char *key, struct ckvs_sha *auth_key, struct ckvs_entry **e_out) {
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);
    M_REQUIRE_MSG(key[0] != '\0',
                  ERR_INVALID_ARGUMENT,
                  "%s", "The given key is empty (length of 0)");
    int err_code = ERR_NONE;

    CKVS_t ckvs_copy = *ckvs; // To keep everything as it was if an error occurs

    //---------- VERIFY ENOUGH PLACE ----------
    M_REQUIRE_MSG(ckvs_copy.header.num_entries < ckvs_copy.header.threshold_entries,
                  ERR_MAX_FILES,
                  "%s", "Can't add a new entry because there is no remaining space in the given ckvs database.");

    //---------- VERIFY KEY IS NOT TOO LONG ----------
    M_REQUIRE_MSG(strlen(key) <= CKVS_MAXKEYLEN,
                  ERR_INVALID_ARGUMENT,
                  "The key %s is too long",
                  key);

    //---------- POINTS TO NEW ENTRY (IF IT DOESN'T EXIST) ----------
    ckvs_entry_t* new_entry_p = NULL; //points directly to the effective ckvs entry
    err_code = ckvs_find_entry(&ckvs_copy, key, auth_key, &new_entry_p);

    //If the auth key is wrong, propagate the error
    M_REQUIRE(err_code != ERR_DUPLICATE_ID, ERR_DUPLICATE_ID);

    //If the entry already exists, or the auth key is wrong, return an error
    M_REQUIRE_MSG(err_code != ERR_NONE, ERR_DUPLICATE_ID,
                  "L'entrée voulant être créée avec la clé %s existe déjà",
                  key);

    //---------- INITIALIZE NEW ENTRY ----------
    strncpy(new_entry_p->key, key, CKVS_MAXKEYLEN);
    strncpy((char*) new_entry_p->auth_key.sha, (char*) auth_key->sha, SHA256_DIGEST_LENGTH);
    new_entry_p->value_len = 0;
    new_entry_p->value_off = 0;

    //---------- WRITE NEW ENTRY ----------
    uint32_t idx = (uint32_t) (new_entry_p - ckvs_copy.entries);
    err_code = ckvs_write_entry_to_disk(&ckvs_copy, idx);
    M_REQUIRE_NO_ERROR(err_code);

    //---------- WRITE NEW HEADER ----------
    ckvs_copy.header.num_entries += 1;

    M_REQUIRE(fseek(ckvs_copy.file, 0L, SEEK_SET) == 0, ERR_IO);

    size_t written_size = fwrite(&ckvs_copy.header, sizeof(ckvs_copy.header), 1, ckvs_copy.file);
    M_REQUIRE(written_size == 1, ERR_IO);

    *ckvs = ckvs_copy;
    *e_out = new_entry_p;
    M_EXIT(ERR_NONE);
}

// ==========================================================================================
static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key) {
    M_ASSERT_NON_NULL(ckvs);
    M_ASSERT_NON_NULL(key);

    unsigned char sha256[SHA256_DIGEST_LENGTH];
    memset(sha256, 0, sizeof(sha256));

    SHA256((const unsigned char*)key, strnlen(key, CKVS_MAXKEYLEN), sha256);
    uint32_t res =  (uint32_t) sha256[3] << 24  |
                    (uint32_t) sha256[2] << 16  |
                    (uint32_t) sha256[1] << 8   |
                    (uint32_t) sha256[0] << 0;

    res &= (ckvs->header.table_size - 1); // Here table_size is a power of 2
    return res;
}

// ==========================================================================================
int read_header(ckvs_header_t* header, FILE* input) {
    M_REQUIRE_NON_NULL(header);
    M_REQUIRE_NON_NULL(input);

#ifdef DEBUG
    const char* const err_mess = "Unable to read the header from the given file: ";
#endif

    ckvs_header_t res;
    memset(&res, 0, sizeof(res));

    size_t read_size = fread(&res, sizeof(res), 1, input);
    M_REQUIRE_MSG(read_size == 1,
              ERR_IO,
              "%s wrong read size.", err_mess);

    // Multiple calls to the same M_REQUIRE_MSG to facilitate debugging via custom messages and different line numbers
    M_REQUIRE_MSG(strncmp(res.header_string, CKVS_HEADERSTRING_PREFIX, strlen(CKVS_HEADERSTRING_PREFIX)) == 0,
              ERR_CORRUPT_STORE,
              "%s wrong header prefix.", err_mess);
    M_REQUIRE_MSG(res.version == 1,
              ERR_CORRUPT_STORE,
              "%s wrong header version.", err_mess);
    M_REQUIRE_MSG(is_power_of_2(res.table_size),
              ERR_CORRUPT_STORE,
              "%s the header table size is not a power of 2.", err_mess);

    *header = res;
    M_EXIT(ERR_NONE);
}

// ==========================================================================================
int read_entries(ckvs_entry_t** entries, FILE* input, const size_t entries_nb) {
    M_REQUIRE_NON_NULL(entries);
    M_REQUIRE_NON_NULL(input);

    ckvs_entry_t* res = calloc(entries_nb, sizeof(ckvs_entry_t));
    M_REQUIRE(res != NULL, ERR_OUT_OF_MEMORY);

    size_t read_size = fread(res, sizeof(res[0]), entries_nb, input);
    if(read_size != entries_nb) {
        free(res);
        M_EXIT(ERR_IO);
    }

    *entries = res;
    M_EXIT(ERR_NONE);
}

// ==========================================================================================
bool is_power_of_2(uint32_t n) {
    if (n == 0) {
        return false;
    }

    while (n != 1) {
        if ((n & 1) != 0) {
            return false;
        }
        n >>= 1;
    }

    return true;
}