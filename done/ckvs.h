/**
 * @file ckvs.h
 * @brief On-disk data structures for CKVS (encrypted key-value store)
 *
 * @author E. Bugnion
 */

#pragma once

#include "ckvs_utils.h"
#include "error.h"
#include <stdint.h>
#include <stdio.h>

/**
 * @brief Expected arguments number for the stats command
 */
#define STATS_ARGC 0

/**
 * @brief Expected arguments number for the get command
 */
#define GET_ARGC 2

/**
 * @brief Expected arguments number for the set command
 */
#define SET_ARGC 3

/**
 * @brief Expected arguments number for the new command
 */
#define NEW_ARGC 2

/**
 * @brief Name of the field "header_string" of the json values
 */
#define HEADER_STRING_NAME "header_string"

/**
 * @brief Name of the field "version" of the json values
 */
#define VERSION_NAME "version"

/**
 * @brief Name of the field "table_size" of the json values
 */
#define TABLE_SIZE_NAME "table_size"

/**
 * @brief Name of the field "threshold_entries" of the json values
 */
#define THRESHOLD_ENTRIES_NAME "threshold_entries"

/**
 * @brief Name of the field "num_entries" of the json values
 */
#define NUM_ENTRIES_NAME "num_entries"

/**
 * @brief Maximum length of the field header_string in ckvs_header.
 */
#define CKVS_HEADERSTRINGLEN 32
/**
 * @brief Value of the prefix header_string in ckvs_header.
 */
#define CKVS_HEADERSTRING_PREFIX "CS212 CryptKVS"
/**
 * @brief Maximum length for an entry's key.
 */
#define CKVS_MAXKEYLEN  32
/**
 * @brief Absolute maximum table_size for a CKVS database.
 */
#define CKVS_MAX_ENTRIES (1<<22)

/**
 * @brief Represents a CKVS database header.
 */
struct ckvs_header {
    char header_string[CKVS_HEADERSTRINGLEN]; /**< should be CKVS_HEADERSTRING */
    uint32_t  version;                        /**< should be 1 */
    uint32_t  table_size;                     /**< must be a power of 2 */
    uint32_t  threshold_entries;              /**< max effective capacity */
    uint32_t  num_entries;                    /**< number of valid entries */
};

/**
 * @brief Represents a CKVS database entry.
 */
struct ckvs_entry {
    char key[CKVS_MAXKEYLEN];  /**< not (necessarily) null-terminated */
    struct ckvs_sha auth_key;  /**< as specified by protocol */
    struct ckvs_sha c2;        /**< as specified by protocol */
    uint64_t value_off;        /**< offset of encrypted secret value in database */
    uint64_t value_len;        /**< length of encrypted secret value in database */
};

// convenience typedefs
typedef struct ckvs_header ckvs_header_t;
typedef struct ckvs_entry  ckvs_entry_t;

