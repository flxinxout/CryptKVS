#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ckvs.h"
#include "ckvs_utils.h"
#include "ckvs_crypto.h"
#include "util.h"

//============================== HEADER ==============================
void print_header(const struct ckvs_header* header) {
    M_CHECK_NON_NULL(header);

#define HEADER_S_FORMAT "%-23s: %s\n"
#define HEADER_U_FORMAT "%-23s: %u\n"

    pps_printf(HEADER_S_FORMAT, "CKVS Header type", header->header_string);
    pps_printf(HEADER_U_FORMAT, "CKVS Header version", header->version);
    pps_printf(HEADER_U_FORMAT, "CKVS Header table_size", header->table_size);
    pps_printf(HEADER_U_FORMAT, "CKVS Header threshold", header->threshold_entries);
    pps_printf(HEADER_U_FORMAT, "CKVS Header num_entries", header->num_entries);
}

//============================== ENTRIES ==============================
#define PADDING  "    "

void print_entry(const struct ckvs_entry* entry) {
    M_CHECK_NON_NULL(entry);

    pps_printf(PADDING ENTRY_KEY_FORMAT, "Key   ", entry->key);
    pps_printf(PADDING ENTRY_VALUE_FORMAT, "Value ", entry->value_off, entry->value_len);
    print_SHA(PADDING "Auth  ", &entry->auth_key);
    print_SHA(PADDING "C2    ", &entry->c2);
}

//============================== SHA ==============================
void print_SHA(const char *prefix, const struct ckvs_sha *sha) {
    M_CHECK_NON_NULL(prefix);
    M_CHECK_NON_NULL(sha);

#define ENTRY_SHA_FORMAT  "%-5s: %s\n"

    char buffer[SHA256_PRINTED_STRLEN];
    SHA256_to_string(sha, buffer);

    pps_printf(ENTRY_SHA_FORMAT, prefix, buffer);
}

//===========================================================================
void SHA256_to_string(const struct ckvs_sha *sha, char *buf) {
    M_CHECK_NON_NULL(sha);
    M_CHECK_NON_NULL(buf);

    hex_encode(sha->sha, SHA256_DIGEST_LENGTH, buf);
}

//===========================================================================
void hex_encode(const uint8_t *in, size_t len, char *buf) {
    M_CHECK_NON_NULL(in);
    M_CHECK_NON_NULL(buf);

    for (size_t i = 0; i < len; i++) {
        sprintf(buf + 2*i, "%02x", in[i]);
    }
}

//===========================================================================
int ckvs_cmp_sha(const struct ckvs_sha *a, const struct ckvs_sha *b) {
    return memcmp(a, b, SHA256_DIGEST_LENGTH);
}

//===========================================================================
int SHA256_from_string(const char *input, struct ckvs_sha *sha) {
    M_REQUIRE_NON_NULL(input);
    M_REQUIRE_NON_NULL(sha);
    M_REQUIRE(strlen(input) < SHA256_PRINTED_STRLEN, ERR_INVALID_ARGUMENT);

    return hex_decode(input, sha->sha);
}

//===========================================================================
int hex_decode(const char *input, uint8_t *buf) {
#define ERR_DECODE -1
    M_REQUIRE(input != NULL, ERR_DECODE);
    M_REQUIRE(buf != NULL, ERR_DECODE);

    char copy[3]; // Buffer where each nibble of the input is copied
    memset(copy, 0, sizeof(copy));

    const size_t in_len = strlen(input);
    char* input_copy = calloc(in_len + 2, sizeof(char));
    M_REQUIRE(input_copy != NULL, ERR_DECODE);

    input_copy[0] = '0';
    memcpy((in_len & 1) == 0 ? input_copy : input_copy + 1, input, in_len);

    size_t i = 0;
    size_t half_len = strlen(input_copy) / 2;
    for (i = 0; i < half_len; i++) {
        memcpy(copy, input_copy + 2*i, 2*sizeof(char));

        errno = 0;
        buf[i] = (uint8_t) strtoul(copy, NULL, 16);
        if(errno != 0) {
            free(input_copy);
            return ERR_DECODE;
        }
    }

    free(input_copy);
    return (int) i;
}
