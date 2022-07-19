#include <stdio.h>
#include <string.h>
#include "ckvs.h"
#include "ckvs_utils.h"
#include "util.h"

//===========================================================================
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

//===========================================================================
void print_entry(const struct ckvs_entry* entry) {
    M_CHECK_NON_NULL(entry);

#define PADDING  "    "
#define ENTRY_KEY_FORMAT PADDING"%-5s: "STR_LENGTH_FMT(CKVS_MAXKEYLEN)"\n"
#define ENTRY_VALUE_FORMAT  PADDING"%-5s: off %lu len %lu\n"

    pps_printf(ENTRY_KEY_FORMAT, "Key   ", entry->key);
    pps_printf(ENTRY_VALUE_FORMAT, "Value ", entry->value_off, entry->value_len);
    print_SHA(PADDING"Auth  ", &entry->auth_key);
    print_SHA(PADDING"C2    ", &entry->c2);
}

//===========================================================================
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

    size_t ratio = SHA256_PRINTED_STRLEN / SHA256_DIGEST_LENGTH;
    for (size_t i = 0; i < len; i++) {
        sprintf(buf + ratio*i, "%02x", in[i]);
    }
}

//===========================================================================
int ckvs_cmp_sha(const struct ckvs_sha *a, const struct ckvs_sha *b) {
    return memcmp(a, b, SHA256_DIGEST_LENGTH);
}