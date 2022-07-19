#include "ckvs_client.h"
#include "ckvs_crypto.h"
#include "error.h"
#include "ckvs_rpc.h"
#include "ckvs_utils.h"
#include "util.h"
#include "ckvs.h"
#include "ckvs_io.h"
#include "json_utils.h"

#include "openssl/rand.h"
#include "openssl/evp.h"
#include <json-c/json.h>

#include <stdlib.h>

//===========================================================================
/**
 * @brief M_JSON_EXTRACT_KEY macro gets the entry with the given key in the given json_object and places
 * it in json_content. If an error occurs, it puts json_object and exits with an error code.
 *
 * @param json_object (const json_object*) json object in which the key will be extracted
 * @param key (const char*) the key to be extracted
 * @param json_content (json_object**) json object where to store the content associated with the given key
 */
#define M_JSON_EXTRACT_KEY(json_object, key, json_content, expected_type)  \
    do { \
        json_bool key_found = json_object_object_get_ex(json_object, key, json_content); \
        if(!key_found || json_object_get_type(*json_content) != expected_type) { \
            M_JSON_PUT_REQUIRE(json_object); \
            M_EXIT(ERR_IO); \
        } \
    } while(0)

//===========================================================================
/**
 * @brief Create a json object for the ckvs_post request
 *
 * @param json_post (struct json_object**) a pointer on the pointer of the json_object that will contain the data and c2
 *                                         hex-encoded
 * @param hex_c2 the hex-encoded c2 value
 * @param hex_data the hex-encoded data value
 * @return int, an error code
 */
static int create_json_post(struct json_object** json_post, const char* hex_c2, const char* hex_data);

//===========================================================================
/**
 * @brief Creates a struct ckvs_header from the given json_object by reading the corresponding keys
 * and places it in the given struct ckvs_header.
 * If an error occurs, the given header isn't modified but json_header is put.
 *
 * @param json_header (const struct json_object*) pointer on the json object containing the keys corresponding to a header
 * @param header (ckvs_header_t*) pointer on the header that will be computed
 * @return int, an error code
 */
static int fetch_header(struct json_object* json_header, ckvs_header_t* header);

//===========================================================================
/**
 * @brief Prints each key of the given json_object which should be of type json_type_array.
 *
 * @param json_keys (struct json_object**) pointer to a pointer to the json_object containing the array of keys.
 * @return int, an error code
 */
static int print_keys(const struct json_object* json_keys);

//===========================================================================
/**
 * @brief Makes a GET request to the server with a pair of key/authentication key.
 * The method does not close the connection and does not curl_free the escaped key
 * under any circumstances.
 * Both key are assumed to be NULL-terminated
 *
 * @param conn (ckvs_connection_t*) the connection
 * @param key_escaped (const char*) the key (NULL-terminated)
 * @param auth_key (char*) the authentication key (NULL-terminated)
 * @return int, an error code
 */
static int do_get_request(ckvs_connection_t* conn, char* key_escaped, char* auth_key);

//===========================================================================
/**
 * @brief Decodes the given encoded data nibble after nibble and store it in decoded_data and the
 * its size in data_len if no error occurs.
 * The decoded data is allocated, DO NOT FORGET TO FREE IT.
 *
 * @param encoded_data (const char*) the data to decode
 * @param decoded_data (char**) where to store the decoded data
 * @param decoded_data_len (size_t*) where to store the length of the decoded data
 * @return int, an error code
 */
static int decode_data(const char* encoded_data, char** decoded_data, size_t* decoded_data_len);

//===========================================================================
int ckvs_client_stats(const char* url, int optargc, _unused char* optargv[]) {
    M_REQUIRE_NON_NULL(url);
    M_REQUIRE_NON_NULL(optargv);
    M_CHECK_ARG_COUNT(optargc, STATS_ARGC);

    int err_code = ERR_NONE;

    //---------- INIT CONNECTION ----------
    ckvs_connection_t conn;
    err_code = ckvs_rpc_init(&conn, url);
    M_REQUIRE_NO_ERROR(err_code);

    //---------- REQUEST STATS ----------
    err_code = ckvs_rpc(&conn, STATS_PATTERN);
    if(err_code != ERR_NONE) {
        pps_printf("%s", conn.resp_buf);
        ckvs_rpc_close(&conn);
        M_EXIT(err_code);
    }

    //---------- PARSING JSON HEADER ----------
    struct json_object* json_header = json_tokener_parse(conn.resp_buf);
    if(json_header == NULL) {
        pps_printf("%s", conn.resp_buf);
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_IO);
    }

    //---------- FETCH AND PRINT HEADER ----------
    {
        ckvs_header_t header;
        memset(&header, 0, sizeof(header));
        err_code = fetch_header(json_header, &header);
        if(err_code != ERR_NONE) {
            ckvs_rpc_close(&conn);
            M_EXIT(err_code);
        }
        print_header(&header);
    }

    //---------- FETCH AND PRINT KEYS ----------
    {
        struct json_object* json_keys = NULL;
        json_bool key_found = json_object_object_get_ex(json_header, "keys", &json_keys);
        if(!key_found || json_object_get_type(json_keys) != json_type_array) {
            ckvs_rpc_close(&conn);
            M_JSON_PUT_REQUIRE(json_header);
            M_EXIT(ERR_IO);
        }

        err_code = print_keys(json_keys);
        if(err_code != ERR_NONE) {
            ckvs_rpc_close(&conn);
            M_JSON_PUT_REQUIRE(json_header);
            M_EXIT(err_code);
        }
    }

    //---------- PUT JSON AND CLOSE CONNECTION ----------
    ckvs_rpc_close(&conn);
    M_JSON_PUT_REQUIRE(json_header);
    M_EXIT(ERR_NONE);
}

//===========================================================================
int ckvs_client_get(const char *url, int optargc, char **optargv) {
    M_REQUIRE_NON_NULL(url);
    M_REQUIRE_NON_NULL(optargv);
    M_CHECK_ARG_COUNT(optargc, GET_ARGC);

    //---------- TREAT ARGS ----------
    const char* key = optargv[0];
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_KEY_NON_EMPTY(key);

    const char* pwd = optargv[1];
    M_REQUIRE_NON_NULL(pwd);

    int err_code = ERR_NONE;

    //---------- INIT CONNECTION ----------
    ckvs_connection_t conn;
    err_code = ckvs_rpc_init(&conn, url);
    M_REQUIRE_NO_ERROR(err_code);

    //---------- ESCAPING KEY ----------
    char* key_escaped = curl_easy_escape(conn.curl, key, 0);
    if(key_escaped == NULL) {
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_IO);
    }

    //---------- ENCRYPT AND HEX-ENCODE AUTH KEY ----------
    char auth_key[SHA256_PRINTED_STRLEN];
    memset(auth_key, 0, sizeof(auth_key));

    ckvs_memrecord_t mr;
    err_code = ckvs_client_encrypt_pwd(&mr, key, pwd);
    if(err_code != ERR_NONE) {
        curl_free(key_escaped);
        ckvs_rpc_close(&conn);
        M_EXIT(err_code);
    }

    SHA256_to_string(&mr.auth_key, auth_key);

    //---------- SERVER CALL ----------
    err_code = do_get_request(&conn, key_escaped, auth_key);
    if(err_code != ERR_NONE) {
        curl_free(key_escaped);
        ckvs_rpc_close(&conn);
        M_EXIT(err_code);
    }

    //---------- FETCH JSON ANSWER ----------
    struct json_object* json_get = json_tokener_parse(conn.resp_buf);
    if(json_get == NULL) {
        pps_printf("%s\n", conn.resp_buf); // we print the error contained in the json response
        curl_free(key_escaped);
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_IO);
    }

    /*
     * We don't modularize the extraction and the hex-decoding of the c2 and the data because they have some differences
     * in the process and the local get has not many similarities with the client get (with the database etc...).
     */
    //---------- EXTRACT C2 ----------
    struct json_object* json_value = NULL;
    ckvs_sha_t c2;
    memset(&c2, 0, sizeof(c2));

    json_bool key_found = json_object_object_get_ex(json_get, "c2", &json_value);
    if(!key_found || json_object_get_type(json_value) != json_type_string) {
        curl_free(key_escaped);
        ckvs_rpc_close(&conn);
        M_JSON_PUT_REQUIRE(json_get);
        M_EXIT(ERR_IO);
    }

    //---------- HEX-DECODE C2 ----------
    char* encoded_c2 = json_object_get_string(json_value);
    err_code = SHA256_from_string(encoded_c2, &c2);
    if(err_code == -1) {
        curl_free(key_escaped);
        ckvs_rpc_close(&conn);
        M_JSON_PUT_REQUIRE(json_get);
        M_EXIT(ERR_IO);
    }

    //---------- EXTRACT DATA ----------
    key_found = json_object_object_get_ex(json_get, "data", &json_value);
    if(!key_found || json_object_get_type(json_value) != json_type_string) {
        curl_free(key_escaped);
        ckvs_rpc_close(&conn);
        M_JSON_PUT_REQUIRE(json_get);
        M_EXIT(ERR_IO);
    }

    char* encoded_data = json_object_get_string(json_value);

    //---------- HEX-DECODE DATA ----------
    size_t cipher_len = 0;
    char* cipher = NULL;

    err_code = decode_data(encoded_data, &cipher, &cipher_len);
    if(err_code != ERR_NONE) {
        curl_free(key_escaped);
        ckvs_rpc_close(&conn);
        M_JSON_PUT_REQUIRE(json_get);
        M_EXIT(err_code);
    }

    //---------- COMPUTE MASTER KEY ----------
    err_code = ckvs_client_compute_masterkey(&mr, &c2);
    if(err_code != ERR_NONE) {
        free(cipher);
        curl_free(key_escaped);
        ckvs_rpc_close(&conn);
        M_JSON_PUT_REQUIRE(json_get);
        M_EXIT(err_code);
    }

    //---------- COMPUTE PLAINTEXT ----------
    size_t written_size = 0;
    unsigned char* plaintext = NULL;
    err_code = crypt_cipher(&mr, 0, (unsigned char*) cipher, cipher_len, &plaintext, &written_size);
    if(err_code != ERR_NONE) {
        free(cipher);
        curl_free(key_escaped);
        ckvs_rpc_close(&conn);
        M_JSON_PUT_REQUIRE(json_get);
        M_EXIT(err_code);
    }

    pps_printf("%s\n", plaintext);

    free(cipher);
    free(plaintext);
    curl_free(key_escaped);
    ckvs_rpc_close(&conn);
    M_JSON_PUT_REQUIRE(json_get);
    M_EXIT(ERR_NONE);
}

//===========================================================================
int ckvs_client_set(const char *url, int optargc, char **optargv) {
    M_REQUIRE_NON_NULL(url);
    M_REQUIRE_NON_NULL(optargv);
    M_CHECK_ARG_COUNT(optargc, SET_ARGC);

    const char* key = optargv[0];
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_KEY_NON_EMPTY(key);

    const char* pwd = optargv[1];
    M_REQUIRE_NON_NULL(pwd);

    const char* valuefilename = optargv[2];
    M_REQUIRE_NON_NULL(valuefilename);

    //---------- MEMRECORD ----------
    ckvs_memrecord_t mr;
    int err_code = ckvs_client_encrypt_pwd(&mr, key, pwd);
    M_REQUIRE_NO_ERROR(err_code);

    //---------- C2 ----------
    ckvs_sha_t c2;
    memset(&c2, 0, sizeof(c2));

    err_code = RAND_bytes(c2.sha, SHA256_DIGEST_LENGTH);
    //TODO THAT THING CAUSES THE ERROR I DONT UNDERSTAND: M_REQUIRE(err == 1, ERR_IO);

    //---------- HEX ENCODE C2 ----------
    char hex_c2[SHA256_PRINTED_STRLEN];
    memset(hex_c2, 0, sizeof(hex_c2));
    hex_encode((uint8_t*) c2.sha, strnlen((char *) c2.sha, SHA256_DIGEST_LENGTH), hex_c2);

    //---------- MASTER KEY ----------
    err_code = ckvs_client_compute_masterkey(&mr, &c2);
    M_REQUIRE_NO_ERROR(err_code);

    //---------- READ SET VALUE ----------
    char* content = NULL;
    size_t content_size = 0;

    err_code = read_value_file_content(valuefilename, &content, &content_size);
    M_REQUIRE_NO_ERROR(err_code);
    size_t cipher_len = strlen(content) + 1 + EVP_MAX_BLOCK_LENGTH;

    //---------- ENCRYPT VALUE ----------
    unsigned char* cipher = NULL;
    size_t written_size = 0;
    err_code = crypt_cipher(&mr, 1, (unsigned char*) content, strlen(content), &cipher, &written_size);
    free(content);
    if(err_code != ERR_NONE) {
        free(cipher);
        M_EXIT(err_code);
    }

    //---------- HEX_ENCODE VALUE ----------
    char* hex_data = calloc(cipher_len * 2 + 1, sizeof(char)); // + 1 for '\0'
    if(hex_data == NULL) {
        free(cipher);
        M_EXIT(ERR_OUT_OF_MEMORY);
    }
    hex_encode(cipher, written_size, hex_data);

    //---------- INIT CONNECTION ----------
    ckvs_connection_t conn;
    err_code = ckvs_rpc_init(&conn, url);
    if(err_code != ERR_NONE) {
        free(hex_data);
        free(cipher);
        M_EXIT(err_code);
    }

    //---------- ESCAPING KEY ----------
    char* key_escaped = curl_easy_escape(conn.curl, key, 0);
    if(key_escaped == NULL) {
        //TODO: pps_printf(conn.respbuf) to test what comes out;
        free(hex_data);
        free(cipher);
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_IO);
    }

    //---------- HEX-ENCODE AUTH KEY ----------
    char hex_auth_key[SHA256_PRINTED_STRLEN];
    memset(hex_auth_key, 0, sizeof(hex_auth_key));

    SHA256_to_string(&mr.auth_key, hex_auth_key);

    //---------- CREATE URL ----------
#define NAME "data.json"
#define OFFSET "0"

#define KEY_PREFIX      "key="
#define AUTH_KEY_PREFIX "auth_key="
#define NAME_PREFIX     "name="
#define OFFSET_PREFIX   "offset="
#define ROUTE_LENGTH strlen(SET_PATTERN) + 1 + \
        1 + strlen(KEY_PREFIX) + \
        strlen(key_escaped) + \
        1 + strlen(AUTH_KEY_PREFIX) + \
        strlen(hex_auth_key) + \
        1 + strlen(NAME_PREFIX) +\
        strlen(NAME) + \
        1 + strlen(OFFSET_PREFIX) + \
        strlen(OFFSET)

    char* route = calloc(ROUTE_LENGTH + 1, sizeof(char));
    if(route == NULL) {
        free(hex_data);
        curl_free(key_escaped);
        free(cipher);
        ckvs_rpc_close(&conn);
        M_EXIT(ERR_OUT_OF_MEMORY);
    }

    strcat(route, SET_PATTERN"?");
    strcat(route, "&"KEY_PREFIX);
    strcat(route, key_escaped);
    strcat(route, "&"AUTH_KEY_PREFIX);
    strcat(route, hex_auth_key);
    strcat(route, "&"NAME_PREFIX);
    strcat(route, NAME);
    strcat(route, "&"OFFSET_PREFIX);
    strcat(route, OFFSET);

    //---------- CREATE JSON POST ----------
    struct json_object* json_post = NULL;
    err_code = create_json_post(&json_post, hex_c2, hex_data);
    if(err_code != ERR_NONE) {
        free(hex_data);
        curl_free(key_escaped);
        free(route);
        free(cipher);
        ckvs_rpc_close(&conn);
        M_EXIT(err_code);
    }

    //---------- DO THE POST REQUEST ----------
    err_code = ckvs_post(&conn, route, json_object_to_json_string(json_post));

    free(hex_data);
    curl_free(key_escaped);
    free(route);
    free(cipher);
    ckvs_rpc_close(&conn);
    M_JSON_PUT_REQUIRE(json_post);
    M_EXIT(err_code);
}

// ======================================================================
static int create_json_post(struct json_object** json_post, const char* hex_c2, const char* hex_data) {
    M_REQUIRE_NON_NULL(json_post);
    M_REQUIRE_NON_NULL(hex_c2);
    M_REQUIRE_NON_NULL(hex_data);

    struct json_object* json_root = json_object_new_object();

    M_JSON_ADD_NEW(json_root, json_object_new_string, hex_c2, "c2");

    M_JSON_ADD_NEW(json_root, json_object_new_string, hex_data, "data");

    *json_post = json_root;
    M_EXIT(ERR_NONE);
}

//===========================================================================
int ckvs_client_new(const char *url, int optargc, char **optargv) {
    return NOT_IMPLEMENTED;
}

//===========================================================================
static int fetch_header(struct json_object* json_header, ckvs_header_t* header) {
    M_REQUIRE_NON_NULL(json_header);
    M_REQUIRE_NON_NULL(header);

    ckvs_header_t header_copy;
    memset(&header_copy, 0, sizeof(header_copy));
    struct json_object* json_content = NULL;

    //---------- HEADER_STRING ---------- (here we don't modularise further because it wouldn't spare any line)
    M_JSON_EXTRACT_KEY(json_header, HEADER_STRING_NAME, &json_content, json_type_string);
    strncpy(header_copy.header_string, json_object_get_string(json_content), CKVS_HEADERSTRINGLEN);

    //---------- VERSION ----------
    M_JSON_EXTRACT_KEY(json_header, VERSION_NAME, &json_content, json_type_int);
    header_copy.version = (uint32_t) json_object_get_int(json_content); /* No need to check errors
                                                                         * since the type of the
                                                                         * json_content is checked
                                                                         * to be int in M_EXTRACT_KEY */

    //---------- TABLE_SIZE ----------
    M_JSON_EXTRACT_KEY(json_header, TABLE_SIZE_NAME, &json_content, json_type_int);
    header_copy.table_size = (uint32_t) json_object_get_int(json_content);

    //---------- THRESHOLD_ENTRIES ----------
    M_JSON_EXTRACT_KEY(json_header, THRESHOLD_ENTRIES_NAME, &json_content, json_type_int);
    header_copy.threshold_entries = (uint32_t) json_object_get_int(json_content);

    //---------- NUM_ENTRIES ----------
    M_JSON_EXTRACT_KEY(json_header, NUM_ENTRIES_NAME, &json_content, json_type_int);
    header_copy.num_entries = (uint32_t) json_object_get_int(json_content);

    *header = header_copy;
    M_EXIT(ERR_NONE);
}

//===========================================================================
static int print_keys(const struct json_object* json_keys) {
    M_REQUIRE_NON_NULL(json_keys);
    M_REQUIRE(json_object_get_type(json_keys) == json_type_array, ERR_INVALID_ARGUMENT);

    struct json_object* json_key = NULL;

    size_t length = json_object_array_length(json_keys);
    for (size_t i = 0; i < length; i++) {
        json_key = json_object_array_get_idx(json_keys, i);
        if(json_key == NULL || json_object_get_type(json_key) != json_type_string) {
            M_EXIT(ERR_IO);
        }

        pps_printf(ENTRY_KEY_FORMAT, "Key       ", json_object_get_string(json_key));
    }

    M_EXIT(ERR_NONE);
}

//===========================================================================
static int do_get_request(ckvs_connection_t* conn, char* key_escaped, char* auth_key) {
    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(key_escaped);
    M_REQUIRE_NON_NULL(auth_key);

    //---------- CREATION OF THE ROUTE ----------
#define KEY_PREFIX "key="
#define AUTH_KEY_PREFIX "auth_key="
#define ROUTE_GET_LENGTH strlen(GET_PATTERN) + 1 + \
        strlen(KEY_PREFIX) + \
        strlen(key_escaped) + \
        strlen(AUTH_KEY_PREFIX) + 1 + \
        strlen(auth_key)

    int err_code = ERR_NONE;

    char* route = calloc(ROUTE_GET_LENGTH + 1, sizeof(char));
    M_REQUIRE(route != NULL, ERR_OUT_OF_MEMORY);

    strcat(route, GET_PATTERN"?");
    strcat(route, KEY_PREFIX);
    strcat(route, key_escaped);
    strcat(route, "&"AUTH_KEY_PREFIX);
    strcat(route, auth_key);

    //---------- MAKE REQUEST ----------
    err_code = ckvs_rpc(conn, route);
    if(err_code != ERR_NONE) {
        free(route);
        M_EXIT(err_code);
    }

    free(route);
    M_EXIT(ERR_NONE);
}

//===========================================================================
static int decode_data(const char* encoded_data, char** decoded_data, size_t* decoded_data_len) {
    M_REQUIRE_NON_NULL(encoded_data);
    M_REQUIRE_NON_NULL(decoded_data);
    M_REQUIRE_NON_NULL(decoded_data_len);

    size_t data_len = strlen(encoded_data) / 2;

    char* data_copy = calloc(data_len + 1, sizeof(encoded_data[0]));
    M_REQUIRE(data_copy != NULL, ERR_OUT_OF_MEMORY);

    int err_code = hex_decode(encoded_data, ((uint8_t*) (data_copy)));
    if(err_code == -1) {
        free(data_copy);
        M_EXIT(ERR_IO);
    }

    *decoded_data_len = data_len;
    *decoded_data = data_copy;
    M_EXIT(ERR_NONE);
}