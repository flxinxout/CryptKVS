/**
 * @file ckvs_httpd.c
 * @brief webserver
 *
 * @author Edouard Bugnion
 */

#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "error.h"
#include "ckvs_httpd.h"
#include <assert.h>
#include "libmongoose/mongoose.h"
#include <json-c/json.h>
#include <string.h>
#include <assert.h>
#include <curl/curl.h>
#include "util.h"
#include "json_utils.h"

// Handle interrupts, like Ctrl-C
static int s_signo;

#define HTTP_ERROR_CODE 500
#define HTTP_OK_CODE 200
#define HTTP_FOUND_CODE 302
#define HTTP_NOTFOUND_CODE 404

/**
 * @brief Handle the stats request from the client
 *
 * @param nc (struct mg_connection*) a pointer on the mg_connection struct
 * @param ckvs (struct CKVS*) a pointer on the CKVS database
 * @param hm (struct mg_http_message*) a pointer on the mg_http_message struct
 */
static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs, _unused struct mg_http_message *hm);

/**
 * @brief Creates the json_object of the header of the given ckvs database and places it in json_header
 * if no error occurs. If an error occurs, it returns an error code and it puts the newly created
 * json_object.
 *
 * @param json_header (struct json_object**) pointer to the json_object where to store the header
 * @param ckvs (const struct CKVS*) the database from which the header is taken
 * @return int, an error code
 */
static int create_json_header(struct json_object** json_header, const struct CKVS* ckvs);

/**
 * @brief Creates the json_object of the entries of the given ckvs database and places it in entries_array_json
 * if no error occurs. If an error occurs, it returns an error code and it puts the newly created
 * json_object.
 *
 * @param json_header (struct json_object**) pointer to the json_object where to store the entries array
 * @param ckvs (const struct CKVS*) the database from which the entries are taken
 * @return int, an error code
 */
static int create_json_entries(struct json_object** entries_array_json, const struct CKVS* ckvs);

/**
 * @brief Handle the get request from the client
 *
 * @param nc (struct mg_connection*) a pointer on the mg_connection struct
 * @param ckvs (struct CKVS*) a pointer on the CKVS database
 * @param hm (struct mg_http_message*) a pointer on the mg_http_message struct
 */
static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs, struct mg_http_message *hm);

/**
 * @brief Handle the set request from the client
 *
 * @param nc (struct mg_connection*) a pointer on the mg_connection struct
 * @param ckvs (struct CKVS*) a pointer on the CKVS database
 * @param hm (struct mg_http_message*) a pointer on the mg_http_message struct
 */
static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs, struct mg_http_message *hm);

/**
 * @brief Retrieve and url decode a variable inside a mg_http_message struct. DO NOT FORGET TO FREE THE RETURNED RESULT.
 *
 * @param hm (struct mg_http_message*) a pointer on the mg_http_message struct
 * @param arg (const char*) the argument to retrieve from the mg_http_message struct
 * @return char*, the argument url decoded
 */
static char* get_urldecoded_argument(struct mg_http_message *hm, const char *arg);

/**
 * @brief Sends an http error message
 * @param nc the http connection
 * @param err the error code corresponding the error message
*/
void mg_error_msg(struct mg_connection* nc, int err) {
    assert(err>=0 && err < ERR_NB_ERR);
    mg_http_reply(nc, HTTP_ERROR_CODE, NULL, "Error: %s", ERR_MESSAGES[err]);
}

/**
 * @brief Handles signal sent to program, eg. Ctrl+C
 */
static void signal_handler(int signo) {
    s_signo = signo;
}

// ======================================================================
/**
 * @brief Handles server events (eg HTTP requests).
 * For more check https://cesanta.com/docs/#event-handler-function
 */
static void ckvs_event_handler(struct mg_connection *nc, int ev, void *ev_data, void *fn_data) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct CKVS *ckvs = (struct CKVS*) fn_data;

    if (ev != MG_EV_POLL)
        debug_printf("Event received %d", ev);

    switch (ev) {
    case MG_EV_POLL:
    case MG_EV_CLOSE:
    case MG_EV_READ:
    case MG_EV_WRITE:
    case MG_EV_HTTP_CHUNK:
        break;

    case MG_EV_ERROR:
        debug_printf("httpd mongoose error \n");
        break;
    case MG_EV_ACCEPT:
        // students: no need to implement SSL
        assert(ckvs->listening_addr);
        debug_printf("accepting connection at %s\n", ckvs->listening_addr);
        assert (mg_url_is_ssl(ckvs->listening_addr) == 0);
        break;

    case MG_EV_HTTP_MSG:
        if(mg_http_match_uri(hm, STATS_PATTERN)) {
            // STATS
            handle_stats_call(nc, ckvs, hm);
        } else if(mg_http_match_uri(hm, GET_PATTERN)) {
            // GET
            handle_get_call(nc, ckvs, hm);
        } else if(mg_http_match_uri(hm, SET_PATTERN)) {
            // SET
            handle_set_call(nc, ckvs, hm);
        } else {
            mg_error_msg(nc, NOT_IMPLEMENTED);
        }
        break;

    default:
        fprintf(stderr, "ckvs_event_handler %u\n", ev);
        assert(0);
    }
}

// ======================================================================
int ckvs_httpd_mainloop(const char *filename, int optargc, char **optargv) {
    if (optargc < 1)
        return ERR_NOT_ENOUGH_ARGUMENTS;
    else if (optargc > 1)
        return ERR_TOO_MANY_ARGUMENTS;

    /* Create server */

    signal(SIGINT, signal_handler); //adds interruption signals to the signal handler
    signal(SIGTERM, signal_handler);

    struct CKVS ckvs;
    int err = ckvs_open(filename, &ckvs);

    if (err != ERR_NONE) {
        return err;
    }

    ckvs.listening_addr = optargv[0];

    struct mg_mgr mgr;
    struct mg_connection *c;

    mg_mgr_init(&mgr);

    c = mg_http_listen(&mgr, ckvs.listening_addr, ckvs_event_handler, &ckvs);
    if (c==NULL) {
        debug_printf("Error starting server on address %s\n", ckvs.listening_addr);
        ckvs_close(&ckvs);
        return ERR_IO;
    }

    debug_printf("Starting CKVS server on %s for database %s\n", ckvs.listening_addr, filename);

    while (s_signo == 0) {
        mg_mgr_poll(&mgr, 1000); //infinite loop as long as no termination signal occurs
    }
    mg_mgr_free(&mgr);
    ckvs_close(&ckvs);
    debug_printf("Exiting HTTPD server\n");
    return ERR_NONE;
}

// ======================================================================
static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs,
                              _unused struct mg_http_message *hm) {
    M_CHECK_NON_NULL(nc);
    M_CHECK_NON_NULL(ckvs);

    struct json_object* json_root = NULL;

    //---------- JSON HEADER ----------
    int err_code = create_json_header(&json_root, ckvs);
    if(err_code != ERR_NONE) {
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //---------- JSON ENTRIES ----------
    struct json_object* entries_array_json = NULL;

    err_code = create_json_entries(&entries_array_json, ckvs);
    if(err_code != ERR_NONE) {
        M_JSON_PUT_MG(json_root, nc);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    if(json_object_object_add(json_root, "keys", entries_array_json) < 0) {
        M_JSON_PUT_MG(entries_array_json, nc);
        M_JSON_PUT_MG(json_root, nc);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    mg_http_reply(nc, HTTP_OK_CODE, JSON_HEADER_OPT, "%s\n",
                  json_object_to_json_string(json_root));

    M_JSON_PUT_MG(json_root, nc);
}

// ======================================================================
static int create_json_header(struct json_object** json_header, const struct CKVS* ckvs) {
    M_REQUIRE_NON_NULL(json_header);
    M_REQUIRE_NON_NULL(ckvs);

    struct json_object* json_root = json_object_new_object();

    //---------- HEADER_STRING ----------
    M_JSON_ADD_NEW(json_root, json_object_new_string, ckvs->header.header_string, HEADER_STRING_NAME);

    //---------- VERSION ----------
    M_JSON_ADD_NEW(json_root, json_object_new_int, (int32_t) ckvs->header.version, VERSION_NAME);

    //---------- TABLE SIZE ----------
    M_JSON_ADD_NEW(json_root, json_object_new_int, (int32_t) ckvs->header.table_size, TABLE_SIZE_NAME);

    //---------- THRESHOLD ENTRIES----------
    M_JSON_ADD_NEW(json_root, json_object_new_int, (int32_t) ckvs->header.threshold_entries, THRESHOLD_ENTRIES_NAME);

    //---------- NUMBER ENTRIES ----------
    M_JSON_ADD_NEW(json_root, json_object_new_int, (int32_t) ckvs->header.num_entries, NUM_ENTRIES_NAME);

    *json_header = json_root;
    M_EXIT(ERR_NONE);
}

// ======================================================================
static int create_json_entries(struct json_object** entries_array_json, const struct CKVS* ckvs) {
    M_REQUIRE_NON_NULL(entries_array_json);
    M_REQUIRE_NON_NULL(ckvs);

    struct json_object* json_array = json_object_new_array_ext((int) ckvs->header.num_entries);
    uint32_t entries_number = ckvs->header.table_size;

    for(uint32_t i = 0; i < entries_number; i++) {
        if (ckvs->entries[i].key[0] != '\0') {
            struct json_object* entry = json_object_new_string(ckvs->entries[i].key);
            json_object_array_add(json_array, entry);
        }
    }

    *entries_array_json = json_array;
    M_EXIT(ERR_NONE);
}

// ======================================================================
static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs, struct mg_http_message *hm) {
    if (nc == NULL || ckvs == NULL || ckvs->file == NULL || hm == NULL) {
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return;
    }

    //---------- URL-DECODE KEY ----------
    char* key = get_urldecoded_argument(hm, "key");
    if (key == NULL) {
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return;
    }

    //---------- EXTRACT AUTH-KEY ----------
    char* hex_auth_key = get_urldecoded_argument(hm, "auth_key");
    if (hex_auth_key == NULL) {
        curl_free(key);
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return;
    }

    //---------- HEX-DECODE AUTH KEY ----------
    ckvs_sha_t auth_key;
    memset(&auth_key, 0, sizeof(auth_key));

    int err_code = SHA256_from_string(hex_auth_key, &auth_key);
    if (err_code == -1) {
        curl_free(key);
        curl_free(hex_auth_key);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //---------- FIND ENTRY ----------
    ckvs_entry_t *p_entry;
    err_code = ckvs_find_entry(ckvs, key, &auth_key, &p_entry);
    if (err_code != ERR_NONE) {
        curl_free(key);
        curl_free(hex_auth_key);
        mg_error_msg(nc, err_code);
        return;
    }

    if (p_entry->value_len == 0) {
        curl_free(key);
        curl_free(hex_auth_key);
        mg_error_msg(nc, ERR_NO_VALUE);
        return;
    }

    //---------- CREATE JSON RESPONSE ----------
    struct json_object* json_obj = json_object_new_object();

    //---------- HEX-ENCODE C2 ----------
    char hex_c2[SHA256_PRINTED_STRLEN];
    memset(hex_c2, 0, sizeof(hex_c2));
    hex_encode(p_entry->c2.sha, strnlen((char *) p_entry->c2.sha, SHA256_DIGEST_LENGTH), hex_c2);

    //---------- CREATE JSON C2 ----------
    struct json_object *c2_string_json = json_object_new_string(hex_c2);
    if (json_object_object_add(json_obj, "c2", c2_string_json) < 0) {
        curl_free(key);
        curl_free(hex_auth_key);
        M_JSON_PUT_MG(json_obj, nc);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //---------- DATA ----------
    //---------- READ CIPHER ----------
    unsigned char* cipher = calloc(p_entry->value_len + 1, sizeof(cipher[0])); //+1 to ensure the last '\0' char
    if (cipher == NULL) {
        curl_free(key);
        curl_free(hex_auth_key);
        M_JSON_PUT_MG(json_obj, nc);
        mg_error_msg(nc, ERR_OUT_OF_MEMORY);
        return;
    }

    err_code = fseek(ckvs->file,
                     (long int) p_entry->value_off,
                     SEEK_SET);

    if(err_code != 0) {
        curl_free(key);
        curl_free(hex_auth_key);
        M_JSON_PUT_MG(json_obj, nc);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    size_t read_size = fread(cipher,
                             sizeof(cipher[0]),
                             p_entry->value_len,
                             ckvs->file);

    if (read_size != p_entry->value_len) {
        free(cipher);
        curl_free(key);
        curl_free(hex_auth_key);
        M_JSON_PUT_MG(json_obj, nc);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    char* hex_data = calloc(p_entry->value_len * 2 + 1, sizeof(char));
    if (hex_data == NULL) {
        free(cipher);
        curl_free(key);
        curl_free(hex_auth_key);
        M_JSON_PUT_MG(json_obj, nc);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    hex_encode((uint8_t *) cipher, p_entry->value_len, hex_data);

    struct json_object* data_string_json = json_object_new_string(hex_data);
    if (json_object_object_add(json_obj, "data", data_string_json) < 0) {
        free(cipher);
        free(hex_data);
        curl_free(key);
        curl_free(hex_auth_key);
        M_JSON_PUT_MG(json_obj, nc);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    mg_http_reply(nc, HTTP_OK_CODE, JSON_HEADER_OPT, "%s\n",
                  json_object_to_json_string(json_obj));

    free(cipher);
    free(hex_data);
    curl_free(key);
    curl_free(hex_auth_key);
    M_JSON_PUT_MG(json_obj, nc);
}

// ======================================================================
static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs, struct mg_http_message *hm) {
    if (nc == NULL || ckvs == NULL || ckvs->file == NULL || hm == NULL) {
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return;
    }

    int err_code = 0;

    if(hm->body.len > 0) {
        err_code = mg_http_upload(nc, hm, "/tmp");
        if(err_code < 0) {
            mg_error_msg(nc, ERR_IO);
            return;
        }
    } else {
        //---------- URL-DECODE KEY ----------
        char* key = get_urldecoded_argument(hm, "key");
        if (key == NULL) {
            mg_error_msg(nc, ERR_INVALID_ARGUMENT);
            return;
        }

        //---------- EXTRACT AUTH-KEY ----------
        char* hex_auth_key = get_urldecoded_argument(hm, "auth_key");
        if (hex_auth_key == NULL) {
            curl_free(key);
            mg_error_msg(nc, ERR_INVALID_ARGUMENT);
            return;
        }

        //---------- HEX-DECODE AUTH KEY ----------
        ckvs_sha_t auth_key;
        memset(&auth_key, 0, sizeof(auth_key));

        err_code = SHA256_from_string(hex_auth_key, &auth_key);
        if (err_code == -1) {
            curl_free(key);
            curl_free(hex_auth_key);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        //---------- FIND ENTRY ----------
        ckvs_entry_t *p_entry;
        err_code = ckvs_find_entry(ckvs, key, &auth_key, &p_entry);
        if (err_code != ERR_NONE) {
            curl_free(key);
            curl_free(hex_auth_key);
            mg_error_msg(nc, err_code);
            return;
        }

        //---------- GET FILE NAME ----------
#define MAX_URLDECODED_ARG_LENGTH 1024
        char tmp_filename[MAX_URLDECODED_ARG_LENGTH + strlen("/tmp/")];
        strcpy(tmp_filename, "/tmp/");

        char name[MAX_URLDECODED_ARG_LENGTH] = "";
        if (mg_http_get_var(&hm->query, "name", name, sizeof(name)) <= 0) {
            curl_free(key);
            curl_free(hex_auth_key);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        strcat(tmp_filename, name);

        //---------- COPY TO TMP ----------
        FILE* tmp_file = fopen(tmp_filename, "r+b");
        if (tmp_file == NULL) {
            curl_free(key);
            curl_free(hex_auth_key);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        if(fseek(tmp_file, 0L, SEEK_END) != 0) {
            fclose(tmp_file);
            curl_free(key);
            curl_free(hex_auth_key);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        long size_of_file = ftell(tmp_file);
        if(size_of_file < 0) {
            fclose(tmp_file);
            curl_free(key);
            curl_free(hex_auth_key);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        char* json_str = calloc((size_t) size_of_file + 1, sizeof(char));
        if(json_str == NULL) {
            fclose(tmp_file);
            curl_free(key);
            curl_free(hex_auth_key);
            mg_error_msg(nc, ERR_OUT_OF_MEMORY);
            return;
        }

        if(fseek(tmp_file, 0L, SEEK_SET) != 0) {
            fclose(tmp_file);
            free(json_str);
            curl_free(key);
            curl_free(hex_auth_key);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        size_t read_size = fread(json_str, sizeof(char), (size_t) size_of_file, tmp_file);
        if(read_size != (size_t) size_of_file) {
            fclose(tmp_file);
            free(json_str);
            curl_free(key);
            curl_free(hex_auth_key);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        //---------- PARSE JSON ----------
        struct json_object* json_value = json_tokener_parse(json_str);
        if(json_value == NULL) {
            fclose(tmp_file);
            free(json_str);
            curl_free(key);
            curl_free(hex_auth_key);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        //---------- PARSE AND HEX-DECODE C2 ----------
        struct json_object* json_content = NULL;
        json_bool key_found = json_object_object_get_ex(json_value, "c2", &json_content);
        if(!key_found || json_object_get_type(json_content) != json_type_string) {
            fclose(tmp_file);
            free(json_str);
            curl_free(key);
            curl_free(hex_auth_key);
            M_JSON_PUT_MG(json_value, nc);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        const char* encoded_c2 = json_object_get_string(json_content);
        ckvs_sha_t c2;
        memset(&c2, 0, sizeof(c2));

        int c2_len = SHA256_from_string(encoded_c2, &c2);
        if(c2_len == -1) {
            free(json_str);
            curl_free(key);
            curl_free(hex_auth_key);
            M_JSON_PUT_MG(json_value, nc);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        //---------- PARSE AND HEX-DECODE DATA ----------
        key_found = json_object_object_get_ex(json_value, "data", &json_content);
        if(!key_found || json_object_get_type(json_content) != json_type_string) {
            free(json_str);
            curl_free(key);
            curl_free(hex_auth_key);
            M_JSON_PUT_MG(json_value, nc);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        const char* encoded_data = json_object_get_string(json_content);

        //TODO: CHECK FOR OVERFLOWS
        char* data = calloc(strlen(encoded_data) * 2 + 1, sizeof(char));
        if(data == NULL) {
            free(json_str);
            curl_free(key);
            curl_free(hex_auth_key);
            M_JSON_PUT_MG(json_value, nc);
            mg_error_msg(nc, ERR_OUT_OF_MEMORY);
            return;
        }

        int data_len = hex_decode(encoded_data, (uint8_t*) data);
        if(data_len == -1) {
            free(json_str);
            curl_free(key);
            curl_free(hex_auth_key);
            M_JSON_PUT_MG(json_value, nc);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        p_entry->c2 = c2;

        err_code = ckvs_write_encrypted_value(ckvs, p_entry, (unsigned char*) data, (uint64_t) data_len);
        if(err_code != ERR_NONE) {
            free(json_str);
            curl_free(key);
            curl_free(hex_auth_key);
            M_JSON_PUT_MG(json_value, nc);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        mg_http_reply(nc, HTTP_OK_CODE, NULL, "");
    }
}

// ======================================================================
static char* get_urldecoded_argument(struct mg_http_message *hm, const char *arg) {
    if(hm == NULL || arg == NULL) {
        return NULL;
    }
#define MAX_URLDECODED_ARG_LENGTH 1024

    char decoded_var[MAX_URLDECODED_ARG_LENGTH] = "";
    if(mg_http_get_var(&hm->query, arg, decoded_var, sizeof(decoded_var)) <= 0) {
        return NULL;
    }

    CURL* curl = curl_easy_init();
    if(curl != NULL) {
        char* arg_decoded = curl_easy_unescape(curl, decoded_var, 0, NULL);
        curl_easy_cleanup(curl);
        return arg_decoded;
    } else {
        // todo: message error
        return NULL;
    }
}
