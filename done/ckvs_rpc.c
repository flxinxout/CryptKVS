/**
 * @file ckvs_rpc.c
 * @brief RPC handling using libcurl
 * @author E. Bugnion
 *
 * Includes example from https://curl.se/libcurl/c/getinmemory.html
 */
#include <stdlib.h>

#include "ckvs_utils.h"
#include "ckvs_rpc.h"
#include "error.h"

/**
 * @brief Macro to perform curl_easy_setopt function with all the free necessary
 */
#define RPC_CURL_EASY_SET_OPT(curl, curl_opt, third_arg, url, error, is_list, slist) do { \
    if(curl_easy_setopt(curl, curl_opt, third_arg) != CURLE_OK) { \
        if(is_list == 1) curl_slist_free_all(slist); \
        free(url); \
        M_EXIT(error); \
    } \
} while(0)

/**
 * ckvs_curl_WriteMemoryCallback -- lifted from https://curl.se/libcurl/c/getinmemory.html
 *
 * @brief Callback that gets called when CURL receives a message.
 * It writes the payload inside ckvs_connection.resp_buf.
 * Note that it is already setup in ckvs_rpc_init.
 *
 * @param contents (void*) content received by CURL
 * @param size (size_t) size of an element of of content. Always 1
 * @param nmemb (size_t) number of elements in content
 * @param userp (void*) points to a ckvs_connection (set with the CURLOPT_WRITEDATA option)
 * @return (size_t) the number of written bytes, or 0 if an error occured
 */
static size_t ckvs_curl_WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct ckvs_connection *conn = (struct ckvs_connection *)userp;

    char *ptr = realloc(conn->resp_buf, conn->resp_size + realsize + 1);
    if(!ptr) {
        /* out of memory! */
        debug_printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    conn->resp_buf = ptr;
    memcpy(&(conn->resp_buf[conn->resp_size]), contents, realsize);
    conn->resp_size += realsize;
    conn->resp_buf[conn->resp_size] = 0;

    return realsize;
}

//===========================================================================
int ckvs_rpc_init(struct ckvs_connection *conn, const char *url) {
    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(url);
    bzero(conn, sizeof(*conn));

    conn->url  = url;
    conn->curl = curl_easy_init();
    if (conn->curl == NULL) {
        return ERR_OUT_OF_MEMORY;
    }
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, ckvs_curl_WriteMemoryCallback);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, (void *)conn);

    return ERR_NONE;
}

//===========================================================================
void ckvs_rpc_close(struct ckvs_connection *conn) {
    if (conn == NULL)
        return;

    if (conn->curl) {
        curl_easy_cleanup(conn->curl);
    }
    if (conn->resp_buf) {
        free(conn->resp_buf);
    }
    bzero(conn, sizeof(*conn));
}

//===========================================================================
int ckvs_rpc(struct ckvs_connection *conn, const char *GET) {
    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(GET);
    M_REQUIRE_NON_NULL(conn->url);
    M_REQUIRE_NON_NULL(conn->curl);

    char* url_copy = calloc(strlen(conn->url) + strlen(GET) + 1, sizeof(char));
    M_REQUIRE(url_copy != NULL, ERR_OUT_OF_MEMORY);

    strcpy(url_copy, conn->url);
    strcat(url_copy, GET);

    CURLcode ret = CURLE_OK;

    RPC_CURL_EASY_SET_OPT(conn->curl, CURLOPT_URL, url_copy, url_copy, ERR_OUT_OF_MEMORY, 0, NULL);


    ret = curl_easy_perform(conn->curl);
    if(ret != CURLE_OK) {
        free(url_copy);
        M_EXIT(ERR_TIMEOUT);
    }

    free(url_copy);
    M_EXIT(ERR_NONE);
}

//===========================================================================
int ckvs_post(struct ckvs_connection* conn, const char* GET, const char* POST) {
    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(conn->url);
    M_REQUIRE_NON_NULL(conn->curl);
    M_REQUIRE_NON_NULL(GET);
    M_REQUIRE_NON_NULL(POST);

    char* url_copy = calloc(strlen(conn->url) + strlen(GET) + 1, sizeof(char));
    M_REQUIRE(url_copy != NULL, ERR_OUT_OF_MEMORY);

    strcpy(url_copy, conn->url);
    strcat(url_copy, GET);

    CURLcode ret = CURLE_OK;

    //---------- SET OPT URL ----------
    RPC_CURL_EASY_SET_OPT(conn->curl, CURLOPT_URL, url_copy, url_copy, ERR_IO, 0, NULL);

    //---------- SET OPT HEADER ----------
    struct curl_slist *slist = NULL;
    slist = curl_slist_append(slist, "Content-Type: application/json");
    if (slist == NULL) {
        free(url_copy);
        M_EXIT(ERR_OUT_OF_MEMORY); //TODO out of mem?
    }

    RPC_CURL_EASY_SET_OPT(conn->curl, CURLOPT_HTTPHEADER, slist, url_copy, ERR_IO, 1, slist);

    //---------- SET OPT POST FIELD SIZE ----------
    RPC_CURL_EASY_SET_OPT(conn->curl, CURLOPT_POSTFIELDSIZE, strlen(POST), url_copy, ERR_IO, 1, slist);

    //---------- SET OPT POST FIELD ----------
    RPC_CURL_EASY_SET_OPT(conn->curl, CURLOPT_POSTFIELDS, POST, url_copy, ERR_IO, 1, slist);

    //---------- PERFORM REQUEST ----------
    ret = curl_easy_perform(conn->curl);
    if(ret != CURLE_OK) {
        curl_slist_free_all(slist);
        free(url_copy);
        M_EXIT(ERR_TIMEOUT);
    }
    if(conn->resp_buf != NULL) {
        curl_slist_free_all(slist);
        free(url_copy);
        pps_printf("%s", conn->resp_buf);
        M_EXIT(ERR_IO);
    }

    //---------- SET OPT POST FIELD SIZE ----------
    RPC_CURL_EASY_SET_OPT(conn->curl, CURLOPT_POSTFIELDSIZE, 0, url_copy, ERR_IO, 1, slist);

    //---------- SET OPT POST FIELD ----------
    RPC_CURL_EASY_SET_OPT(conn->curl, CURLOPT_POSTFIELDS, "", url_copy, ERR_IO, 1, slist);

    //---------- PERFORM REQUEST ----------
    ret = curl_easy_perform(conn->curl);
    if(ret != CURLE_OK) {
        curl_slist_free_all(slist);
        free(url_copy);
        M_EXIT(ERR_TIMEOUT);
    }
    if(conn->resp_buf != NULL) {
        curl_slist_free_all(slist);
        free(url_copy);
        pps_printf("%s", conn->resp_buf);
        M_EXIT(ERR_IO);
    }

    curl_slist_free_all(slist);
    free(url_copy);
    M_EXIT(ERR_NONE);
}

