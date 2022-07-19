/**
 * @file json_utils.h
 * @brief JSON useful macros
 *
 * Utilities to work with JSON data.
 */

#pragma once

#include <json-c/json.h>
#include "error.h"

/**
 * @brief Defines the number of commands for the program
 */
#define JSON_HEADER_OPT "Content-Type: application/json\r\n"

//===========================================================================
/**
 * @brief M_JSON_PUT_REQUIRE macro is useful to put a json_object
 * and exits with ERR_IO if an error occurs.
 *
 * Equivalent to:
 * @code
 *      int res_destroy = json_object_put(json_object);
 *      M_REQUIRE(res_destroy == 1, ERR_IO);
 *
 * @param json_object (json_object*) json object to put
 */
#define M_JSON_PUT_REQUIRE(json_object) do { \
    int res_destroy = json_object_put(json_object); \
    M_REQUIRE(res_destroy == 1, ERR_IO); \
} while(0)

//===========================================================================
/**
 * @brief M_JSON_PUT_MG macro is useful to put a json_object. If an error occurs, it exits the
 * program and sends an ERR_IO message to the given connection. \n
 *
 * Equivalent to:
 * @code
 *      int res_destroy = json_object_put(json_object);
 *      if(res_destroy != 1)  {
 *          mg_error_msg(nc, ERR_IO);
 *          return;
 *      }
 *
 * @param json_object (json_object*) json object to put
 * @param nc (struct mg_connection*) connection where to write in case of an error
 */
#define M_JSON_PUT_MG(json_object, nc) do { \
    int res_destroy = json_object_put(json_object); \
    if(res_destroy != 1)  { \
        mg_error_msg(nc, ERR_IO); \
        return; \
    } \
} while(0)

// ======================================================================
/**
 * @brief Add the given value to the given root with the given key using the given function.
 * If an error occurs, it puts the json_root and exits the program with an ERR_IO.
 *
 * Equivalent to:
 * @code
 *      struct json_object* json_val = new_func(val);
 *      if(json_object_object_add(json_root, key, json_val) < 0) {
 *          M_JSON_PUT_REQUIRE(json_root, nc); \
            M_EXIT(ERR_IO);
 *       }
 *
 * @param json_root (*json_object) the root where to add a new object
 * @param new_func (struct json_object* (val)) the function used to create the new object from val
 * @param val (int|const char*) the value which the added object should take
 * @param key (const char*) the key from which the added object should be referenced
 */
#define M_JSON_ADD_NEW(json_root, new_func, val, key) do { \
        struct json_object* json_val = new_func(val); \
        if(json_object_object_add(json_root, key, json_val) < 0) { \
            M_JSON_PUT_REQUIRE(json_root); \
            M_EXIT(ERR_IO); \
        } \
    } while(0)

/*#define M_JSON_ADD_NEW(json_root, new_func, val, key) do { \
        struct json_object* json_val = new_func(val); \
        json_object_object_add(json_root, key, json_val); \
    } while(0)*/

//TODO: make a method M_JSON_EXTRACT_KEY instead of macros