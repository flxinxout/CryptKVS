#pragma once

/**
 * @file error.h
 * @brief Error codes for PPS course (CS-212)
 *
 * @author E. Bugnion, J.-C. Chappelier, V. Rousset
 * @date 2016-2021
 */
#include <stdio.h> // for fprintf
#include <string.h> // strerror()
#include <errno.h>  // errno
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

// ======================================================================
/**
 * @brief internal error codes.
 *
 */
typedef enum {
    ERR_CLANG_TYPE_FIX = -1, // this stupid value is to fix type to be int instead of unsigned on some compilers (e.g. clang version 8.0)
    ERR_NONE = 0, // no error

    ERR_IO,
    ERR_OUT_OF_MEMORY,
    ERR_NOT_ENOUGH_ARGUMENTS,
    ERR_TOO_MANY_ARGUMENTS,
    ERR_INVALID_FILENAME,
    ERR_INVALID_COMMAND,
    ERR_INVALID_ARGUMENT,
    ERR_MAX_FILES,
    ERR_KEY_NOT_FOUND,
    ERR_NO_VALUE,
    NOT_IMPLEMENTED,
    ERR_DUPLICATE_ID,
    ERR_CORRUPT_STORE,
    ERR_TIMEOUT,
    ERR_PROTOCOL,
    ERR_NB_ERR // not an actual error but to have the total number of errors
} error_code;

// ======================================================================
/*
 * Helpers (macros)
 */

// ----------------------------------------------------------------------
/**
 * @brief debug_printf macro is useful to print message in DEBUG mode only.
 */

#ifdef DEBUG
// dirty trick, waiting for N2023 (www.open-std.org/jtc1/sc22/wg14/www/docs/n2023.pdf) to be implemented...
#define debug_printf_core(fmt, ...)                                       \
        do { fprintf(stderr, "DEBUG %s:%d:%s(): " fmt "%s\n", __FILE__, __LINE__, __func__, __VA_ARGS__); } while (0)
#define debug_printf(...) debug_printf_core(__VA_ARGS__, "")
#else
#define debug_printf(fmt, ...) \
    do {} while(0)
#endif

// ----------------------------------------------------------------------
/**
 * @brief M_EXIT_MSG macro is useful to return an error code from a function with a debug message.
 *        Example usage:
 *           M_EXIT_MSG(ERR_INVALID_ARGUMENT, "unable to do something decent with value %lu", i);
 */
#define M_EXIT_MSG(error_code, fmt, ...)  \
    do { \
        if (error_code < ERR_NB_ERR) { \
            debug_printf("%s: " fmt, ERR_MESSAGES[error_code], __VA_ARGS__); \
        } else { \
            debug_printf(fmt, __VA_ARGS__); \
        } \
        return error_code; \
    } while(0)

// ----------------------------------------------------------------------
/**
 * @brief M_EXIT macro is useful to return an error code from a function with a default debug message.
*/
#define M_EXIT(error_code)  \
    do { \
       if (error_code < ERR_NB_ERR) { \
            debug_printf("%s", ERR_MESSAGES[error_code]); \
        } else { \
            debug_printf("%s", "An unidentified type of error occured."); \
        } \
        return error_code; \
    } while(0)

// ----------------------------------------------------------------------
/**
 * @brief M_REQUIRE_MSG macro is similar to M_EXIT_MSG, but exits only when the
 *        provided test is false (thus "require").
 *        Example usage:
 *            M_REQUIRE_MSG(i <= 3, ERR_INVALID_ARGUMENT, "input value (%lu) is too high (> 3)", i);
 */
#define M_REQUIRE_MSG(test, error_code, fmt, ...)   \
    do { \
        if (!(test)) { \
             M_EXIT_MSG(error_code, fmt, __VA_ARGS__); \
        } \
    } while(0)

// ----------------------------------------------------------------------
/**
 * @brief M_REQUIRE macro is similar to M_EXIT, but exits only when the
 *        provided test is false (thus "require").
 *        Example usage:
 *            M_REQUIRE(i <= 3, ERR_INVALID_ARGUMENT);
 */
#define M_REQUIRE(test, error_code)   \
    do { \
        if (!(test)) { \
             M_EXIT(error_code); \
        } \
    } while(0)

// ----------------------------------------------------------------------
/**
 * @brief M_REQUIRE_NO_ERROR macro checks that the given error code is ERR_NONE. If it is not, it returns this
 * error. Otherwise it does nothing. \n
 * It is equivalent to
 *          M_REQUIRE(err_code == ERR_NONE, err_code)
 */
#define M_REQUIRE_NO_ERROR(err_code)   \
    do { \
        M_REQUIRE(err_code == ERR_NONE, err_code); \
    } while(0)

// ----------------------------------------------------------------------
/**
 * @brief M_REQUIRE_NON_NULL macro is useful for requiring non-NULL arguments.
 *        Example usage:
 *            int my_favorite_function(struct whatever* key)
 *            {
 *                M_REQUIRE_NON_NULL(key);
 */
#define M_REQUIRE_NON_NULL(arg) \
    M_REQUIRE_MSG((arg) != NULL, ERR_INVALID_ARGUMENT, "parameter %s is NULL", #arg)

// ----------------------------------------------------------------------
/**
 * @brief M_REQUIRE_FILE_OPENED macro is useful for requiring non-NULL opened files (checking a file opened correctly).
 * Return an ERR_INVALID_FILENAME if the given file is NULL\n\n
 *        Equivalent to
 *          M_REQUIRE_MSG(file != NULL,
 *                          ERR_INVALID_FILENAME,
 *                          ": file %s couldn't be opened",
 *                          filename);
 */
#define M_REQUIRE_FILE_OPENED(file, filename) \
    do { \
        M_REQUIRE_MSG(file != NULL, ERR_IO, "file %s couldn't be opened", filename); \
} while(0)

// ----------------------------------------------------------------------
/**
 * @brief M_CHECK_NON_NULL_ARG macro is useful for checking non-nullity. If the given argument is NULL, just return
 * (void) from the function.
 *       Equivalent to:
 *          if(arg == NULL) return;
 */
#define M_CHECK_NON_NULL(arg) \
    do { \
        if (arg == NULL) { \
             return; \
        } \
    } while(0)

// ----------------------------------------------------------------------
/**
 * @brief M_ASSERT_NON_NULL_ARG macro is useful to assert non-nullity.
 * If the given argument is NULL, the program is aborted.
 *       Equivalent to:
 *          assert(arg != NULL);
 */
#define M_ASSERT_NON_NULL(arg) \
    do { \
        assert(arg != NULL); \
    } while(0)

// ----------------------------------------------------------------------
/**
 * @brief M_CHECK_ARG_COUNT macro is useful for checking if a function receives the correct number.
 *
 */
#define M_CHECK_ARG_COUNT(argc, expected) \
    do { \
        M_REQUIRE(!(argc < expected), ERR_NOT_ENOUGH_ARGUMENTS); \
        M_REQUIRE(!(argc > expected), ERR_TOO_MANY_ARGUMENTS); \
    } while(0)
// ======================================================================
/**
* @brief internal error messages. defined in error.c
*
*/
extern
const char* const ERR_MESSAGES[];

#ifdef __cplusplus
}
#endif
