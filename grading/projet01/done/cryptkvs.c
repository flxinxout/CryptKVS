/*
 * cryptkvs -- main ; argument parsing and dispatch ; etc.
 */

#include <stdio.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"

/* *************************************************** *
 * TODO WEEK 09-11: Add then augment usage messages    *
 * *************************************************** */

/* *************************************************** *
 * TODO WEEK 04-07: add message                        *
 * TODO WEEK 09: Refactor usage()                      *
 * *************************************************** */
static void usage(const char *execname, int err)
{
    if (err == ERR_INVALID_COMMAND) {
        pps_printf("Available commands:\n");
        pps_printf("- cryptkvs <database> stats\n");
        pps_printf("- cryptkvs <database> get <key> <password>\n");
        pps_printf("- cryptkvs <database> set <key> <password> <filename>\n");
        pps_printf("\n");
    } else if (err >= 0 && err < ERR_NB_ERR) {
        pps_printf("%s exited with error: %s\n\n\n", execname, ERR_MESSAGES[err]);
    } else {
        pps_printf("%s exited with error: %d (out of range)\n\n\n", execname, err);
    }
}

/* *************************************************** *
 * TODO WEEK 04-11: Add more commands                  *
 * TODO WEEK 09: Refactor ckvs_local_*** commands      *
 * *************************************************** */
/**
 * @brief Runs the command requested by the user in the command line, or returns ERR_INVALID_COMMAND if the command is not found.
 *
 * @param argc (int) the number of arguments in the command line
 * @param argv (char*[]) the arguments of the command line, as passed to main()
 */
int ckvs_do_one_cmd(int argc, char *argv[])
{
#define GET_ARG_COUNT 5
#define SET_ARG_COUNT 6

    M_REQUIRE(argc >= 3, ERR_INVALID_COMMAND);

    const char* db_filename = argv[1];
    const char* cmd = argv[2];

    int err_code = ERR_NONE;

    if(strcmp(cmd, "stats") == 0) {
        err_code = ckvs_local_stats(db_filename);
    } else if(strcmp(cmd, "get") == 0) {
        M_REQUIRE(argc >= GET_ARG_COUNT, ERR_NOT_ENOUGH_ARGUMENTS);
        M_REQUIRE(argc <= GET_ARG_COUNT, ERR_TOO_MANY_ARGUMENTS);

        const char* key = argv[3];
        const char* pwd = argv[4];
        err_code = ckvs_local_get(db_filename, key, pwd);
    } else if(strcmp(cmd, "set") == 0) {
        M_REQUIRE(argc >= SET_ARG_COUNT, ERR_NOT_ENOUGH_ARGUMENTS);
        M_REQUIRE(argc <= SET_ARG_COUNT, ERR_TOO_MANY_ARGUMENTS);

        const char* key = argv[3];
        const char* pwd = argv[4];
        const char* filename = argv[5];
        err_code = ckvs_local_set(db_filename, key, pwd, filename);
    } else {
            M_EXIT(ERR_INVALID_COMMAND);
    }

    M_EXIT(err_code);
}

#ifndef FUZZ
/**
 * @brief main function, runs the requested command and prints the resulting error if any.
 */
int main(int argc, char *argv[])
{
    int ret = ckvs_do_one_cmd(argc, argv);
    if (ret != ERR_NONE) {
        usage(argv[0], ret);
    }
    return ret;
}
#endif
