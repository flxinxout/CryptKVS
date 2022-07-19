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

/**
 * @brief Define the number of commands for the program
 */
#define COMMAND_NUMBER 4

/**
 * @brief Define a pointer to the functions that will execute the different commands of the program
 */
typedef int (*ckvs_command)(const char* filename, int optargc, char* optargv[]);

/**
 * @brief Regroup a function with its name and its description.
 *
 * @param name (const char*) the name of the command
 * @param description (const char*) the description/format of the command (shown to list all available commands)
 * @param command (const ckvs_command) the function that will execute the command
 */
typedef struct ckvs_command_mapping {
    const char* name;
    const char* description;
    const ckvs_command command;
} ckvs_command_mapping_t;

/**
 * @brief Array of all command mappings of the program
 */
const ckvs_command_mapping_t commands[COMMAND_NUMBER] = {
        {"stats", "- cryptkvs <database> stats", ckvs_local_stats },
        {"get", "- cryptkvs <database> get <key> <password>", ckvs_local_get },
        {"set", "- cryptkvs <database> set <key> <password> <filename>", ckvs_local_set },
        {"new", "- cryptkvs <database> new <key> <password>", ckvs_local_new }
};

static void usage(const char *execname, int err)
{
    if(err == ERR_INVALID_COMMAND) {
        pps_printf("Available commands:\n");
        for (size_t i = 0; i < COMMAND_NUMBER; ++i) {
            pps_printf("%s\n", commands[i].description);
        }
        pps_printf("\n");
    } else if (err >= 0 && err < ERR_NB_ERR) {
        pps_printf("%s exited with error: %s\n\n\n", execname, ERR_MESSAGES[err]);
    } else {
        pps_printf("%s exited with error: %d (out of range)\n\n\n", execname, err);
    }
}

/* *************************************************** *
 * TODO WEEK 04-11: Add more commands                  *
 * *************************************************** */
/**
 * @brief Runs the command requested by the user in the command line, or returns ERR_INVALID_COMMAND if the command is not found.
 *
 * @param argc (int) the number of arguments in the command line
 * @param argv (char*[]) the arguments of the command line, as passed to main()
 */
int ckvs_do_one_cmd(int argc, char *argv[])
{
    M_REQUIRE(argc >= 3, ERR_INVALID_COMMAND);

    const char* db_filename = argv[1];
    const char* cmd = argv[2];

    int err_code = ERR_NONE;

    for (size_t i = 0; i < COMMAND_NUMBER; ++i) {
        const ckvs_command_mapping_t* command_mapping = &commands[i];
        if(strcmp(cmd, command_mapping->name) == 0) {
            err_code = command_mapping->command(db_filename, argc - 3, argv + 3);
            M_EXIT(err_code);
        }
    }

    M_EXIT(ERR_INVALID_COMMAND);
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
