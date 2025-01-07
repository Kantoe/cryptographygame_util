#ifndef FLAG_FILE_H
#define FLAG_FILE_H

#include "cryptography_game_util.h"

/**
 * Generates a random valid directory path from predefined root directories
 *
 * @param path - Buffer to store the generated path
 * @param path_size - Size of the path buffer
 *
 * Operation: Selects a random root directory, finds all subdirectories up to depth 5,
 * selects a random one, and verifies it has no spaces and is writable. Retries until
 * a valid path is found.
 *
 * @return STATUS_OKAY on success, GENERAL_ERROR on failure
 */
int generate_random_path_name(char *path, size_t path_size);

/**
 * Executes a shell command and handles various execution outcomes
 *
 * @param command - Shell command string to execute
 *
 * Operation: Uses system() to execute the command and carefully handles all
 * possible execution outcomes including process creation failure, shell execution
 * failure, normal termination with error, and signal termination.
 *
 * @return STATUS_OKAY on successful execution, GENERAL_ERROR on any failure
 */
int execute_command(const char *command);

/**
 * Generates a random string using alphanumeric characters
 *
 * @param buffer - Pointer to the buffer where the random string will be stored
 * @param buf_size - Size of the random string to generate (not including null terminator)
 *
 * Operation: Creates a random string by selecting random characters from a charset of
 * alphanumeric characters using arc4random_uniform. Ensures null-termination.
 *
 * @return void
 */
void generate_random_string(char *buffer, size_t buf_size);

#endif //FLAG_FILE_H
