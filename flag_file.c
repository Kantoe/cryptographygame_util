#include "flag_file.h"

#define PATH_NUMBER_SIZE 32
#define CORRECT_RANDOM_PATH_NUMBER 1
#define REMOVE_NEWLINE 1

const char *random_directories[] = {"/home/", "/media/", "/opt/", "/usr/", "/lib/"};
const int num_directories = sizeof(random_directories) / sizeof(random_directories[0]);

/**
 * Checks if the current process has write permissions for a given path
 *
 * @param path - Path to check for write permissions
 *
 * Operation: Uses access() system call to check if the process has write permissions
 *
 * @return STATUS_OKAY if write permission exists, GENERAL_ERROR otherwise
 */
int check_permissions(const char *path);

/**
 * Counts the number of subdirectories in a given directory up to 5 levels deep
 *
 * @param selected_directory - Directory path to count subdirectories in
 *
 * Operation: Uses find command through popen to count directories, limited to
 * depth 5. Executes shell command and parses the result.
 *
 * @return Number of subdirectories found or GENERAL_ERROR on failure
 */
int get_paths_number(const char *selected_directory);

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
void generate_random_string(char *buffer, const size_t buf_size) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const size_t charset_size = strlen(charset);
    // Map random bytes directly into the character set
    for (size_t i = 0; i < buf_size; i++) {
        buffer[i] = charset[arc4random_uniform(charset_size)];
    }
    buffer[buf_size] = NULL_CHAR; // Null-terminate the string
}

/**
 * Checks if the current process has write permissions for a given path
 *
 * @param path - Path to check for write permissions
 *
 * Operation: Uses access() system call to check if the process has write permissions
 *
 * @return STATUS_OKAY if write permission exists, GENERAL_ERROR otherwise
 */
int check_permissions(const char *path) {
    return access(path, W_OK) == ACCESS_SUCCESS ? STATUS_OKAY : GENERAL_ERROR;
}

/**
 * Counts the number of subdirectories in a given directory up to 5 levels deep
 *
 * @param selected_directory - Directory path to count subdirectories in
 *
 * Operation: Uses find command through popen to count directories, limited to
 * depth 5. Executes shell command and parses the result.
 *
 * @return Number of subdirectories found or GENERAL_ERROR on failure
 */
int get_paths_number(const char *selected_directory) {
    char find_paths_command[128] = {NULL_CHAR};
    if (snprintf(find_paths_command, sizeof(find_paths_command),
                 "find %s -maxdepth 5 -type d | wc -l",
                 selected_directory) >= sizeof(find_paths_command)) {
        return GENERAL_ERROR;
    }
    FILE *fp = popen(find_paths_command, "r");
    if (fp == NULL) {
        return GENERAL_ERROR;
    }
    char paths_number[PATH_NUMBER_SIZE] = {NULL_CHAR};
    if (fgets(paths_number, sizeof(paths_number), fp) == NULL) {
        pclose(fp);
        return GENERAL_ERROR;
    }
    pclose(fp);
    return atoi(paths_number);
}

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
int generate_random_path_name(char *path, const size_t path_size) {
    while (true) {
        const uint32_t random_dir_index = arc4random_uniform(num_directories);
        const char *selected_dir = random_directories[random_dir_index];
        const int paths_number = get_paths_number(selected_dir);
        if (paths_number == GENERAL_ERROR) {
            return GENERAL_ERROR;
        }
        const uint32_t random_path_number = arc4random_uniform(paths_number) + CORRECT_RANDOM_PATH_NUMBER;
        char get_path_command[128] = {NULL_CHAR};
        if (snprintf(get_path_command, sizeof(get_path_command),
                     "find %s -maxdepth 5 -type d | sed -n '%dp'",
                     selected_dir, random_path_number) >= sizeof(get_path_command)) {
            return GENERAL_ERROR;
        }
        FILE *pp = popen(get_path_command, "r");
        if (pp == NULL) {
            return GENERAL_ERROR;
        }
        memset(path, NULL_CHAR, path_size);
        if (fgets(path, path_size, pp) == NULL) {
            pclose(pp);
            return GENERAL_ERROR;
        }
        path[strlen(path) - REMOVE_NEWLINE] = NULL_CHAR; //remove newline
        pclose(pp);
        if (!strchr(path, ' ') && check_permissions(path) == STATUS_OKAY) {
            break;
        }
    }
    return STATUS_OKAY;
}

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
int execute_command(const char *command) {
    if (command == NULL) {
        return GENERAL_ERROR;
    }
    if (strlen(command) == 0) {
        return GENERAL_ERROR;
    }
    // Execute command
    const int ret = system(command);
    // Case 1: Failed to create child process or get status
    if (ret == SYSTEM_FAILURE) {
        return GENERAL_ERROR;
    }
    // Case 2: Shell execution failed in child process
    if (WIFEXITED(ret) && WEXITSTATUS(ret) == EXE_CHILD_FAIL_CHECK) {
        return GENERAL_ERROR;
    }
    // Case 3: Normal termination - check exit status
    if (WIFEXITED(ret)) {
        const int exit_status = WEXITSTATUS(ret);
        if (exit_status != STATUS_OKAY) {
            return GENERAL_ERROR;
        }
        return STATUS_OKAY; // Success case
    }
    // Case 4: Terminated by signal
    if (WIFSIGNALED(ret)) {
        return GENERAL_ERROR;
    }
    return GENERAL_ERROR;
}
