#include "commands.h"

//prototypes

/*
 * Finds the most recently used 'cd' command in a given command string.
 * This function scans through the entire input command, identifying and tracking
 * the last occurrence of a change directory (cd) command. It's useful for
 * processing command sequences where multiple 'cd' commands might exist,
 * ensuring that only the most recent directory change is considered.
 *
 * The function works by repeatedly searching for "cd " substrings, updating
 * the last found pointer with each iteration. This allows tracking of the
 * final 'cd' command in a potentially complex command string.
 *
 * Parameters:
 *   command - The input string to search for 'cd' commands
 * Returns: Pointer to the last 'cd' command, or NULL if no 'cd' found
 */
char *find_last_cd(const char *command);

/*
 * Comprehensive handler for 'cd' command processing in a networked context.
 * This function orchestrates the entire CD command workflow, from initial
 * parsing to final directory update and client communication. It provides
 * a robust, secure mechanism for handling directory change requests in a
 * networked environment.
 *
 * The function performs a complex sequence of operations:
 * 1. Extract and validate the CD command
 * 2. Safely execute the directory change
 * 3. Update the working directory
 * 4. Communicate the new directory state to the client
 * 5. Handle potential errors at each stage
 *
 * Parameters:
 *   sock_fd - Socket file descriptor for client communication
 *   command - Incoming command string
 *   working_directory - Current working directory buffer
 *   working_directory_size - Size of the working directory buffer
 * Returns: Status of the entire CD command processing
 */
int8_t check_cd(int sock_fd, const unsigned char *encryption_key, const char *command,
                char *working_directory, size_t working_directory_size);

/*
 * Builds and validates command string with necessary redirections
 * Parameters:
 *   command - Original command string
 *   command_size - Size of command buffer
 *   socket_fd - Socket file descriptor
 *   working_directory - Current working directory
 *   pfd - Pipe file descriptors array
 *   full_command - Buffer for complete command string
 * Returns: 0 on success, -1 on error
 */
int build_check_command(char *command, size_t command_size, int socket_fd, const unsigned char *encryption_key,
                        char *working_directory, int (*pfd)[2],
                        char (*full_command)[512]);

/*
 * Executes command and sends stdout to client
 * Parameters:
 *   socket_fd - Socket file descriptor
 *   pfd - Pipe file descriptors
 *   full_command - Complete command string
 *   pout - Pointer to FILE stream for output
 *   output - Buffer for command output
 * Returns: 0 on success, -1 on error
 */
int send_command_stdout(int socket_fd, const unsigned char *encryption_key, int pfd[2], char full_command[512],
                        FILE **pout, char output[1024]);

/*
 * Handles command stderr and sends to client
 * Parameters:
 *   socket_fd - Socket file descriptor
 *   pfd - Pipe file descriptors
 *   error_check - Error status flag
 *   pout - FILE stream for output
 *    - Buffer for error output
 *   pipe_err - Pointer to FILE stream for errors
 * Returns: 0 on success, -1 on error
 */
int send_command_stderr(int socket_fd, const unsigned char *encryption_key, int pfd[2], int8_t *error_check,
                        FILE *pout, char output[1024], FILE **pipe_err);


/*
 * Validates whether a character is acceptable in a Linux file path.
 * This function provides a strict validation of path characters, allowing
 * only alphanumeric characters, specific special characters commonly used
 * in file and directory names. This helps prevent injection or malicious
 * path manipulation by rejecting unexpected characters.
 *
 * The allowed characters include:
 * - Alphanumeric characters (letters and numbers)
 * - Dot (.) for file extensions or current directory
 * - Hyphen (-) for some naming conventions
 * - Underscore (_) for file/directory naming
 * - Forward slash (/) for path navigation
 * - Tilde (~) for home directory references
 *
 * Parameters:
 *   c - The character to validate
 * Returns: 1 if character is valid, 0 otherwise
 */
int is_valid_path_char(char c);

/*
 * Sanitizes a 'cd' command by extracting only the valid path portion.
 * This function ensures that only safe, well-formed directory paths are
 * processed by truncating the command at the first invalid character.
 * It provides a crucial security measure to prevent command injection
 * or unexpected behavior when changing directories.
 *
 * The function first verifies the command starts with 'cd_', then
 * systematically checks each subsequent character. As soon as an
 * invalid character is encountered, the command is truncated, effectively
 * sanitizing the input path.
 *
 * Parameters:
 *   cd_command - The CD command to be sanitized
 *   max_len - Maximum length of the command buffer
 */
void extract_valid_cd_command(char *cd_command, size_t max_len);

/*
 * Extracts and prepares the last 'cd' command for execution.
 * This function serves as a comprehensive handler for CD command processing.
 * It finds the most recent 'cd' command, validates its path, and prepares
 * it for potential execution. If no valid CD command is found or the path
 * is invalid, it handles error scenarios appropriately.
 *
 * The function performs multiple critical steps:
 * 1. Locate the last 'cd' command in the input string
 * 2. Extract and sanitize the directory path
 * 3. Validate the extracted path
 * 4. Prepare for potential directory change
 *
 * Parameters:
 *   command - The full input command string
 *   cd_command - Pointer to store the extracted CD command
 * Returns: Status of command extraction (success or error)
 */
int8_t get_cd_command(const char *command, char **cd_command);

/*
 * Constructs and executes a 'cd' command in a controlled environment.
 * This function provides a secure mechanism for changing directories,
 * featuring multiple layers of safety and error handling. It uses a
 * subprocess to change directories, captures the resulting path, and
 * ensures that only valid directory changes are processed.
 *
 * Key operations include:
 * 1. Creating a pipe for error and output capturing
 * 2. Constructing a shell command that changes directory
 * 3. Executing the command in a controlled subprocess
 * 4. Capturing the resulting working directory path
 * 5. Handling potential errors during directory change
 *
 * Parameters:
 *   working_directory - Current working directory path
 *   cd_command - Sanitized CD command to execute
 *   output - Buffer to store the resulting directory path
 * Returns: Status of directory change operation
 */
int8_t build_and_execute_cd(char *working_directory, char *cd_command, char (*output)[512]);

//methods

/*
 * Builds and validates command string with necessary redirections
 * Parameters:
 *   command - Original command string
 *   command_size - Size of command buffer
 *   socket_fd - Socket file descriptor
 *   working_directory - Current working directory
 *   pfd - Pipe file descriptors array
 *   full_command - Buffer for complete command string
 * Returns: 0 on success, -1 on error
 */

int build_check_command(char *command, const size_t command_size, const int socket_fd,
                        const unsigned char *encryption_key, char *working_directory,
                        int (*pfd)[2], char (*full_command)[512]) {
    if (pipe(*pfd) < PIPE_ERR_CHECK) {
        perror("pipe failed");
        return GENERAL_ERROR;
    }
    if (command_size + strlen(working_directory) > BUFFER_SIZE_CMD_MAX) {
        char err_buf[ERR_BUFFER_SIZE];
        prepare_buffer(err_buf, sizeof(err_buf), "command size too large\n", "ERR");
        s_send(socket_fd, encryption_key, err_buf, strlen(err_buf));
        return GENERAL_ERROR;
    }
    snprintf(*full_command, sizeof(*full_command), "cd %s 2>&%d && (%s) 2>&%d",
             working_directory, (*pfd)[PIPE_OUT], command, (*pfd)[PIPE_OUT]);
    return STATUS_OKAY;
}

/*
 * Executes command and sends stdout to client
 * Parameters:
 *   socket_fd - Socket file descriptor
 *   pfd - Pipe file descriptors
 *   full_command - Complete command string
 *   pout - Pointer to FILE stream for output
 *   output - Buffer for command output
 * Returns: 0 on success, -1 on error
 */
int send_command_stdout(const int socket_fd, const unsigned char *encryption_key, int pfd[2], char full_command[512],
                        FILE **pout, char output[1024]) {
    *pout = popen(full_command, "r");
    if (*pout == NULL) {
        perror("popen failed");
        close(pfd[PIPE_OUT]);
        return GENERAL_ERROR;
    }
    close(pfd[PIPE_OUT]);
    while (fgets(output, BUFFER_SIZE_OUTPUT, *pout) != NULL) {
        // Send each line to the socket
        char buffer[BUFFER_SIZE_SEND] = {NULL_CHAR};
        prepare_buffer(buffer, sizeof(buffer), output, "OUT");
        s_send(socket_fd, encryption_key, buffer, strlen(buffer));
    }
    return STATUS_OKAY;
}

/*
 * Handles command stderr and sends to client
 * Parameters:
 *   socket_fd - Socket file descriptor
 *   pfd - Pipe file descriptors
 *   error_check - Error status flag
 *   pout - FILE stream for output
 *    - Buffer for error output
 *   pipe_err - Pointer to FILE stream for errors
 * Returns: 0 on success, -1 on error
 */
int send_command_stderr(const int socket_fd, const unsigned char *encryption_key, int pfd[2], int8_t *error_check,
                        FILE *pout, char output[1024],
                        FILE **pipe_err) {
    *pipe_err = fdopen(pfd[PIPE_SUCCESS], "r");
    if (*pipe_err == NULL) {
        perror("fdopen failed");
        pclose(pout);
        return GENERAL_ERROR;
    }
    while (fgets(output, BUFFER_SIZE_OUTPUT, *pipe_err) != NULL) {
        // Send each error line to the socket
        *error_check = true;
        char buffer[BUFFER_SIZE_SEND] = {NULL_CHAR};
        prepare_buffer(buffer, sizeof(buffer), output, "ERR");
        s_send(socket_fd, encryption_key, buffer, strlen(buffer));
    }
    return STATUS_OKAY;
}

/*
* Executes a shell command and handles its output through a socket connection.
* This function executes the provided command in the specified working directory,
* captures both stdout and stderr, and sends the output back through the socket.
* The function also handles directory changes if the command includes 'cd'.
* Parameters:
*   command - The shell command to execute
*   command_size - Size of the command buffer
*   socket_fd - Socket file descriptor for sending output
*   working_directory - Current working directory path
*   working_directory_size - Size of working directory buffer
* Returns: 0 on success, -1 on failure
*/
int execute_command_and_send(char *command, const size_t command_size,
                             const int socket_fd, const unsigned char *encryption_key, char *working_directory,
                             const size_t working_directory_size) {
    int pfd[2];
    int8_t error_check = 0;
    char full_command[BUFFER_SIZE_FULL_CMD];
    s_send(socket_fd, encryption_key,EMPTY_DATA, strlen(EMPTY_DATA));
    if (build_check_command(command, command_size, socket_fd, encryption_key, working_directory, &pfd, &full_command) ==
        GENERAL_ERROR) {
        return GENERAL_ERROR;
    }
    FILE *pout;
    char output[BUFFER_SIZE_OUTPUT] = {0};
    if (send_command_stdout(socket_fd, encryption_key, pfd, full_command, &pout, output) == GENERAL_ERROR) {
        return GENERAL_ERROR;
    }
    FILE *pipe_err;
    if (send_command_stderr(socket_fd, encryption_key, pfd, &error_check, pout, output, &pipe_err) == GENERAL_ERROR) {
        return GENERAL_ERROR;
    }
    if (!error_check) {
        check_cd(socket_fd, encryption_key, command, working_directory, working_directory_size);
    }
    // Clean up
    pclose(pout);
    fclose(pipe_err);
    return STATUS_OKAY;
}

/*
 * Finds the most recently used 'cd' command in a given command string.
 * This function scans through the entire input command, identifying and tracking
 * the last occurrence of a change directory (cd) command. It's useful for
 * processing command sequences where multiple 'cd' commands might exist,
 * ensuring that only the most recent directory change is considered.
 *
 * The function works by repeatedly searching for "cd " substrings, updating
 * the last found pointer with each iteration. This allows tracking of the
 * final 'cd' command in a potentially complex command string.
 *
 * Parameters:
 *   command - The input string to search for 'cd' commands
 * Returns: Pointer to the last 'cd' command, or NULL if no 'cd' found
 */
char *find_last_cd(const char *command) {
    char *last_cd = NULL;
    char *current_cd = strstr(command, "cd "); // Start searching for the first occurrence
    while (current_cd != NULL) {
        last_cd = current_cd; // Update the last found pointer
        current_cd = strstr(current_cd + NEXT_CD, "cd "); // Search for the next occurrence
    }
    return last_cd; // Return the last occurrence or NULL if none found
}

/*
 * Validates whether a character is acceptable in a Linux file path.
 * This function provides a strict validation of path characters, allowing
 * only alphanumeric characters, specific special characters commonly used
 * in file and directory names. This helps prevent injection or malicious
 * path manipulation by rejecting unexpected characters.
 *
 * The allowed characters include:
 * - Alphanumeric characters (letters and numbers)
 * - Dot (.) for file extensions or current directory
 * - Hyphen (-) for some naming conventions
 * - Underscore (_) for file/directory naming
 * - Forward slash (/) for path navigation
 * - Tilde (~) for home directory references
 *
 * Parameters:
 *   c - The character to validate
 * Returns: 1 if character is valid, 0 otherwise
 */
int is_valid_path_char(const char c) {
    // Valid path characters: alphanumeric, '.', '-', '_', '/', and '~'
    return isalnum(c) || c == '.' || c == '-' || c == '_' || c == '/' || c == '~' ||
           c == '+' || c == '^' || c == '%' || c == '=' || c == ':' || c == ',' || c == '@';
}

/*
 * Sanitizes a 'cd' command by extracting only the valid path portion.
 * This function ensures that only safe, well-formed directory paths are
 * processed by truncating the command at the first invalid character.
 * It provides a crucial security measure to prevent command injection
 * or unexpected behavior when changing directories.
 *
 * The function first verifies the command starts with 'cd_', then
 * systematically checks each subsequent character. As soon as an
 * invalid character is encountered, the command is truncated, effectively
 * sanitizing the input path.
 *
 * Parameters:
 *   cd_command - The CD command to be sanitized
 *   max_len - Maximum length of the command buffer
 */
void extract_valid_cd_command(char *cd_command, const size_t max_len) {
    // Check if the command starts with "cd "
    if (strncmp(cd_command, "cd ", CD_AND_SPACE_LEN) != CMP_EQUAL) {
        return; // Not a cd command, do nothing
    }

    // Find the first invalid character, starting after "cd "
    for (int i = CD_AND_SPACE_LEN; i < max_len; i++) {
        if (!is_valid_path_char(cd_command[i])) {
            cd_command[i] = '\0';
            break;
        }
    }
}

/*
 * Extracts and prepares the last 'cd' command for execution.
 * This function serves as a comprehensive handler for CD command processing.
 * It finds the most recent 'cd' command, validates its path, and prepares
 * it for potential execution. If no valid CD command is found or the path
 * is invalid, it handles error scenarios appropriately.
 *
 * The function performs multiple critical steps:
 * 1. Locate the last 'cd' command in the input string
 * 2. Extract and sanitize the directory path
 * 3. Validate the extracted path
 * 4. Prepare for potential directory change
 *
 * Parameters:
 *   command - The full input command string
 *   cd_command - Pointer to store the extracted CD command
 * Returns: Status of command extraction (success or error)
 */
int8_t get_cd_command(const char *command, char **cd_command) {
    *cd_command = find_last_cd(command);
    if (*cd_command == NULL) {
        return STATUS_OKAY; // No "cd" command found, nothing to do
    }
    // Extract the valid portion of the "cd" command
    extract_valid_cd_command(*cd_command, strlen(*cd_command));
    // If no valid path was extracted, return an error
    if (strlen(*cd_command) == 0) {
        fprintf(stderr, "Invalid cd command\n");
        return GENERAL_ERROR;
    }
    return true;
}

/*
 * Constructs and executes a 'cd' command in a controlled environment.
 * This function provides a secure mechanism for changing directories,
 * featuring multiple layers of safety and error handling. It uses a
 * subprocess to change directories, captures the resulting path, and
 * ensures that only valid directory changes are processed.
 *
 * Key operations include:
 * 1. Creating a pipe for error and output capturing
 * 2. Constructing a shell command that changes directory
 * 3. Executing the command in a controlled subprocess
 * 4. Capturing the resulting working directory path
 * 5. Handling potential errors during directory change
 *
 * Parameters:
 *   working_directory - Current working directory path
 *   cd_command - Sanitized CD command to execute
 *   output - Buffer to store the resulting directory path
 * Returns: Status of directory change operation
 */
int8_t build_and_execute_cd(char *working_directory, char *cd_command, char (*output)[512]) {
    int pfd[2];
    if (pipe(pfd) < PIPE_ERR_CHECK) {
        perror("pipe failed");
        return GENERAL_ERROR;
    }
    // Prepare the command to execute in a subshell
    char shell_command[BUFFER_SIZE_CD];
    snprintf(shell_command, sizeof(shell_command), "cd %s && %s 2>&%d && pwd", working_directory, cd_command,
             pfd[PIPE_OUT]);
    FILE *pout = popen(shell_command, "r");
    if (pout == NULL) {
        perror("popen failed");
        close(pfd[PIPE_OUT]);
        return GENERAL_ERROR;
    }
    close(pfd[PIPE_OUT]);
    if (fgets(*output, sizeof(*output), pout) == NULL) {
        pclose(pout);
        return GENERAL_ERROR;
    }
    pclose(pout);
    close(pfd[PIPE_READ]);
    return true;
}

/*
 * Comprehensive handler for 'cd' command processing in a networked context.
 * This function orchestrates the entire CD command workflow, from initial
 * parsing to final directory update and client communication. It provides
 * a robust, secure mechanism for handling directory change requests in a
 * networked environment.
 *
 * The function performs a complex sequence of operations:
 * 1. Extract and validate the CD command
 * 2. Safely execute the directory change
 * 3. Update the working directory
 * 4. Communicate the new directory state to the client
 * 5. Handle potential errors at each stage
 *
 * Parameters:
 *   sock_fd - Socket file descriptor for client communication
 *   command - Incoming command string
 *   working_directory - Current working directory buffer
 *   working_directory_size - Size of the working directory buffer
 * Returns: Status of the entire CD command processing
 */
int8_t check_cd(const int sock_fd, const unsigned char *encryption_key, const char *command,
                char *working_directory, const size_t working_directory_size) {
    char *cd_command;
    if (get_cd_command(command, &cd_command) != true) {
        return GENERAL_ERROR;
    }
    char output[BUFFER_SIZE_CD];
    if (build_and_execute_cd(working_directory, cd_command, &output) != true) {
        return GENERAL_ERROR;
    }
    // Remove the trailing newline from the output
    const size_t len = strlen(output);
    if (len > MIN_VALID_LENGTH && output[len - LAST_CHAR_OFFSET] == '\n') {
        output[len - LAST_CHAR_OFFSET] = NULL_CHAR;
    }
    // Ensure the output fits into the working_directory buffer
    if (strlen(output) >= working_directory_size) {
        fprintf(stderr, "Working directory path is too long\n");
        return GENERAL_ERROR;
    }
    // Update the working directory
    memset(working_directory, NULL_CHAR, working_directory_size);
    snprintf(working_directory, working_directory_size, "%s", output);
    // Prepare the buffer to send to the client
    char cd_buf[BUFFER_SIZE_CD];
    prepare_buffer(cd_buf, sizeof(cd_buf), working_directory, "CWD");
    // Send the updated working directory to the client
    if (s_send(sock_fd, encryption_key, cd_buf, strlen(cd_buf)) < 0) {
        perror("s_send failed");
        return GENERAL_ERROR;
    }
    return STATUS_OKAY;
}
