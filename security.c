#include "security.h"

//globals
const char *banned_words[] = {"etc", "proc", "<", ">", "sudo"};
const char *allowed_commands[] = {"ls", "cat", "pwd", "date", "cd"};

//prototypes

/*
 * Checks if string contains any banned words
 * Parameters:
 *   data - String to check
 * Returns: true if banned word found, false otherwise
 */
bool contains_banned_word(const char *data);

/*
 * Validates if command is in allowed commands list
 * Parameters:
 *   cmd - Command to check
 * Returns: true if command is allowed, false otherwise
 */
bool is_allowed_command(const char *cmd);

/*
* Validates command string against security rules.
* Checks if the command contains banned words or uses unauthorized
* commands. Ensures command adheres to allowed command list and
* security policies.
* Parameters:
*   data - Command string to validate
* Returns: 1 if command is valid, 0 if command violates security rules
*/
bool check_command_data(const char *data);

//methods

/*
 * Checks if string contains any banned words
 * Parameters:
 *   data - String to check
 * Returns: true if banned word found, false otherwise
 */

bool contains_banned_word(const char *data) {
    for (int i = 0; i < sizeof(banned_words) / sizeof(banned_words[0]); i++) {
        if (strstr(data, banned_words[i]) != NULL) {
            return true;
        }
    }
    return false;
}

/*
 * Validates if command is in allowed commands list
 * Parameters:
 *   cmd - Command to check
 * Returns: true if command is allowed, false otherwise
 */
bool is_allowed_command(const char *cmd) {
    for (int i = 0; i < sizeof(allowed_commands) / sizeof(allowed_commands[0]); i++) {
        if (strncmp(cmd, allowed_commands[i], strlen(allowed_commands[i])) == 0) {
            return true;
        }
    }
    return false;
}

/*
* Validates command string against security rules.
* Checks if the command contains banned words or uses unauthorized
* commands. Ensures command adheres to allowed command list and
* security policies.
* Parameters:
*   data - Command string to validate
* Returns: 1 if command is valid, 0 if command violates security rules
*/
bool check_command_data(const char *data) {
    char *data_copy = strdup(data);
    char *token = strtok(data_copy, "&&");
    while (token != NULL) {
        // Trim leading and trailing whitespaces
        while (*token == ' ') token++;
        char *end = token + strlen(token) - LAST_CHAR_OFFSET;
        while (end > token && *end == ' ') end--;
        *(end + NULL_TERMINATOR_OFFSET) = NULL_CHAR;
        // Check for banned words
        if (contains_banned_word(token)) {
            free(data_copy);
            return false; // Banned word found, return 0
        }
        // Check if the command is allowed
        char cmd[BUFFER_SIZE_OUTPUT] = {0};
        sscanf(token, "%s", cmd); // Extract the command (first word)
        if (!is_allowed_command(cmd)) {
            free(data_copy);
            return false; // Command not allowed, return 0
        }
        // Get the next command
        token = strtok(NULL, "&&");
    }
    free(data_copy);
    return true; // Data is valid
}
