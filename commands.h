//
// Created by idokantor on 12/12/24.
//

#ifndef COMMANDS_H
#define COMMANDS_H
#include "cryptography_game_util.h"

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
int execute_command_and_send(char *command, size_t command_size,
                             int socket_fd, char *working_directory,
                             size_t working_directory_size);
#endif //COMMANDS_H
