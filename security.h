#ifndef SECURITY_H
#define SECURITY_H
#include "cryptography_game_util.h"

/*
* Validates command string against security rules.
* Checks if the command contains banned words or uses unauthorized
* commands. Ensures command adheres to allowed command list and
* security policies.
* Parameters:
*   data - Command string to validate
* Returns: 1 if command is valid, 0 if command violates security rules
*/
int check_command_data(const char *data);

#endif //SECURITY_H
