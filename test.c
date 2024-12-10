#include "cryptography_game_util.h"

int main() {
    /*const char *data1 = "ls /home&& rm test.txt";
    const char *data2 = "ls /home&& 0";
    const char *data3 = "ls /home&& ls /etc";
    const char *data4 = "ls /home&& ls /home/idokantor && cd /";
    const char *data5 = "rm test.txt";
    printf("Check data1: %d\n", check_command_data(data1)); // Should return 0
    printf("Check data2: %d\n", check_command_data(data2)); // Should return 0
    printf("Check data3: %d\n", check_command_data(data3)); // Should return 0
    printf("Check data4: %d\n", check_command_data(data4)); // Should return 1
    printf("Check data5: %d\n", check_command_data(data5)); // Should return 0*/
    char buffer[1024];
    prepare_buffer(buffer, sizeof(buffer), "cd /home",
                   "CMD");
    printf("%s\n", buffer);
    return 0;
}

/*
 * comment this code, dont change any logic of the code and add macros in the code for constants.
 * also if a constant is already in the code dont change it for a different constant. again dont change any code logic,
 * dont comment too much try to add comments based on how the code is already commented if there are comments missing
 * add more inside functions dont comment too much. a good rule of thumb for comments inside functions is every 5 lines add a comment
 * each prototype comment like this style.
 /*
 * Processes received data from the server based on message type.
 * This function handles three different message types: OUT (output),
 * CMD (commands), and ERR (errors). It parses incoming messages and
 * processes each segment according to its type and length.
 * Parameters:
 *   socketFD - The socket file descriptor
 *   data - Buffer containing the message data
 *   type - Buffer containing message type information
 *   length - Buffer containing message length information
 * Returns: None
 */
