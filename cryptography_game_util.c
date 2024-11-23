/*
* Ido Kantor
* methods used in code for the game
 */
#include "cryptography_game_util.h"

#include <limits.h>

/* Constants for socket configuration */
#define SOCKET_FLAG 0
#define NO_IP 0
#define PORT_RANGE_MIN 0
#define PORT_RANGE_MAX 65535
#define CHECK_IP 0

/* Constants for buffer sizes and message handling */
#define NUM_ZERO 4
#define MAX_COMMAND_SIZE 500
#define MAX_FULL_COMMAND 512
#define MAX_OUTPUT_BUFFER 1024
#define MAX_SEND_BUFFER 2048
#define MAX_CD_BUFFER 256

//globals
const char *banned_words[] = {"etc", "proc"};
const char *allowed_commands[] = {"ls", "cat", "pwd", "date", "cd"};

// prototypes

/*
 * Calculates the number of decimal places in an integer
 * Parameters:
 *   n - The integer to analyze
 * Returns: Number of decimal places
 */
int numPlaces(int n);

/*
 * Extracts the total length value from a tlength string
 * Parameters:
 *   tlength_str - String containing the tlength field
 * Returns: Extracted length value or -1 on error
 */
int extract_tlength(const char *tlength_str);

/*
 * Processes a single packet by extracting its fields
 * Parameters:
 *   packets - Raw packet data
 *   packets_data - Buffer for processed data
 *   packets_type - Buffer for packet types
 *   packets_length - Buffer for packet lengths
 *   tlength - Total length of packet
 *   packets_length_size - Size of length buffer
 *   packets_data_size - Size of data buffer
 *   packets_type_size - Size of type buffer
 * Returns: 0 on success, -1 on failure
 */
int8_t process_packet(
    const char *packets, char *packets_data, char *packets_type,
    char *packets_length, ssize_t tlength,
    size_t packets_length_size, ssize_t packets_data_size,
    size_t packets_type_size);

/*
 * Finds the last occurrence of 'cd' command in input
 * Parameters:
 *   command - The command string to search
 * Returns: Pointer to last 'cd' occurrence or NULL
 */
char *find_last_cd(const char *command);

/*
 * Processes cd command and updates working directory
 * Parameters:
 *   sock_fd - Socket file descriptor
 *   command - Command string
 *   command_size - Size of command buffer
 *   working_directory - Current working directory
 *   working_directory_size - Size of directory buffer
 * Returns: 0 on success, -1 on failure
 */
int8_t check_cd(int sock_fd, const char *command, size_t command_size,
                char *working_directory, size_t working_directory_size);

int createTCPIpv4Socket() {
    return socket(AF_INET, SOCK_STREAM, SOCKET_FLAG);
}


int createIPv4Address(const char *ip, const int port,
                      struct sockaddr_in *address) {
    int ip_check = 1;
    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    if (strlen(ip) == NO_IP) {
        address->sin_addr.s_addr = INADDR_ANY;
    } else {
        ip_check = inet_pton(AF_INET, ip, &address->sin_addr.s_addr);
    }
    return PORT_RANGE_MIN < port && port <= PORT_RANGE_MAX && ip_check !=
           CHECK_IP;
}

int execute_command_and_send(char *command, const size_t command_size,
                             const int socket_fd, char *working_directory,
                             const size_t working_directory_size) {
    int pfd[2]; // Pipe file descriptors
    int8_t error_check = 0;
    if (pipe(pfd) < 0) {
        perror("pipe failed");
        return -1;
    }
    if (command_size + strlen(working_directory) > 500) {
        char err_buf[256];
        prepare_buffer(err_buf, sizeof(err_buf), "command size too large\n", "ERR");
        s_send(socket_fd, err_buf, strlen(err_buf));
        return -1;
    }
    char full_command[512];
    snprintf(full_command, sizeof(full_command), "cd %s 2>&%d && %s 2>&%d",
             working_directory, pfd[1], command, pfd[1]);
    FILE *pout = popen(full_command, "r");
    if (pout == NULL) {
        perror("popen failed");
        close(pfd[1]);
        return -1;
    }
    close(pfd[1]);
    char output[1024];
    while (fgets(output, sizeof(output), pout) != NULL) {
        // Send each line to the socket
        char buffer[2048] = {0};
        prepare_buffer(buffer, sizeof(buffer), output, "OUT");
        s_send(socket_fd, buffer, strlen(buffer));
    }
    FILE *pipe_err = fdopen(pfd[0], "r");
    if (pipe_err == NULL) {
        perror("fdopen failed");
        pclose(pout);
        return -1;
    }

    while (fgets(output, sizeof(output), pipe_err) != NULL) {
        // Send each error line to the socket
        error_check = 1;
        char buffer[2048] = {0};
        prepare_buffer(buffer, sizeof(buffer), output, "OUT");
        s_send(socket_fd, buffer, strlen(buffer));
    }
    if (!error_check) {
        check_cd(socket_fd, command, command_size, working_directory, working_directory_size);
    }
    // Clean up
    pclose(pout);
    fclose(pipe_err);
    return 0;
}


int numPlaces(int n) {
    int r = 1;
    if (n < 0) n = (n == 0) ? INT_MAX : -n;
    while (n > 9) {
        n /= 10;
        r++;
    }
    return r;
}

int extract_tlength(const char *tlength_str) {
    // Skip "tlength:"
    const char *number_start = tlength_str + 8;
    char *end_ptr = strchr(number_start, ';');
    if (!end_ptr) {
        // If no delimiter found, it's an invalid format
        fprintf(stderr, "Invalid tlength format\n");
        return -1;
    }
    // Create a temporary buffer to store the number
    const size_t length = end_ptr - number_start;
    char temp[length + 1];
    strncpy(temp, number_start, length);
    temp[length] = 0;
    // Convert to integer
    return atoi(temp);
}

/*
 * takes a single packet and processes it by its fields
 * appending them to a pointer of all packets fields
 */

int8_t process_packet(
    const char *packets, char *packets_data, char *packets_type,
    char *packets_length, const ssize_t tlength,
    const size_t packets_length_size, const ssize_t packets_data_size,
    const size_t packets_type_size) {
    // Make a copy of the packet for parsing
    const size_t rest_of_length = 9 + numPlaces(tlength);
    //-9 for tlength: + ; -amount of tlength digits
    char *packet = strndup(packets + rest_of_length, tlength - rest_of_length);
    if (!packet) {
        perror("Failed to allocate memory for buffer");
        return -1;
    }
    // Step 3: Parse the fields using the delimiter
    const char *type = strtok(packet, ";");
    const char *data_length = strtok(NULL, ";");
    const char *data = strtok(NULL, ";");
    if (type && data_length && data) {
        if (strncmp(type, "type:", 5) == 0 && strncmp(data_length, "length:", 7)
            == 0 && atoi(data_length + 7) == strlen(data + 5)) {
            if (packets_data_size >= strlen(packets_data) + strlen(data)) {
                strcat(packets_data, data + 5);
            }
            if (packets_type_size >= strlen(packets_type) + strlen(type) + 1) {
                strcat(packets_type, type + 5);
                strcat(packets_type, ";");
            }
            if (packets_length_size >= strlen(packets_length) + strlen(
                    data_length) + 1) {
                strcat(packets_length, data_length + 7);
                strcat(packets_length, ";");
            }
        } else {
            //fprintf(stderr, "Invalid packet fields\n");
            free(packet);
            return -1;
        }
    } else {
        //fprintf(stderr, "Failed to parse packet fields\n");
        free(packet);
        return -1;
    }
    free(packet);
    return 0;
}

int parse_received_packets(
    const char *received_packets, char *packets_data, char *packets_type,
    char *packets_length,
    const size_t packets_size, const size_t packets_length_size,
    const ssize_t packets_data_size,
    const size_t packets_type_size) {
    const char *current = received_packets;
    size_t current_length = 0;
    while (*current && current_length < packets_size) {
        const char *tlength_str = strstr(current, "tlength:");
        if (tlength_str == NULL) {
            return 0;
        }
        const ssize_t tlength = extract_tlength(tlength_str);
        if (tlength <= 0) {
            printf("tlength is less than zero\n");
            return 0;
        }
        if (strlen(current) < tlength) {
            printf("tlength is bigger than current length\n");
            return 0;
        }
        const int8_t check = process_packet(current, packets_data, packets_type,
                                            packets_length, tlength,
                                            packets_length_size,
                                            packets_data_size,
                                            packets_type_size);
        if (check == -1) {
            return 0;
        }
        current += tlength;
        current_length += tlength;
    }
    return current_length == packets_size;
}

int8_t prepare_buffer(
    char *buffer, const size_t buffer_size,
    const char *data, const char *type) {
    // Calculate the length of the data
    const int data_length = strlen(data);

    // Format the message without tlength first, so we can calculate it later
    const int formatted_length = snprintf(buffer, buffer_size,
                                          "tlength:;type:%s;length:%d;data:%s",
                                          type, data_length, data);

    // If formatting fails or message is too large, return
    if (formatted_length >= buffer_size) {
        fprintf(stderr,
                "Buffer too small to store formatted message.\n");
        return 0;
    }
    // Calculate tlength as the length of the formatted message (including "tlength:" part)
    const int message_length = snprintf(NULL, 0,
                                        "tlength:%d;type:%s;length:%d;data:%s",
                                        formatted_length, type, data_length,
                                        data);

    // Format the final message with correct tlength
    snprintf(buffer, buffer_size,
             "tlength:%d;type:%s;length:%d;data:%s",
             message_length, type, data_length, data);
    return 1;
}

ssize_t s_send(const int socket, const char *data, const size_t data_size) {
    char length_string[NUM_ZERO + 1] = {0}; // +1 for null-terminator
    const size_t buf_size = NUM_ZERO + data_size + 1;
    char buffer[buf_size];
    memset(buffer, 0, buf_size);
    // Generate a zero-padded length string
    snprintf(length_string, sizeof(length_string), "%0*u", NUM_ZERO,
             (unsigned int) data_size);

    // Copy the length string and data into the buffer
    memcpy(buffer, length_string, NUM_ZERO); // Copy the zero-padded length
    memcpy(buffer + NUM_ZERO, data, data_size); // Copy the data

    // Send the buffer (length + data)
    return send(socket, buffer, NUM_ZERO + data_size, 0);
}

ssize_t s_recv(const int socket, char *data, const size_t data_size) {
    char raw_size[LENGTH_CHECK + 1] = {0};
    // Buffer for the size header (+1 for null-terminator)
    size_t received = 0;

    // Step 1: Receive the size header
    while (received < LENGTH_CHECK) {
        const ssize_t bytes = recv(socket, raw_size + received,
                                   LENGTH_CHECK - received, 0);
        if (bytes <= 0) {
            // Handle errors or connection closure
            return FINISH_RECEIVE;
        }
        received += bytes;
    }
    char *endptr;
    const size_t received_data_size = strtoul(raw_size, &endptr, 10);
    if (received_data_size == 0 || received_data_size > data_size || *endptr != '\0') {
        return -1;
    }
    // Step 2: Receive the payload
    size_t total_received = 0;
    while (total_received < received_data_size) {
        const ssize_t bytes = recv(socket, data + total_received,
                                   received_data_size - total_received, 0);
        if (bytes <= 0) {
            // Handle errors or connection closure
            return FINISH_RECEIVE;
        }
        total_received += bytes;
    }
    // Return the total bytes received (header + payload)
    return total_received + LENGTH_CHECK;
}

char *find_last_cd(const char *command) {
    char *last_cd = NULL;
    char *current_cd = strstr(command, "cd ");  // Start searching for the first occurrence
    while (current_cd != NULL) {
        last_cd = current_cd;                 // Update the last found pointer
        current_cd = strstr(current_cd + 1, "cd ");  // Search for the next occurrence
    }
    return last_cd;  // Return the last occurrence or NULL if none found
}

int8_t check_cd(const int sock_fd, const char *command, const size_t command_size,
                char *working_directory, const size_t working_directory_size) {
    char *cd_command = find_last_cd(command);
    if (cd_command != NULL) {
        char *new_working_directory = strtok(cd_command + 3, " ");
        if (new_working_directory == NULL) {
            return -1;
        }
        if (strlen(new_working_directory) + strlen(working_directory) + 1 > working_directory_size) {
            return -1;
        }
        if (new_working_directory[strlen(new_working_directory) - 1] == '/' &&
            strlen(new_working_directory) > 1) {
            //check for / in the end of new dir e.g. cd proc/ -> proc
            new_working_directory[strlen(new_working_directory) - 1] = 0;
        }
        if (strcmp(new_working_directory, "..") == 0) {
            for (int i = strlen(working_directory) - 1; i >= 0; i--) {
                if (working_directory[i] == '/') {
                    memset(working_directory + i, 0, strlen(working_directory) - i);
                }
            }
            if(strlen(working_directory) == 0) {
                *working_directory = '/';
            }
        }
        else {
            if (*new_working_directory != '/') {
                /*
                 * cwd /home, cd idokantor -> /home/idokantor
                 * cwd /, cd home -> /home
                 */
                if (strcmp(working_directory, "/") != 0) {
                    strcat(working_directory, "/");
                }
                strcat(working_directory, new_working_directory);
            }
            else {
                //cwd /x/y/z, cd /a/b/c -> /a/b/c
                strcpy(working_directory, new_working_directory);
            }
        }
        char cd_buf[256];
        prepare_buffer(cd_buf, sizeof(cd_buf), working_directory, "CWD");
        //send cwd for first client to print and confirm
        s_send(sock_fd, cd_buf, strlen(cd_buf));
    }
    return 0;
}


// Helper function to check if the string contains any banned words
bool contains_banned_word(const char *data) {
    for (int i = 0; i < sizeof(banned_words) / sizeof(banned_words[0]); i++) {
        if (strstr(data, banned_words[i]) != NULL) {
            return true;
        }
    }
    return false;
}

// Helper function to check if the command is allowed
bool is_allowed_command(const char *cmd) {
    for (int i = 0; i < sizeof(allowed_commands) / sizeof(allowed_commands[0]); i++) {
        if (strncmp(cmd, allowed_commands[i], strlen(allowed_commands[i])) == 0) {
            return true;
        }
    }
    return false;
}

// Main function to check the command string
int check_command_data(const char *data) {
    char *data_copy = strdup(data);
    char *token = strtok(data_copy, "&&");

    while (token != NULL) {
        // Trim leading and trailing whitespaces
        while (*token == ' ') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') end--;
        *(end + 1) = '\0';

        // Check for banned words
        if (contains_banned_word(token)) {
            free(data_copy);
            return 0;  // Banned word found, return 0
        }

        // Check if the command is allowed
        char cmd[1024] = {0};
        sscanf(token, "%s", cmd);  // Extract the command (first word)
        if (!is_allowed_command(cmd)) {
            free(data_copy);
            return 0;  // Command not allowed, return 0
        }

        // Get the next command
        token = strtok(NULL, "&&");
    }

    free(data_copy);
    return 1;  // Data is valid
}