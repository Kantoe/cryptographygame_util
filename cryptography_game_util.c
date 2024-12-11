/*
* Ido Kantor
* methods used in code for the game
 */
#include "cryptography_game_util.h"

#include <ctype.h>
#include <limits.h>

//globals
const char *banned_words[] = {"etc", "proc", "<", ">", "sudo"};
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
 * Creates a TCP IPv4 socket for network communication
 * Parameters: None
 * Returns: Socket file descriptor or -1 on error
 */
int createTCPIpv4Socket();

/* Initializes an IPv4 address structure with the given IP and port.
 * Parameters:
 * - ip: A string representing the IP address.
 * If an empty string is provided,
 * INADDR_ANY will be set, allowing the socket to bind
 * to all available interfaces.
 * - port: The port number to bind to.
 * - address: A pointer to a sockaddr_in structure
 * to be populated with the IP and port.
 * Returns:
 * - 0 on success if INADDR_ANY is used;
 * - 1 on successful conversion of the provided
 * IP address to network format;
 * - 0 if the port is outside the valid range.
 */
int createIPv4Address(const char *ip, int port, struct sockaddr_in *address);

/*
 * Extracts total length value from a tlength string field
 * Parameters:
 *   tlength_str - String containing the tlength field
 * Returns: Extracted length value or -1 on error
 */
int extract_tlength(const char *tlength_str);

/*
 * Processes a single packet by extracting and validating its fields
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
int8_t process_packet(const char *packets, char *packets_data, char *packets_type,
                      char *packets_length, ssize_t tlength, size_t packets_length_size,
                      ssize_t packets_data_size, size_t packets_type_size);

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
int8_t check_cd(int sock_fd, const char *command,
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
int build_check_command(char *command, size_t command_size, int socket_fd,
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
int send_command_stdout(int socket_fd, int pfd[2], char full_command[512],
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
int send_command_stderr(int socket_fd, int pfd[2], int8_t *error_check,
                        FILE *pout, char output[1024], FILE **pipe_err);

/*
 * Validates packet fields and updates corresponding buffers
 * Parameters:
 *   packets_data - Buffer for packet data
 *   packets_type - Buffer for packet types
 *   packets_length - Buffer for packet lengths
 *   packets_length_size - Size of length buffer
 *   packets_data_size - Size of data buffer
 *   packets_type_size - Size of type buffer
 *   packet - Current packet being processed
 * Returns: 0 on success, -1 on failure
 */
int8_t check_command_fields(char *packets_data, char *packets_type,
                            char *packets_length, size_t packets_length_size,
                            ssize_t packets_data_size, size_t packets_type_size,
                            char *packet);

/*
 * Receives size field from socket
 * Parameters:
 *   socket - Socket file descriptor
 *   raw_size - Buffer for size data
 * Returns: 0 on success, FINISH_RECEIVE on error
 */
ssize_t receive_raw_size(int socket, char raw_size[5]);

/*
 * Receives data from socket based on size
 * Parameters:
 *   socket - Socket file descriptor
 *   data - Buffer for received data
 *   received_data_size - Expected data size
 *   total_received - Actual bytes received
 * Returns: 0 on success, FINISH_RECEIVE on error
 */
ssize_t receive_raw_data(int socket, char *data, size_t received_data_size,
                         size_t *total_received);

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
int check_command_data(const char *data);

//methods
/*
 * Creates a TCP IPv4 socket for network communication
 * Parameters: None
 * Returns: Socket file descriptor or -1 on error
 */
int createTCPIpv4Socket() {
    return socket(AF_INET, SOCK_STREAM, SOCKET_FLAG);
}

/* Initializes an IPv4 address structure with the given IP and port.
 * Parameters:
 * - ip: A string representing the IP address.
 * If an empty string is provided,
 * INADDR_ANY will be set, allowing the socket to bind
 * to all available interfaces.
 * - port: The port number to bind to.
 * - address: A pointer to a sockaddr_in structure
 * to be populated with the IP and port.
 * Returns:
 * - 0 on success if INADDR_ANY is used;
 * - 1 on successful conversion of the provided
 * IP address to network format;
 * - 0 if the port is outside the valid range.
 */
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
int build_check_command(char *command, const size_t command_size, const int socket_fd, char *working_directory,
                        int (*pfd)[2], char (*full_command)[512]) {
    if (pipe(*pfd) < PIPE_ERR_CHECK) {
        perror("pipe failed");
        return GENERAL_ERROR;
    }
    if (command_size + strlen(working_directory) > BUFFER_SIZE_CMD_MAX) {
        char err_buf[ERR_BUFFER_SIZE];
        prepare_buffer(err_buf, sizeof(err_buf), "command size too large\n", "ERR");
        s_send(socket_fd, err_buf, strlen(err_buf));
        return GENERAL_ERROR;
    }
    snprintf(*full_command, sizeof(*full_command), "cd %s 2>&%d && %s 2>&%d",
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
int send_command_stdout(const int socket_fd, int pfd[2], char full_command[512], FILE **pout, char output[1024]) {
    *pout = popen(full_command, "r");
    if (*pout == NULL) {
        perror("popen failed");
        close(pfd[PIPE_OUT]);
        return GENERAL_ERROR;
    }
    close(pfd[PIPE_OUT]);
    while (fgets(output, BUFFER_SIZE_OUTPUT, *pout) != NULL) {
        // Send each line to the socket
        char buffer[BUFFER_SIZE_SEND] = {0};
        prepare_buffer(buffer, sizeof(buffer), output, "OUT");
        s_send(socket_fd, buffer, strlen(buffer));
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
int send_command_stderr(const int socket_fd, int pfd[2], int8_t *error_check, FILE *pout, char output[1024],
                        FILE **pipe_err) {
    *pipe_err = fdopen(pfd[PIPE_ERR], "r");
    if (*pipe_err == NULL) {
        perror("fdopen failed");
        pclose(pout);
        return GENERAL_ERROR;
    }
    while (fgets(output, BUFFER_SIZE_OUTPUT, *pipe_err) != NULL) {
        // Send each error line to the socket
        *error_check = 1;
        char buffer[BUFFER_SIZE_SEND] = {0};
        prepare_buffer(buffer, sizeof(buffer), output, "OUT");
        s_send(socket_fd, buffer, strlen(buffer));
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
                             const int socket_fd, char *working_directory,
                             const size_t working_directory_size) {
    int pfd[2];
    int8_t error_check = 0;
    char full_command[BUFFER_SIZE_FULL_CMD];
    s_send(socket_fd,EMPTY_DATA, strlen(EMPTY_DATA));
    if (build_check_command(command, command_size, socket_fd, working_directory, &pfd, &full_command) ==
        GENERAL_ERROR) {
        return GENERAL_ERROR;
    }
    FILE *pout;
    char output[BUFFER_SIZE_OUTPUT];
    if (send_command_stdout(socket_fd, pfd, full_command, &pout, output) == GENERAL_ERROR) {
        return GENERAL_ERROR;
    }
    FILE *pipe_err;
    if (send_command_stderr(socket_fd, pfd, &error_check, pout, output, &pipe_err) == GENERAL_ERROR) {
        return GENERAL_ERROR;
    }
    if (!error_check) {
        check_cd(socket_fd, command, working_directory, working_directory_size);
    }
    // Clean up
    pclose(pout);
    fclose(pipe_err);
    return STATUS_OKAY;
}

/*
 * Calculates the number of decimal places in an integer
 * Parameters:
 *   n - The integer to analyze
 * Returns: Number of decimal places
 */
int numPlaces(int n) {
    int r = 1; // Start with the minimum count of places
    if (n < 0) n = HANDLE_ZERO(HANDLE_NEGATIVE(n)); // Handle negative numbers and zero
    while (n > SINGLE_DIGIT_LIMIT) {
        // Loop until n is a single-digit number
        n /= BASE_TEN; // Divide by the base (10)
        r++;
    }
    return r;
}

/*
 * Extracts total length value from a tlength string field
 * Parameters:
 *   tlength_str - String containing the tlength field
 * Returns: Extracted length value or -1 on error
 */
int extract_tlength(const char *tlength_str) {
    // Skip "tlength:"
    const char *number_start = tlength_str + SKIP_TLENGTH;
    char *end_ptr = strchr(number_start, ';');
    if (!end_ptr) {
        // If no delimiter found, it's an invalid format
        fprintf(stderr, "Invalid tlength format\n");
        return GENERAL_ERROR;
    }
    // Create a temporary buffer to store the number
    const size_t length = end_ptr - number_start;
    char temp[length + NULL_CHAR_LEN];
    strncpy(temp, number_start, length);
    temp[length] = NULL_CHAR;
    // Convert to integer
    return atoi(temp);
}

/*
 * Validates packet fields and updates corresponding buffers
 * Parameters:
 *   packets_data - Buffer for packet data
 *   packets_type - Buffer for packet types
 *   packets_length - Buffer for packet lengths
 *   packets_length_size - Size of length buffer
 *   packets_data_size - Size of data buffer
 *   packets_type_size - Size of type buffer
 *   packet - Current packet being processed
 * Returns: 0 on success, -1 on failure
 */

int8_t check_command_fields(char *packets_data, char *packets_type, char *packets_length,
                            const size_t packets_length_size, const ssize_t packets_data_size,
                            const size_t packets_type_size, char *packet) {
    const char *type = strtok(packet, ";");
    const char *data_length = strtok(NULL, ";");
    const char *data = strtok(NULL, ";");
    if (type && data_length && data) {
        if (strncmp(type, "type:", TYPE_LEN) == STATUS_OKAY && strncmp(data_length, "length:", LENGTH_LEN)
            == STATUS_OKAY && atoi(data_length + LENGTH_LEN) == strlen(data + DATA_LEN)) {
            if (packets_data_size >= strlen(packets_data) + strlen(data)) {
                strcat(packets_data, data + DATA_LEN);
            }
            if (packets_type_size >= strlen(packets_type) + strlen(type) + NULL_CHAR_LEN) {
                strcat(packets_type, type + TYPE_LEN);
                strcat(packets_type, ";");
            }
            if (packets_length_size >= strlen(packets_length) + strlen(
                    data_length) + NULL_CHAR_LEN) {
                strcat(packets_length, data_length + LENGTH_LEN);
                strcat(packets_length, ";");
            }
        } else {
            fprintf(stderr, "Invalid packet fields\n");
            free(packet);
            return GENERAL_ERROR;
        }
    } else {
        fprintf(stderr, "Failed to parse packet fields\n");
        free(packet);
        return GENERAL_ERROR;
    }
    return STATUS_OKAY;
}

/*
 * Processes a single packet by extracting and validating its fields
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
    char *packets_length, const ssize_t tlength,
    const size_t packets_length_size, const ssize_t packets_data_size,
    const size_t packets_type_size) {
    // Make a copy of the packet for parsing
    const size_t rest_of_length = TLENGTH_LEN + numPlaces(tlength);
    //-9 for tlength: + ; -amount of tlength digits
    char *packet = strndup(packets + rest_of_length, tlength - rest_of_length);
    if (!packet) {
        perror("Failed to allocate memory for buffer");
        return GENERAL_ERROR;
    }
    // Step 3: Parse the fields using the delimiter
    const int8_t check_fields = check_command_fields(
        packets_data, packets_type,
        packets_length, packets_length_size,
        packets_data_size, packets_type_size, packet);
    if (check_fields != GENERAL_ERROR) {
        free(packet);
    }
    return check_fields;
}

/*
* Parses a received network packet stream into its component parts.
* This function processes a string of packets containing type, length,
* and data fields, separating them into their respective buffers.
* Validates packet format and ensures all fields are properly extracted.
* Parameters:
*   received_packets - Raw packet data string to parse
*   packets_data - Buffer to store extracted data fields
*   packets_type - Buffer to store packet type information
*   packets_length - Buffer to store length information
*   packets_size - Total size of received packets
*   packets_length_size - Size of length buffer
*   packets_data_size - Size of data buffer
*   packets_type_size - Size of type buffer
* Returns: 1 if parsing successful, 0 if any error occurs
*/
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
            return false;
        }
        const ssize_t tlength = extract_tlength(tlength_str);
        if (tlength <= TLENGTH_CHECK) {
            printf("tlength is less than zero\n");
            return false;
        }
        if (strlen(current) < tlength) {
            printf("tlength is bigger than current length\n");
            return false;
        }
        const int8_t check = process_packet(current, packets_data, packets_type,
                                            packets_length, tlength,
                                            packets_length_size,
                                            packets_data_size,
                                            packets_type_size);
        if (check == GENERAL_ERROR) {
            return false;
        }
        current += tlength;
        current_length += tlength;
    }
    return current_length == packets_size;
}

/*
* Prepares a network message buffer with formatted data.
* Formats the message with proper protocol fields including total length,
* type, data length, and the data itself. Creates a complete packet
* ready for network transmission.
* Parameters:
*   buffer - Destination buffer for the formatted message
*   buffer_size - Size of the destination buffer
*   data - The actual data to be sent
*   type - Message type identifier (e.g., "OUT", "ERR", "CWD")
* Returns: 1 on success, 0 on failure
*/
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
        return false;
    }
    // Calculate tlength as the length of the formatted message (including "tlength:" part)
    const int message_length = snprintf(NULL, 0,
                                        "tlength:%d;type:%s;length:%d;data:%s",
                                        formatted_length, type, data_length,
                                        data);
    if (message_length >= buffer_size) {
        fprintf(stderr,
                "Buffer too small to store formatted message.\n");
        return false;
    }
    // Format the final message with correct tlength
    const int final_size = snprintf(buffer, buffer_size,
                                    "tlength:%d;type:%s;length:%d;data:%s",
                                    message_length, type, data_length, data);
    if (final_size >= buffer_size) {
        fprintf(stderr,
                "Buffer too small to store formatted message.\n");
        return false;
    }
    snprintf(buffer, buffer_size,
             "tlength:%d;type:%s;length:%d;data:%s",
             final_size, type, data_length, data);
    return true;
}

/*
* Sends data over a socket with a length prefix.
* Implements a reliable sending mechanism by prefixing the data with
* its length as a fixed-width field. Ensures complete transmission
* of the data.
* Parameters:
*   socket - Socket file descriptor
*   data - Data buffer to send
*   data_size - Size of the data to send
* Returns: Number of bytes sent including length prefix, or -1 on error
*/
ssize_t s_send(const int socket, const char *data, const size_t data_size) {
    char length_string[NUM_ZERO + NULL_CHAR_LEN] = {0}; // +1 for null-terminator
    const size_t buf_size = NUM_ZERO + data_size + NULL_CHAR_LEN;
    char buffer[buf_size];
    memset(buffer, NULL_CHAR, buf_size);
    // Generate a zero-padded length string
    snprintf(length_string, sizeof(length_string), "%0*u", NUM_ZERO,
             (unsigned int) data_size);

    // Copy the length string and data into the buffer
    memcpy(buffer, length_string, NUM_ZERO); // Copy the zero-padded length
    memcpy(buffer + NUM_ZERO, data, data_size); // Copy the data

    // Send the buffer (length + data)
    return send(socket, buffer, NUM_ZERO + data_size, RECEIVE_FLAG);
}

/*
 * Receives size field from socket
 * Parameters:
 *   socket - Socket file descriptor
 *   raw_size - Buffer for size data
 * Returns: 0 on success, FINISH_RECEIVE on error
 */
ssize_t receive_raw_size(const int socket, char raw_size[5]) {
    // raw size 4 + 1 null char
    size_t received = 0;
    // Step 1: Receive the size header
    while (received < LENGTH_CHECK) {
        const ssize_t bytes = recv(socket, raw_size + received,
                                   LENGTH_CHECK - received, RECEIVE_FLAG);
        if (bytes <= CHECK_RECEIVE) {
            // Handle errors or connection closure
            return FINISH_RECEIVE;
        }
        received += bytes;
    }
    return STATUS_OKAY;
}

/*
 * Receives data from socket based on size
 * Parameters:
 *   socket - Socket file descriptor
 *   data - Buffer for received data
 *   received_data_size - Expected data size
 *   total_received - Actual bytes received
 * Returns: 0 on success, FINISH_RECEIVE on error
 */
ssize_t receive_raw_data(const int socket, char *data, const size_t received_data_size, size_t *total_received) {
    *total_received = 0;
    while (*total_received < received_data_size) {
        const ssize_t bytes = recv(socket, data + *total_received,
                                   received_data_size - *total_received, RECEIVE_FLAG);
        if (bytes <= CHECK_RECEIVE) {
            // Handle errors or connection closure
            return FINISH_RECEIVE;
        }
        *total_received += bytes;
    }
    return STATUS_OKAY;
}

/*
* Receives data from a socket with length prefix handling.
* Reads a fixed-width length field first, then receives the specified
* amount of data. Implements reliable receiving mechanism with
* proper error checking.
* Parameters:
*   socket - Socket file descriptor
*   data - Buffer to store received data
*   data_size - Maximum size of receive buffer
* Returns: Total bytes received including length prefix, or -1 on error
*/
ssize_t s_recv(const int socket, char *data, const size_t data_size) {
    char raw_size[LENGTH_CHECK + NULL_CHAR_LEN] = {0};
    // Buffer for the size header (+1 for null-terminator)
    const ssize_t raw_size_check = receive_raw_size(socket, raw_size);
    if (raw_size_check == GENERAL_ERROR) {
        return FINISH_RECEIVE;
    }
    char *endptr;
    const size_t received_data_size = strtoul(raw_size, &endptr, BASE_10);
    if (received_data_size == CHECK_RECEIVE || received_data_size > data_size || *endptr != '\0') {
        return GENERAL_ERROR;
    }
    // Step 2: Receive the payload
    size_t total_received;
    const ssize_t raw_data_check = receive_raw_data(socket, data, received_data_size, &total_received);
    if (raw_data_check == GENERAL_ERROR) {
        return FINISH_RECEIVE;
    }
    // Return the total bytes received (header + payload)
    return total_received + LENGTH_CHECK;
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
    return isalnum(c) || c == '.' || c == '-' || c == '_' || c == '/' || c == '~';
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
    if (strncmp(cd_command, "cd ", CD_AND_SPACE_LEN) != 0) {
        return; // Not a cd command, do nothing
    }

    // Find the first invalid character, starting after "cd "
    for (size_t i = CD_AND_SPACE_LEN; i < max_len; i++) {
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
int8_t check_cd(const int sock_fd, const char *command,
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
    if (s_send(sock_fd, cd_buf, strlen(cd_buf)) < 0) {
        perror("s_send failed");
        return GENERAL_ERROR;
    }
    return STATUS_OKAY;
}

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
int check_command_data(const char *data) {
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
