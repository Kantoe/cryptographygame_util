/*
* Ido Kantor
* methods used in code for cryptography_game
 */
#ifndef CRYPTOGRAPHY_GAME_UTIL_H
#define CRYPTOGRAPHY_GAME_UTIL_H
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

/* Buffer size constants */
#define BUFFER_SIZE_CMD_MAX 500
#define BUFFER_SIZE_FULL_CMD 512
#define BUFFER_SIZE_OUTPUT 1024
#define BUFFER_SIZE_SEND 2048
#define BUFFER_SIZE_CD 256
#define ERR_BUFFER_SIZE 256

/* Message processing constants */
#define FINISH_RECEIVE -1
#define TLENGTH_LEN 9
#define BASE_10 10
#define LENGTH_CHECK 4
#define NUM_ZERO 4
#define EMPTY_DATA "tlength:34;type:OUT;length:0;data:"

/* Constants for socket configuration */
#define SOCKET_FLAG 0
#define NO_IP 0
#define PORT_RANGE_MIN 0
#define PORT_RANGE_MAX 65535
#define CHECK_IP 0

/* Constants for errors */
#define PIPE_ERR_CHECK 0
#define GENERAL_ERROR -1
#define STATUS_OKAY 0

#define PIPE_OUT 1
#define PIPE_ERR 0

/* Creates a TCP IPv4 socket.
 * Returns: The file descriptor for the created socket, or -1 on failure.
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
    const char *received_packets, char *packets_data, char *packets_type, char *packets_length,
    size_t packets_size, size_t packets_length_size, ssize_t packets_data_size,
    size_t packets_type_size);

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
int8_t prepare_buffer(char *buffer, size_t buffer_size, const char *data, const char *type);

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
ssize_t s_send(int socket, const char *data, size_t data_size);

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
ssize_t s_recv(int socket, char *data, size_t data_size);

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

#endif
