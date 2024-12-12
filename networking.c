#include "networking.h"

//prototypes

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
