#ifndef NETWORKING_H
#define NETWORKING_H
#include "cryptography_game_util.h"

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

#endif //NETWORKING_H
