/*
* Ido Kantor
* methods used in code for the game
 */
#ifndef CRYPTOGRAPHY_GAME_UTIL_H
#define CRYPTOGRAPHY_GAME_UTIL_H
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#define SOCKET_FLAG 0
#define NO_IP 0
#define PORT_RANGE_MIN 0
#define PORT_RANGE_MAX 65535
#define CHECK_IP 0

/* Creates a TCP IPv4 socket.
 * Returns: The file descriptor for the created socket, or -1 on failure.
 */

int createIPv4Address(const char *ip, int port, struct sockaddr_in *address);

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

int createTCPIpv4Socket();


#endif