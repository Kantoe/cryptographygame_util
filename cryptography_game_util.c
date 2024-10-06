#include "cryptography_game_util.h"


int createTCPIpv4Socket()
{
    return socket(AF_INET, SOCK_STREAM, SOCKET_FLAG);
}


int createIPv4Address(const char *ip, const int port, struct sockaddr_in *address)
{
    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    if(strlen(ip) == NO_IP)
        address->sin_addr.s_addr = INADDR_ANY;
    else
        return inet_pton(AF_INET,ip , &address->sin_addr.s_addr);
    return PORT_RANGE_MIN < port && port <= PORT_RANGE_MAX;
}