#ifndef KEY_EXCHANGE_H
#define KEY_EXCHANGE_H

unsigned char *send_recv_key(int socket, size_t *key_len);

unsigned char *recv_send_key(int socket, size_t *key_len);

#endif
