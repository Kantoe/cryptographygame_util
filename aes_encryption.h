#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

char *aes_encrypt(const unsigned char *key, const unsigned char *data, size_t data_len, size_t *output_len);

unsigned char *aes_decrypt(const unsigned char *key, const char *encrypted_data,
                           size_t encrypted_len, size_t *output_len);
#endif //AES_ENCRYPTION_H
