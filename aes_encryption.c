#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/buffer.h>
#include "cryptography_game_util.h"
#include "aes_encryption.h"

#define AES_BLOCK_SIZE 16
#define BASE64_ENCODE_LEN(n) (((n + 2) / 3) * 4 + 1)
#define BASE64_DECODE_LEN(n) (((n + 3) / 4) * 3)

// Base64 encoding/decoding functions
static char *base64_encode(const unsigned char *input, const size_t length, size_t *output_len) {
    BUF_MEM *bufferPtr;
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    char *output = malloc(bufferPtr->length + 1);
    if (!output) {
        BIO_free_all(bio);
        return NULL;
    }
    memcpy(output, bufferPtr->data, bufferPtr->length);
    output[bufferPtr->length] = '\0';
    *output_len = bufferPtr->length;
    BIO_free_all(bio);
    return output;
}

static unsigned char *base64_decode(const char *input, const size_t length, size_t *output_len) {
    // Calculate maximum possible decoded length
    const size_t max_decode_len = BASE64_DECODE_LEN(length);
    unsigned char *output = malloc(max_decode_len);
    if (!output) return NULL;
    // Create BIOs with proper error checking
    BIO *bio = BIO_new_mem_buf(input, length); // Note: explicitly passing length
    if (!bio) {
        free(output);
        return NULL;
    }
    BIO *b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        BIO_free(bio);
        free(output);
        return NULL;
    }
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    // Read with proper error handling
    const int read_len = BIO_read(bio, output, length);
    if (read_len <= 0) {
        BIO_free_all(bio);
        free(output);
        return NULL;
    }
    *output_len = read_len;
    BIO_free_all(bio);
    return output;
}

// PKCS7 padding functions
static unsigned char *pad_data(const unsigned char *data, const size_t len, size_t *padded_len) {
    const size_t padding_len = AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE);
    *padded_len = len + padding_len;
    unsigned char *padded = malloc(*padded_len);
    if (!padded) return NULL;
    memcpy(padded, data, len);
    memset(padded + len, padding_len, padding_len);
    return padded;
}

static unsigned char *unpad_data(const unsigned char *data, const size_t len, size_t *unpadded_len) {
    if (len == 0) return NULL;
    const unsigned char padding_len = data[len - 1];
    if (padding_len > AES_BLOCK_SIZE || padding_len > len) return NULL;
    *unpadded_len = len - padding_len;
    unsigned char *unpadded = malloc(*unpadded_len);
    if (!unpadded) return NULL;
    memcpy(unpadded, data, *unpadded_len);
    return unpadded;
}

// Main encryption function
char *aes_encrypt(const unsigned char *key, const unsigned char *data, const size_t data_len, size_t *output_len) {
    // Generate IV
    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) return NULL;
    // Create and initialize the context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    // Pad the input data
    size_t padded_len;
    unsigned char *padded_data = pad_data(data, data_len, &padded_len);
    if (!padded_data) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    // Initialize encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        free(padded_data);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    // Prepare the output buffer (IV + encrypted data)
    const size_t max_cipher_len = padded_len + EVP_MAX_BLOCK_LENGTH;
    unsigned char *cipher_with_iv = malloc(AES_BLOCK_SIZE + max_cipher_len);
    if (!cipher_with_iv) {
        free(padded_data);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    // Copy IV to the beginning of output
    memcpy(cipher_with_iv, iv, AES_BLOCK_SIZE);
    // Perform encryption
    int cipher_len;
    if (EVP_EncryptUpdate(ctx, cipher_with_iv + AES_BLOCK_SIZE, &cipher_len,
                          padded_data, padded_len) != 1) {
        free(padded_data);
        free(cipher_with_iv);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, cipher_with_iv + AES_BLOCK_SIZE + cipher_len,
                            &final_len) != 1) {
        free(padded_data);
        free(cipher_with_iv);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    const size_t total_len = AES_BLOCK_SIZE + cipher_len + final_len;
    char *base64_output = base64_encode(cipher_with_iv, total_len, output_len);
    // Clean up
    free(padded_data);
    free(cipher_with_iv);
    EVP_CIPHER_CTX_free(ctx);
    return base64_output;
}

// Main decryption function
unsigned char *aes_decrypt(const unsigned char *key, const char *encrypted_data,
                           const size_t encrypted_len, size_t *output_len) {
    // Decode base64
    size_t decoded_len;
    unsigned char *decoded = base64_decode(encrypted_data, encrypted_len, &decoded_len);
    if (!decoded || decoded_len <= AES_BLOCK_SIZE) {
        perror("base64_decode");
        return NULL;
    }
    // Extract IV
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, decoded, AES_BLOCK_SIZE);
    // Create and initialize the context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("EVP_CIPHER_CTX_new");
        free(decoded);
        return NULL;
    }
    // Initialize decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        perror("EVP_DecryptInit_ex");
        free(decoded);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    // Prepare output buffer
    unsigned char *decrypted = malloc(decoded_len - AES_BLOCK_SIZE);
    if (!decrypted) {
        perror("malloc");
        free(decoded);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    // Perform decryption
    int decrypt_len;
    if (EVP_DecryptUpdate(ctx, decrypted, &decrypt_len,
                          decoded + AES_BLOCK_SIZE,
                          decoded_len - AES_BLOCK_SIZE) != 1) {
        perror("EVP_DecryptUpdate");
        free(decoded);
        free(decrypted);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, decrypted + decrypt_len, &final_len) != 1) {
        perror("EVP_DecryptFinal_ex");
        free(decoded);
        free(decrypted);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    // Unpad the decrypted data
    size_t unpadded_len;
    unsigned char *unpadded = unpad_data(decrypted, decrypt_len + final_len, &unpadded_len);
    if (!unpadded) {
        perror("unpad_data");
    }
    // Clean up
    free(decoded);
    free(decrypted);
    EVP_CIPHER_CTX_free(ctx);
    *output_len = unpadded_len;
    return unpadded;
}
