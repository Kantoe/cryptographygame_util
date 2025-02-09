#include <openssl/evp.h>
#include <openssl/pem.h>
#include "key_exchange.h"
#include "cryptography_game_util.h"

#define DH_MAX_SHARED_SECRET_LEN 128

typedef struct {
    EVP_PKEY *key;
    EVP_PKEY_CTX *ctx;
} DiffieHellman;

DiffieHellman *create_dh() {
    DiffieHellman *dh = malloc(sizeof(DiffieHellman));
    if (!dh) return NULL;
    dh->key = NULL;
    dh->ctx = NULL;
    // Create context for key generation
    dh->ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!dh->ctx) {
        free(dh);
        return NULL;
    }
    // Initialize key generation
    if (EVP_PKEY_keygen_init(dh->ctx) <= 0) {
        EVP_PKEY_CTX_free(dh->ctx);
        free(dh);
        return NULL;
    }
    // Set the curve to secp384r1
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(dh->ctx, NID_secp384r1) <= 0) {
        EVP_PKEY_CTX_free(dh->ctx);
        free(dh);
        return NULL;
    }
    // Generate the key pair
    if (EVP_PKEY_generate(dh->ctx, &dh->key) <= 0) {
        EVP_PKEY_CTX_free(dh->ctx);
        free(dh);
        return NULL;
    }
    return dh;
}

// Free Diffie-Hellman context
void free_dh(DiffieHellman *dh) {
    if (dh) {
        EVP_PKEY_free(dh->key);
        EVP_PKEY_CTX_free(dh->ctx);
        free(dh);
    }
}

// Serialize public key to PEM format
char *serialize_public_key(const DiffieHellman *dh, size_t *len) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return NULL;
    if (!PEM_write_bio_PUBKEY(bio, dh->key)) {
        BIO_free(bio);
        return NULL;
    }
    *len = BIO_pending(bio);
    char *pem = malloc(*len + 1);
    if (!pem) {
        BIO_free(bio);
        return NULL;
    }
    BIO_read(bio, pem, *len);
    pem[*len] = '\0';
    BIO_free(bio);
    return pem;
}

// Deserialize public key from PEM format
EVP_PKEY *deserialize_public_key(const char *pem_data, const size_t len) {
    BIO *bio = BIO_new_mem_buf(pem_data, len);
    if (!bio) return NULL;
    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return key;
}

// Derive key using modern EVP interface
static unsigned char *derive_key(EVP_PKEY *private_key, EVP_PKEY *peer_key,
                                 size_t *key_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx) return NULL;
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    size_t secret_len;
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    unsigned char *secret = malloc(secret_len);
    if (!secret) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_derive(ctx, secret, &secret_len) <= 0) {
        free(secret);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    // Create digest context for key derivation
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        free(secret);
        return NULL;
    }
    if (!EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(md_ctx, secret, secret_len) ||
        !EVP_DigestUpdate(md_ctx, "DH-KEY-DERIVATION", 16)) {
        free(secret);
        EVP_MD_CTX_free(md_ctx);
        return NULL;
    }
    unsigned char *derived_key = malloc(32); // SHA256 output size
    if (!derived_key) {
        free(secret);
        EVP_MD_CTX_free(md_ctx);
        return NULL;
    }
    unsigned int derived_len;
    if (!EVP_DigestFinal_ex(md_ctx, derived_key, &derived_len)) {
        free(secret);
        free(derived_key);
        EVP_MD_CTX_free(md_ctx);
        return NULL;
    }
    free(secret);
    EVP_MD_CTX_free(md_ctx);
    *key_len = derived_len;
    return derived_key;
}

// Client-side key exchange
unsigned char *send_recv_key(const int socket, size_t *key_len) {
    DiffieHellman *dh = create_dh();
    if (!dh) return NULL;
    // Send our public key
    size_t pub_len;
    char *pub_pem = serialize_public_key(dh, &pub_len);
    if (!pub_pem) {
        free_dh(dh);
        return NULL;
    }
    if (s_send(socket, NULL, pub_pem, pub_len) < 0) {
        free(pub_pem);
        free_dh(dh);
        return NULL;
    }
    free(pub_pem);
    // Receive peer's public key
    char peer_pem[4096];
    const ssize_t received = s_recv(socket, peer_pem, sizeof(peer_pem), NULL);
    if (received < 0) {
        free_dh(dh);
        return NULL;
    }
    // Deserialize peer's key and generate shared key
    EVP_PKEY *peer_key = deserialize_public_key(peer_pem, received);
    if (!peer_key) {
        free_dh(dh);
        return NULL;
    }
    unsigned char *key = derive_key(dh->key, peer_key, key_len);
    EVP_PKEY_free(peer_key);
    free_dh(dh);
    return key;
}

// Server-side key exchange
unsigned char *recv_send_key(const int socket, size_t *key_len) {
    // Receive client's public key
    char client_pem[4096];
    const ssize_t received = s_recv(socket, client_pem, sizeof(client_pem), NULL);
    if (received < 0) return NULL;
    // Create our DH context
    DiffieHellman *dh = create_dh();
    if (!dh) return NULL;
    // Deserialize client's key
    EVP_PKEY *client_key = deserialize_public_key(client_pem, received);
    if (!client_key) {
        free_dh(dh);
        return NULL;
    }
    // Send our public key
    size_t pub_len;
    char *pub_pem = serialize_public_key(dh, &pub_len);
    if (!pub_pem) {
        EVP_PKEY_free(client_key);
        free_dh(dh);
        return NULL;
    }
    if (s_send(socket, NULL, pub_pem, pub_len) < 0) {
        free(pub_pem);
        EVP_PKEY_free(client_key);
        free_dh(dh);
        return NULL;
    }
    free(pub_pem);
    // Generate shared key
    unsigned char *key = derive_key(dh->key, client_key, key_len);
    EVP_PKEY_free(client_key);
    free_dh(dh);
    return key;
}
