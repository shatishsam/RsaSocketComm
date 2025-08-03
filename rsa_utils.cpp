// rsa_utils.cpp
#include "rsa_utils.h"
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Function to generate an RSA key pair
void generate_rsa_key_pair(RSA** public_key, RSA** private_key) {
    // Generate RSA keys with 2048-bit size
    *private_key = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    if (*private_key == nullptr) {
        std::cerr << "RSA key generation failed!" << std::endl;
        exit(1);
    }
    *public_key = RSAPublicKey_dup(*private_key);  // Get public key from private key
    if (*public_key == nullptr) {
        std::cerr << "Failed to extract public key!" << std::endl;
        exit(1);
    }
}
// Function to encrypt a message using a public key
int rsa_encrypt(const char* message, unsigned char* encrypted, RSA* public_key) {
    int encrypted_length = RSA_public_encrypt(strlen(message), (unsigned char*)message, encrypted, public_key, RSA_PKCS1_OAEP_PADDING);
    if (encrypted_length == -1) {
        std::cerr << "Encryption failed!" << std::endl;
        exit(1);
    }
    return encrypted_length;
}

// Function to decrypt a message using a private key
int rsa_decrypt(const unsigned char* encrypted, int encrypted_length, unsigned char* decrypted, RSA* private_key) {
    int decrypted_length = RSA_private_decrypt(encrypted_length, encrypted, decrypted, private_key, RSA_PKCS1_OAEP_PADDING);
    if (decrypted_length == -1) {
        std::cerr << "Decryption failed!" << std::endl;
        exit(1);
    }
    return decrypted_length;
}

// Function to convert an RSA public key to PEM format string
std::string rsa_public_key_to_pem(RSA* public_key) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, public_key);
    char* pem_data;
    long pem_length = BIO_get_mem_data(bio, &pem_data);
    std::string pem_string(pem_data, pem_length);
    BIO_free(bio);
    return pem_string;
}

// Function to convert an RSA private key to PEM format string
std::string rsa_private_key_to_pem(RSA* private_key) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, private_key, nullptr, nullptr, 0, nullptr, nullptr);
    char* pem_data;
    long pem_length = BIO_get_mem_data(bio, &pem_data);
    std::string pem_string(pem_data, pem_length);
    BIO_free(bio);
    return pem_string;
}