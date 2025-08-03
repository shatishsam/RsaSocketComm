// rsa_utils.h
#ifndef RSA_UTILS_H
#define RSA_UTILS_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>

// Function to generate an RSA key pair
void generate_rsa_key_pair(RSA** public_key, RSA** private_key);

// Function to encrypt a message using a public key
int rsa_encrypt(const char* message, unsigned char* encrypted, RSA* public_key);

// Function to decrypt a message using a private key
int rsa_decrypt(const unsigned char* encrypted, int encrypted_length, unsigned char* decrypted, RSA* private_key);

// Function to convert an RSA public key to PEM format string
std::string rsa_public_key_to_pem(RSA* public_key);

// Function to convert an RSA private key to PEM format string
std::string rsa_private_key_to_pem(RSA* private_key);

#endif // RSA_UTILS_H
