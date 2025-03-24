#ifndef ENCRYPT_DECRYPT_H_INCLUDED
#define ENCRYPT_DECRYPT_H_INCLUDED

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>

#define ENC_DEC_stddbg stderr   // standard debbug output
#define ENC_DEC_ERR_MSG_LEN 1024  // max error message length
#define ENC_DEC_FILE_PATH_LEN 1024  // max length of the file path

#define ENC_DEC_CHUNK_SIZE 1024    // size of the chunks to be read from the file when enrypting/decrypting

#define FILE_PATH_LEN 1024  // max length of the file path

/*
initliazes the program

@param dir_name name for session directory, NULL for default
@return exit code
*/
int init_encrypt_decrypt(char *dir_name);

// AES encryptions

/*
encrypts the file located at input_filepath and saves to output_path

@param input_filepath string which holds the location of the file you want to encrypt
@param output_filepath string which holds the directory where you want the encrypted file to be saved
@param key string which holds the key used for encryption
@param iv string which holds the initialization vector used for encryption
@param tag string which will be the output of the authentication tag
@return exit code OR ciphertext len
*/
int encrypt_file_aes_gcm(char *input_filepath, char *output_filepath, const unsigned char *key, const unsigned char *iv, char *tag);

/*
decrypts the file located at input_filepath and saves to output_path

@param input_filepath string which holds the location of the file you want to encrypt
@param output_filepath string which holds the directory where you want the encrypted file to be saved
@param key string which holds the key used for encryption
@param iv string which holds the initialization vector used for encryption
@param tag string which will be the input of the authentication tag
@return exit code OR plaintext len
*/
int decrypt_file_aes_gcm(char *input_filepath, char *output_filepath, const unsigned char *key, const unsigned char *iv, char *tag);

// RSA encryptions

/*
genereates a RSA key

@param bits key size in bits (2048, 4096, etc)
@return generated key struct
*/
EVP_PKEY* generate_key_rsa(int bits);

/*
gets pem encoded public key from a key struct

@param pkey EVP_PKEY* struct
@return pem encoded public key
*/
char* get_pem_from_pkey(EVP_PKEY *pkey);

/*
gets pkey struct from a pem encoded public key (it will only hold the public key not a private key)

@param public_key pem encoded public key
@return EVP_PKEY* struct
*/
EVP_PKEY* get_pkey_from_pem(const char *public_key);

/*
encrypts a string using RSA encryption and a public key

@param plaintext binary to be encrypted
@param plaintext_len length of the plaintext
@param public_key pem encoded public key
@param ciphertext buffer to store the encrypted binary
@return ciphertext length
*/
int encrpy_string_rsa(const unsigned char *plaintext, const size_t plaintext_len, const char *public_key, unsigned char *ciphertext);

/*
decrypts a string using RSA encryption and a private key

@param ciphertext binary to be decrypted
@param ciphertext_len length of the ciphertext
@param private_key EVP_PKEY* struct private key
@param plaintext buffer to store the decrypted binary
@return plaintext length
*/
int decrypt_string_rsa(const unsigned char *ciphertext, const size_t ciphertext_len, EVP_PKEY *private_key, unsigned char *plaintext);

#endif  // ENCRYPT_DECRYPT_H_INCLUDED