#include "../headers/main_headers.h"
#include "../headers/encrypt_decrypt.h"

#ifndef ERR_MSG_LEN
#define ERR_MSG_LEN 1024
#endif

#define CHUNK_SIZE 1024

char err_msg[ERR_MSG_LEN]; // buffer for error messages

extern int errno;       // error number from <errno.h>


// AES-GCM encryptions/decryption functions

int encrypt_file_aes_gcm(const char *input_filepath, const char *output_filepath, const char *key, const char *iv, char *tag) 
{
    FILE *input_file = fopen(input_filepath, "rb");
    FILE *output_file = fopen(output_filepath, "wb");

    if(input_file == NULL || output_file == NULL) 
    {
        perror("File open error");
        return -1;
    }

    EVP_CIPHER_CTX *ctx;
    int temp_len;   // used to store the length of the current encrypted block
    int ciphertext_len = 0; // used to return the final length of the cipher text
    unsigned char buffer[CHUNK_SIZE];
    unsigned char temp_ciphertext[CHUNK_SIZE + 16]; // CHUNK_SIZE + AES_CHUNK_SIZE (16) 

    if((ctx = EVP_CIPHER_CTX_new()) == NULL) // creating new ctx for ecryption
    {
        snprintf(err_msg, ERR_MSG_LEN, "encrypt_file_aes_gcm - Error creating new ctx: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        EVP_CIPHER_CTX_free(ctx);   // frees the ctx
        return -2;
    }

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) == 0) // initializing encryption
    {
        snprintf(err_msg, ERR_MSG_LEN, "encrypt_file_aes_gcm - Error initializing encryption: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        EVP_CIPHER_CTX_free(ctx);   // frees the ctx
        return -3;
    }

    while((temp_len = fread(buffer, 1, CHUNK_SIZE, input_file)) > 0)  // raeding each block of the input file
    {
        if(EVP_EncryptUpdate(ctx, temp_ciphertext, &temp_len, buffer, temp_len) != 1)   // encrypts block and checks for errors
        {
            snprintf(err_msg, ERR_MSG_LEN, "encrypt_file_aes_gcm - Error encrypting data: %s\n", strerror(errno));
            fprintf(stddbg, err_msg);
            EVP_CIPHER_CTX_free(ctx);   // frees the ctx
            return -4;
        }
        fwrite(temp_ciphertext, 1, temp_len, output_file);  // writes the encrypted block to the output file
        ciphertext_len += temp_len; // adds block's length to the total length
    }

    if(EVP_EncryptFinal_ex(ctx, temp_ciphertext, &temp_len) != 1)   // finalizes encryption and checks for errors
    {
        snprintf(err_msg, ERR_MSG_LEN, "encrypt_file_aes_gcm - Error finalizing encryption: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        EVP_CIPHER_CTX_free(ctx);   // frees the ctx
        return -5;
    }
    fwrite(temp_ciphertext, 1, temp_len, output_file);  // writes the final encrypted block to the output

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)    // gets authentication tag
    {
        snprintf(err_msg, ERR_MSG_LEN, "encrypt_file_aes_gcm - Error getting authentication tag: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        EVP_CIPHER_CTX_free(ctx);   // frees the ctx
        return -6;
    }

    EVP_CIPHER_CTX_free(ctx);   // frees the ctx
    fclose(input_file); // closes the input file
    fclose(output_file);    // closes the output file

    return ciphertext_len;
}


int decrypt_file_aes_gcm(const char *input_filepath, const char *output_filepath, const char *key, const char *iv, char *tag) 
{
    FILE *input_file = fopen(input_filepath, "rb");
    FILE *output_file = fopen(output_filepath, "wb");

    if(input_file == NULL || output_file == NULL) 
    {
        perror("File open error");
        return -1;
    }

    EVP_CIPHER_CTX *ctx;
    int temp_len;   // used to store the length of the current decrypted block
    int plaintext_len = 0; // used to return the final length of the  plaintext
    unsigned char buffer[CHUNK_SIZE];
    unsigned char temp_plaintext[CHUNK_SIZE]; // CHUNK_SIZE 

    if((ctx = EVP_CIPHER_CTX_new()) == NULL) // creating new ctx for ecryption
    {
        snprintf(err_msg, ERR_MSG_LEN, "decrypt_file_aes_gcm - Error creating new ctx: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        return -2;
    }

    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) == 0) // initializing decryption
    {
        snprintf(err_msg, ERR_MSG_LEN, "decrypt_file_aes_gcm - Error initializing decryption: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        EVP_CIPHER_CTX_free(ctx);   // frees the ctx
        return -3;
    }

    while((temp_len = fread(buffer, 1, CHUNK_SIZE, input_file)) > 0)  // raeding each block of the input file
    {
        if(EVP_DecryptUpdate(ctx, temp_plaintext, &temp_len, buffer, temp_len) != 1)   // decrypts block and checks for errors
        {
            snprintf(err_msg, ERR_MSG_LEN, "decrypt_file_aes_gcm - Error decrypting data: %s\n", strerror(errno));
            fprintf(stddbg, err_msg);
            EVP_CIPHER_CTX_free(ctx);   // frees the ctx
            return -4;
        }
        fwrite(temp_plaintext, 1, temp_len, output_file);  // writes the decrypted block to the output file
        plaintext_len += temp_len; // adds block's length to the total length
    }

    if(EVP_DecryptFinal_ex(ctx, temp_plaintext, &temp_len) != 1)   // finalizes decryption and checks for errors
    {
        snprintf(err_msg, ERR_MSG_LEN, "decrypt_file_aes_gcm - Error finalizing decryption: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        EVP_CIPHER_CTX_free(ctx);   // frees the ctx
        return -5;
    }
    fwrite(temp_plaintext, 1, temp_len, output_file);  // writes the final decrypted block to the output

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1)    // set authentication tag
    {
        snprintf(err_msg, ERR_MSG_LEN, "decrypt_file_aes_gcm - Authentication failed: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        EVP_CIPHER_CTX_free(ctx);   // frees the ctx
        return -6;
    }

    EVP_CIPHER_CTX_free(ctx);   // frees the ctx
    fclose(input_file); // closes the input file
    fclose(output_file);    // closes the output file

    return plaintext_len; 
}


// RSA encryptions/decryption functions

int generate_key_rsa(RSA *rsa, int bits)   // RSA *rsa should be a pointer to a none initialized RSA struct
{
    BIGNUM *big_num = NULL;    // BIGNUM structure
    unsigned long exponent = RSA_F4; // public exponent
    
    
    big_num = BN_new(); // creates new BIGNUM structure
    if(BN_set_word(big_num, exponent) != 1) // sets the big_num to the exponent
    {
        sprintf(err_msg, ERR_MSG_LEN, "generate_key_rsa - Error setting big_num: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        BN_free(big_num);  // frees the BIGNUM structure
        return -1;
    }

    rsa = RSA_new();    // creates new RSA structure
    if(RSA_generate_key_ex(rsa, bits, big_num, NULL) != 1) // generates RSA key
    {
        sprintf(err_msg, ERR_MSG_LEN, "generate_key_rsa - Error generating RSA key: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        RSA_free(rsa);  // frees the RSA structure
        BN_free(big_num);  // frees the BIGNUM structure
        return -2;
    }

    RSA_free(rsa);  // frees the RSA structure
    BN_free(big_num);  // frees the BIGNUM structure
    return 0;
}


int get_public_key_from_der(RSA *rsa, unsigned char *public_key)
{
    int len = i2d_RSAPublicKey(rsa, &public_key);   // extracts publick key from rsa
    if(len == -1)
    {
        sprintf(err_msg, ERR_MSG_LEN, "get_public_key_der - Error getting public key: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        return -1;
    }

    return len;
}


int get_rsa_from_public_key(const unsigned char *der, unsigned int der_len, RSA **rsa)
{
    d2i_RSAPublicKey(rsa, &der, der_len);    // loads public key from der into *rsa
    if(rsa == NULL)
    {
        sprintf(err_msg, ERR_MSG_LEN, "load_rsa_public_key_der - Error loading public key: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        return -1;
    }

    return 0;
}


int encrypt_string_rsa(const char *plaintext, const char *public_key, size_t public_key_len, unsigned char *ciphertext)
{
    RSA *rsa = NULL;   // RSA structure
    int ciphertext_len; // length of the encrypted text   

    if(get_rsa_from_public_key(public_key, public_key_len, &rsa) < 0)    // loads public key from der into *rsa    
    {
        sprintf(err_msg, ERR_MSG_LEN, "encrypt_string_rsa - Error loading public key: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        return -1;
    }

    // encrypt the plaintext
    ciphertext_len = RSA_public_encrypt(strlen(plaintext), plaintext, ciphertext, rsa, RSA_PKCS1_OAEP_PADDING);
    if(ciphertext_len == -1)    // checks for errors
    {
        sprintf(err_msg, ERR_MSG_LEN, "encrypt_string_rsa - Error encrypting data: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        RSA_free(rsa);  // frees the RSA structure
        return -2;
    }

    RSA_free(rsa);  // frees the RSA structure
    return ciphertext_len;
}


int decrypt_string_rsa(const unsigned char *ciphertext, size_t ciphertext_len, RSA *rsa, char *plaintext)
{
    int plaintext_len;
    if (plaintext_len = RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, rsa, RSA_PKCS1_OAEP_PADDING) == -1) {
        sprintf(err_msg, ERR_MSG_LEN, "decrypt_string_rsa - Error decrypting data: %s\n", strerror(errno));
        fprintf(stddbg, err_msg);
        return -1;
    }

    plaintext[plaintext_len] = '\0';    // null-terminates the decrypted string
    return plaintext_len;
}