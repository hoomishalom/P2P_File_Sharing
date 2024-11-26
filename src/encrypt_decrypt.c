#include "../headers/main_headers.h"
#include "../headers/encrypt_decrypt.h"

#define errMsgLen 1024  // max error message length
#define CHUNK_SIZE 1024

char errMsg[errMsgLen]; // buffer for error messages

extern int errno;       // error number from <errno.h>

int encrypt_file_aes_gcm(const char *input_filepath, const char *output_filepath, const char *key, const char *iv, char *tag) 
{
    FILE *input_file = fopen(input_filepath, "rb");
    FILE *output_file = fopen(output_filepath, "rb");

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
        snprintf(errMsg, errMsgLen, "encrypt_file_aes_gcm - Error creating new ctx: %s\n", strerror(errno));
        return -1;
    }

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) == 0) // initializing encryption
    {
        snprintf(errMsg, errMsgLen, "encrypt_file_aes_gcm - Error initializing encryption: %s\n", strerror(errno));
        return -2;
    }

    while((temp_len = fread(buffer, 1, CHUNK_SIZE, input_file)) > 0)  // raeding each block of the input file
    {
        if(EVP_EncryptUpdate(ctx, temp_ciphertext, &temp_len, buffer, temp_len) != 1)   // encrypts block and checks for errors
        {
            snprintf(errMsg, errMsgLen, "encrypt_file_aes_gcm - Error encrypting data: %s\n", strerror(errno));
            return -3;
        }
        fwrite(temp_ciphertext, 1, temp_len, output_file);  // writes the encrypted block to the output file
        ciphertext_len += temp_len; // adds block's length to the total length
    }

    if(EVP_EncryptFinal_ex(ctx, temp_ciphertext, &temp_len) != 1)   // finalizes encryption and checks for errors
    {
        snprintf(errMsg, errMsgLen, "encrypt_file_aes_gcm - Error finalizing encryption: %s\n", strerror(errno));
        return -4;
    }
    fwrite(temp_ciphertext, 1, temp_len, output_file);  // writes the final encrypted block to the output

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)    // gets authentication tag
    {
        snprintf(errMsg, errMsgLen, "encrypt_file_aes_gcm - Error getting authentication tag: %s\n", strerror(errno));
        return -5;
    }

    EVP_CIPHER_CTX_free(ctx);   // frees the ctx
    fclose(input_file); // closes the input file
    fclose(output_file);    // closes the output file
}