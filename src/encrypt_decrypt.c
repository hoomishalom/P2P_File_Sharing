#include "../headers/encrypt_decrypt.h"

extern int errno;       // error number from <errno.h>

char err_msg[ENC_DEC_ERR_MSG_LEN]; // buffer for error messages

// Helper functions

static void handle_errors(const char *msg, const char *format)
{
    snprintf(err_msg, ENC_DEC_ERR_MSG_LEN, "%s: %s\n", msg, format);
    fprintf(ENC_DEC_stddbg, err_msg);
}

// AES-GCM encryptions/decryption functions

int encrypt_file_aes_gcm(char *input_filepath, char *output_filepath, const char *key, const char *iv, char *tag) 
{
    char *file_name = basename(input_filepath); // gets the file name from the input file path
    char file_path_name_buffer[ENC_DEC_FILE_PATH_LEN];   // buffer to combine output_filepath and file_name
    strcat(file_path_name_buffer, output_filepath);
    strcat(file_path_name_buffer, file_name);

    FILE *input_file = fopen(input_filepath, "rb");
    FILE *output_file = fopen(output_filepath, "wb");

    if(input_file == NULL || output_file == NULL) 
    {
        handle_errors("encrypt_file_aes_gcm - Error openning files", strerror(errno));
        return -1;
    }

    EVP_CIPHER_CTX *ctx;
    int temp_len;   // used to store the length of the current encrypted block
    int ciphertext_len = 0; // used to return the final length of the cipher text
    unsigned char buffer[ENC_DEC_CHUNK_SIZE];
    unsigned char temp_ciphertext[ENC_DEC_CHUNK_SIZE + 16]; // ENC_DEC_CHUNK_SIZE + AES_ENC_DEC_CHUNK_SIZE (16) 

    if((ctx = EVP_CIPHER_CTX_new()) == NULL) // creating new ctx for ecryption
    {
        handle_errors("encrypt_file_aes_gcm - Error creating new ctx", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);   // frees the ctx
        return -2;
    }

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) == 0) // initializing encryption
    {   
        handle_errors("encrypt_file_aes_gcm - Error initializing encryption", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);   // frees the ctx
        return -3;
    }

    while((temp_len = fread(buffer, 1, ENC_DEC_CHUNK_SIZE, input_file)) > 0)  // raeding each block of the input file
    {
        if(EVP_EncryptUpdate(ctx, temp_ciphertext, &temp_len, buffer, temp_len) != 1)   // encrypts block and checks for errors
        {
            handle_errors("encrypt_file_aes_gcm - Error encrypting data", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);   // frees the ctx
            return -4;
        }
        fwrite(temp_ciphertext, 1, temp_len, output_file);  // writes the encrypted block to the output file
        ciphertext_len += temp_len; // adds block's length to the total length
    }

    if(EVP_EncryptFinal_ex(ctx, temp_ciphertext, &temp_len) != 1)   // finalizes encryption and checks for errors
    {   
        handle_errors("encrypt_file_aes_gcm - Error finalizing encryption", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);   // frees the ctx
        return -5;
    }
    fwrite(temp_ciphertext, 1, temp_len, output_file);  // writes the final encrypted block to the output

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)    // gets authentication tag
    {
        handle_errors("encrypt_file_aes_gcm - Error getting authentication tag", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);   // frees the ctx
        return -6;
    }

    EVP_CIPHER_CTX_free(ctx);   // frees the ctx
    fclose(input_file); // closes the input file
    fclose(output_file);    // closes the output file

    return ciphertext_len;
}


int decrypt_file_aes_gcm(char *input_filepath, char *output_filepath, const char *key, const char *iv, char *tag) 
{
    const char *file_name = basename(input_filepath); // gets the file name from the input file path
    char file_path_name_buffer[ENC_DEC_FILE_PATH_LEN];   // buffer to combine output_filepath and file_name
    strcat(file_path_name_buffer, output_filepath);
    strcat(file_path_name_buffer, file_name);

    FILE *input_file = fopen(input_filepath, "rb");
    FILE *output_file = fopen(file_path_name_buffer, "wb");

    if(input_file == NULL || output_file == NULL) 
    {
        handle_errors("decrypt_file_aes_gcm - Error openning files", strerror(errno));
        return -1;
    }

    EVP_CIPHER_CTX *ctx;
    int temp_len;   // used to store the length of the current decrypted block
    int plaintext_len = 0; // used to return the final length of the  plaintext
    unsigned char buffer[ENC_DEC_CHUNK_SIZE];
    unsigned char temp_plaintext[ENC_DEC_CHUNK_SIZE]; // ENC_DEC_CHUNK_SIZE 

    if((ctx = EVP_CIPHER_CTX_new()) == NULL) // creating new ctx for ecryption
    {
        handle_errors("decrypt_file_aes_gcm - Error creating new ctx", ERR_error_string(ERR_get_error(), NULL));
        return -2;
    }

    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) == 0) // initializing decryption
    {
        handle_errors("decrypt_file_aes_gcm - Error initializing decryption", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);   // frees the ctx
        return -3;
    }

    while((temp_len = fread(buffer, 1, ENC_DEC_CHUNK_SIZE, input_file)) > 0)  // raeding each block of the input file
    {
        if(EVP_DecryptUpdate(ctx, temp_plaintext, &temp_len, buffer, temp_len) != 1)   // decrypts block and checks for errors
        {
            handle_errors("decrypt_file_aes_gcm - Error decrypting data", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_free(ctx);   // frees the ctx
            return -4;
        }
        fwrite(temp_plaintext, 1, temp_len, output_file);  // writes the decrypted block to the output file
        plaintext_len += temp_len; // adds block's length to the total length
    }

    if(EVP_DecryptFinal_ex(ctx, temp_plaintext, &temp_len) != 1)   // finalizes decryption and checks for errors
    {
        handle_errors("decrypt_file_aes_gcm - Error finalizing decryption", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);   // frees the ctx
        return -5;
    }
    fwrite(temp_plaintext, 1, temp_len, output_file);  // writes the final decrypted block to the output

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1)    // set authentication tag
    {
        handle_errors("decrypt_file_aes_gcm - Authentication failed", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);   // frees the ctx
        return -6;
    }

    EVP_CIPHER_CTX_free(ctx);   // frees the ctx
    fclose(input_file); // closes the input file
    fclose(output_file);    // closes the output file

    return plaintext_len; 
}


// RSA encryptions/decryption functions

EVP_PKEY* generate_key_rsa(int bits)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if(ctx == NULL)
    {
        handle_errors("generate_key_rsa - failed creating CTX", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    if(EVP_PKEY_keygen_init(ctx) <= 0)
    {
        handle_errors("generate_key_rsa - failed initializing keygen", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
    {
        handle_errors("generate_key_rsa - failed setting keygen bits", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if(EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        handle_errors("generate_key_rsa - failed keygen", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}


char* get_pem_from_pkey(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if(bio == NULL) {
        handle_errors("get_pem_from_pkey - failed creating BIO", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    if(PEM_write_bio_PUBKEY(bio, pkey) != 1)
    {
        handle_errors("get_pem_from_pkey - failed writing to BIO", ERR_error_string(ERR_get_error(), NULL));
        BIO_free(bio);
        return NULL;
    }

    char *pem_data;
    size_t pem_len = BIO_get_mem_data(bio, &pem_data);
    char *pem_str = strndup(pem_data, pem_len);

    BIO_free(bio);
    return pem_str;
}


EVP_PKEY* get_pkey_from_pem(const char *public_key)
{
    BIO *bio = BIO_new_mem_buf(public_key, -1);
    if(bio == NULL) {
        handle_errors("get_pkey_from_pem - failed creating BIO", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if(pkey == NULL)
    {
        handle_errors("get_pkey_from_pem - failed reading from BIO", ERR_error_string(ERR_get_error(), NULL));
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);
    return pkey;
}

int encrpy_string_rsa(const unsigned char *plaintext, const size_t plaintext_len, const char *public_key, unsigned char *ciphertext)
{
    EVP_PKEY *pkey = get_pkey_from_pem(public_key);
    if(pkey == NULL)
    {
        handle_errors("encrpy_string_rsa - failed getting pkey", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    EVP_PKEY_CTX *ctx = NULL;
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if(ctx == NULL)
    {
        handle_errors("encrpy_string_rsa - failed creating CTX", ERR_error_string(ERR_get_error(), NULL));
        return -2;
    }

    if(EVP_PKEY_encrypt_init(ctx) <= 0) 
    {
        handle_errors("encrpy_string_rsa - failed initializing encryption", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(ctx);
        return -3;
    }

    size_t ciphertext_len;
    if(EVP_PKEY_encrypt(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len) <= 0)
    {
        handle_errors("encrpy_string_rsa - failed encrypting", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(ctx);
        return -4;
    }

    EVP_PKEY_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt_string_rsa(const unsigned char *ciphertext, const size_t ciphertext_len, EVP_PKEY *private_key, unsigned char *plaintext)
{
    EVP_PKEY_CTX *ctx = NULL;
    ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if(ctx == NULL)
    {
        handle_errors("decrypt_string_rsa - failed creating CTX", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    if(EVP_PKEY_decrypt_init(ctx) <= 0) 
    {
        handle_errors("decrypt_string_rsa - failed initializing decryption", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(ctx);
        return -2;
    }

    size_t plaintext_len;
    if(EVP_PKEY_decrypt(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len) <= 0)
    {
        handle_errors("decrypt_string_rsa - failed decrypting", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(ctx);
        return -3;
    }

    EVP_PKEY_CTX_free(ctx);
    return plaintext_len;
}