#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handleErrors() {
    fprintf(stderr, "An error occurred\n");
    exit(EXIT_FAILURE);
}

int encrypt_file(const char *input_filename, const char *output_filename, unsigned char *key, unsigned char *iv, unsigned char *tag) {
    FILE *input_file = fopen(input_filename, "rb");
    FILE *output_file = fopen(output_filename, "wb");
    if (!input_file || !output_file) {
        perror("File open error");
        return -1;
    }

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len = 0;
    unsigned char buffer[1024];
    unsigned char ciphertext[1040]; // Buffer size + AES_BLOCK_SIZE

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handleErrors();
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    while ((len = fread(buffer, 1, 1024, input_file)) > 0) {
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, len)) handleErrors();
        fwrite(ciphertext, 1, len, output_file);
        ciphertext_len += len;
    }

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext, &len)) handleErrors();
    fwrite(ciphertext, 1, len, output_file);
    ciphertext_len += len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) handleErrors();

    EVP_CIPHER_CTX_free(ctx);
    fclose(input_file);
    fclose(output_file);

    return ciphertext_len;
}

int decrypt_file(const char *input_filename, const char *output_filename, unsigned char *key, unsigned char *iv, unsigned char *tag) {
    FILE *input_file = fopen(input_filename, "rb");
    FILE *output_file = fopen(output_filename, "wb");
    if (!input_file || !output_file) {
        perror("File open error");
        return -1;
    }

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len = 0;
    unsigned char buffer[1024];
    unsigned char plaintext[1024];

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handleErrors();
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) handleErrors();

    while ((len = fread(buffer, 1, 1024, input_file)) > 0) {
        if(!EVP_DecryptUpdate(ctx, plaintext, &len, buffer, len)) handleErrors();
        fwrite(plaintext, 1, len, output_file);
        plaintext_len += len;
    }

    if(EVP_DecryptFinal_ex(ctx, plaintext, &len) > 0) {
        fwrite(plaintext, 1, len, output_file);
        plaintext_len += len;
    } else {
        handleErrors();
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(input_file);
    fclose(output_file);

    return plaintext_len;
}

int main() {
    unsigned char key[32];
    unsigned char iv[12];
    unsigned char tag[16];

    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        handleErrors();
    }

    if (encrypt_file("plaintext.txt", "encrypted.bin", key, iv, tag) < 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }

    if (decrypt_file("encrypted.bin", "decrypted.txt", key, iv, tag) < 0) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }

    printf("Encryption and decryption completed successfully.\n");

    return 0;
}
