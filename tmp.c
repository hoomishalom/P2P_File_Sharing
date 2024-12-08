#include "headers/main_headers.h"
#include "headers/encrypt_decrypt.h"

int main() {
    // init_encrypt_decrypt(NULL);
    EVP_PKEY *pkey;
    pkey = generate_key_rsa(RSA_KEY_BITS);
    char *public_key = get_pem_from_pkey(pkey);

    unsigned char ciphertext[RSA_KEY_BITS*2];
    int ciphertext_len = encrpy_string_rsa("Hello World", strlen("Hello World"), public_key, ciphertext);

    unsigned char plaintext[RSA_KEY_BITS*2];
    int plaintext_len = decrypt_string_rsa(ciphertext, ciphertext_len, pkey, plaintext);

    printf(plaintext);
}
