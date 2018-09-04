#include <sodium.h>
#include <string.h>

#define MESSAGE ((const unsigned char *) "test")
#define MESSAGE_LEN 4
#define CIPHERTEXT_LEN (crypto_secretbox_MACBYTES + MESSAGE_LEN)

unsigned char key[crypto_secretbox_KEYBYTES];
unsigned char nonce[crypto_secretbox_NONCEBYTES];
unsigned char ciphertext[CIPHERTEXT_LEN];

void print_bytes(unsigned char *buf, int len){
    for (int i = 0; i < len; i++)
    {
        printf("%02x", buf[i]);
    }
}

int main(){

    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized, it is not safe to use */
    }
    printf("ok\n");

    crypto_secretbox_keygen(key);
    printf("Key:   "); print_bytes(key, sizeof key);
    randombytes_buf(nonce, sizeof nonce);
    printf("\nNonce: "); print_bytes(nonce, sizeof nonce);
    crypto_secretbox_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce, key);
    printf("\nCryp:  "); print_bytes(ciphertext, sizeof ciphertext);

    unsigned char decrypted[MESSAGE_LEN];
    if (crypto_secretbox_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce, key) != 0) {
            /* message forged! */
    }
    printf("\nDecr:  %s\n", decrypted); 
}
