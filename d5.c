#include <sodium.h>
#include <string.h>

#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 4
#define CIPHERTEXT_LEN (crypto_box_MACBYTES + MESSAGE_LEN)

void print_bytes(unsigned char *buf, int len){
    for (int i = 0; i < len; i++)
    {
        printf("%02x", buf[i]);
    }
}

int main(void)
{
    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized, it is not safe to use */
    }
    printf("ok!\n");

    unsigned char alice_publickey[crypto_box_PUBLICKEYBYTES];
    unsigned char alice_secretkey[crypto_box_SECRETKEYBYTES];
    unsigned char alice_calckey[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(alice_publickey, alice_secretkey);

    unsigned char bob_publickey[crypto_box_PUBLICKEYBYTES];
    unsigned char bob_secretkey[crypto_box_SECRETKEYBYTES];
    unsigned char bob_calckey[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(bob_publickey, bob_secretkey);

    if( crypto_box_beforenm(alice_calckey, bob_publickey, alice_secretkey) != 0)
        printf("Beforenm calculation failed!\n");
    if( crypto_box_beforenm(bob_calckey, alice_publickey, bob_secretkey) != 0)
        printf("Beforenm calculation failed!\n");

    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char ciphertext[CIPHERTEXT_LEN];
    unsigned char ciphertext2[CIPHERTEXT_LEN];
    randombytes_buf(nonce, sizeof nonce);

    if (crypto_box_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce,
                                    bob_publickey, alice_secretkey) != 0) {
        printf("crypt error!\n");
    }
    if (crypto_box_easy_afternm(ciphertext2, MESSAGE, MESSAGE_LEN, nonce,
                                    alice_calckey) != 0) {
        printf("After crpyt error!\n");
    }

    unsigned char decrypted[MESSAGE_LEN];
    unsigned char decrypted2[MESSAGE_LEN];
    if (crypto_box_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce,
                                         alice_publickey, bob_secretkey) != 0) {
        /* message for Bob pretending to be from Alice has been forged! */
        printf("decrypt error!\n");
    } else { 
        printf("Decryption succes!\n");
    }
    if (crypto_box_open_easy_afternm(decrypted2, ciphertext2, CIPHERTEXT_LEN, nonce,
                                         bob_calckey) != 0) {
        /* message for Bob pretending to be from Alice has been forged! */
        printf("After decrypt error!\n");
    } else { 
        printf("After Decryption succes!\n");
    }

    printf("A public: "); print_bytes(alice_publickey, sizeof alice_publickey);
    printf("\n  private:"); print_bytes(alice_secretkey, sizeof alice_secretkey);
    printf("\n  calc   :"); print_bytes(alice_calckey, sizeof alice_calckey);
    printf("\nB public: "); print_bytes(bob_publickey, sizeof bob_publickey);
    printf("\n  private:"); print_bytes(bob_secretkey, sizeof bob_publickey);
    printf("\n  calc   :"); print_bytes(bob_calckey, sizeof bob_calckey);
    printf("\nMessage: %s crypt: ", decrypted); print_bytes(ciphertext, sizeof ciphertext);
    printf("\nMessage: %s crypt: ", decrypted2); print_bytes(ciphertext2, sizeof ciphertext2);
    printf("\nnonce: "); print_bytes(nonce, sizeof nonce);
    printf("\n");
    return 0;
}
