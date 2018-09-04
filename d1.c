#include <sodium.h>
#include <string.h>

#define PASSWORD "905438642148"
char hashed_password[crypto_pwhash_STRBYTES];

int main(void)
{
    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized, it is not safe to use */
    }
    printf("ok!\n");
    
    if (crypto_pwhash_str(hashed_password, PASSWORD, strlen(PASSWORD),
                          crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
        printf("out of memory!\n");
    }

    printf("pw:%s, hash:%s\n", PASSWORD, hashed_password);
    for(int i =0 ; i< 1000; i++){
        if (crypto_pwhash_str_verify
                    (hashed_password, PASSWORD, strlen(PASSWORD)) != 0) {
                /* wrong password */
            printf("password wrong!\n");
        } else {
            printf("password ok!\n");
        }
    }
    return 0;
}
