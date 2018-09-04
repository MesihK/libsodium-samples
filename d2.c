#include <sodium.h>
#include <string.h>

#define PASSWORD "905438642148"
#define IP "127.0.0.1"
char hashed_password[crypto_pwhash_STRBYTES];
unsigned char hash[crypto_generichash_BYTES];
unsigned char hashIP[crypto_generichash_BYTES];

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
    
    if (crypto_generichash(hash, sizeof hash, PASSWORD, strlen(PASSWORD), NULL, 0) == -1) {
        printf("hashing failed!\n");
    }

    if (crypto_generichash(hashIP, sizeof hashIP, IP, strlen(IP), PASSWORD, strlen(PASSWORD)) == -1) {
        printf("hashing failed!\n");
    }
    printf("pw:%s, hash:", PASSWORD);
    print_bytes(hash, sizeof hash);
    printf("\n");
    printf("ip:%s, hash:", IP);
    print_bytes(hashIP, sizeof hashIP);
    printf("\n");

    return 0;
}
