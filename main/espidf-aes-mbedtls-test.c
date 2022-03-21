#include <stdio.h>
#include "mbedtls/aes.h"

unsigned char key[] = "1234567890123456";
unsigned char iv[] = "1234567890123456";
unsigned char iv2[] = "1234567890123456";

mbedtls_aes_context aes, aes2;

unsigned char input[16] = "teste pika";
unsigned char output[16];
unsigned char output2[16];

void app_main(void)
{
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);

    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 16, iv, input, output);
    //mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, input, output);

    printf("%s\n", input);

    // print in hex

    for(int i = 0; i < 16; i++){
        printf("%02x ", output[i]);
    }

    //printf("%s\n", output);

    printf("\n");

    mbedtls_aes_free(&aes);

    mbedtls_aes_init(&aes2);
    mbedtls_aes_setkey_dec(&aes2, key, 128);
    mbedtls_aes_crypt_cbc(&aes2, MBEDTLS_AES_DECRYPT, 16, iv2, output, output2);
    //mbedtls_aes_crypt_ecb(&aes2, MBEDTLS_AES_DECRYPT, output, output2);

    // print in hex

    for(int i = 0; i < 16; i++){
        printf("%02X ", output2[i]);
    }

    printf("\n");

    printf("%s\n", output2);

    mbedtls_aes_free(&aes2);
}
