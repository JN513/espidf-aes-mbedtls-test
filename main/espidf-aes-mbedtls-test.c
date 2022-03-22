#include <stdio.h>
#include <string.h>
#include "mbedtls/aes.h"

unsigned char key[] = "1234567890123456";
unsigned char iv[] = "1234567890123456";

mbedtls_aes_context aes;

static void init_aes();
static void deinit_aes();
static size_t get_output_size(size_t input_size);
static int get_qtd_blocks(size_t input_size);
static void aes_encrypt(unsigned char *input, size_t input_size, unsigned char *output);
static void aes_decrypt(unsigned char *input, size_t input_size, unsigned char *output);
static void print_hex(unsigned char *buf, int len);
static void to_uint8(unsigned char *buf, int len, uint8_t *output);
static void to_uchar(uint8_t *buf, int len, unsigned char *output);

void app_main(void)
{
    init_aes();

    unsigned char input[18] = "123456789012345678";

    size_t output_len = get_output_size(sizeof(input));

    printf("output_len: %d\n", output_len);

    unsigned char output[output_len];

    aes_encrypt(input, sizeof(input), output);

    print_hex(output, output_len);

    unsigned char output2[output_len+1];

    memset(output2, 0, output_len+1);

    aes_decrypt(output, sizeof(output), output2);

    print_hex(output2, output_len);

    printf("%s\n", output2);
}


static void init_aes(){
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);
    mbedtls_aes_setkey_dec(&aes, key, 128);
}

static void deinit_aes(){
    mbedtls_aes_free(&aes);
}

static size_t get_output_size(size_t input_size){
    if( input_size % 16 == 0 ){
        return input_size;
    } else {
        return 16 * (input_size / 16 + 1);
    }
}

static int get_qtd_blocks(size_t input_size){
    if( input_size % 16 == 0 ){
        return input_size / 16;
    } else {
        return input_size / 16 + 1;
    }
}

static void aes_encrypt(unsigned char *input, size_t input_size, unsigned char *output){
    unsigned char iv_copy[16];

    memcpy(iv_copy, iv, 16);

    int qtd_blocks = get_qtd_blocks(input_size);

    unsigned char input_block[16];
    unsigned char output_block[16];

    for(int i = 0; i < qtd_blocks; i++){
        memset(input_block, 0, 16);
        memset(output_block, 0, 16);

        if(input_size - (i * 16) < 16){
            memcpy(input_block, input + (i * 16), input_size - (i * 16));
        } else {
            memcpy(input_block, input + (i * 16), 16);
        }

        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 16, iv_copy, input_block, output_block);
        
        memcpy(output + i * 16, output_block, 16);
    }


}

static void aes_decrypt(unsigned char *input, size_t input_size, unsigned char *output){
    unsigned char iv_copy[16];

    memcpy(iv_copy, iv, 16);

    int qtd_blocks = get_qtd_blocks(input_size);

    unsigned char input_block[16];
    unsigned char output_block[16];

    for(int i = 0; i < qtd_blocks; i++){
        memset(input_block, 0, 16);
        memset(output_block, 0, 16);

        if(input_size - (i * 16) < 16){
            memcpy(input_block, input + (i * 16), input_size - (i * 16));
        } else {
            memcpy(input_block, input + (i * 16), 16);
        }

        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16, iv_copy, input_block, output_block);
        
        memcpy(output + i * 16, output_block, 16);
    }
}
static void print_hex(unsigned char *buf, int len){
    for(int i = 0; i < len; i++){
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

static void to_uint8(unsigned char *buf, int len, uint8_t *output){
    memcpy(output, buf, len);
}

static void to_uchar(uint8_t *buf, int len, unsigned char *output){
    memcpy(output, buf, len);
}