#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>



int print_hex(char *data, int len)
{
        int i;
        for (i = 0; i < len; i++) {
                printf("%02hhx", data[i]);
        }
        printf("\n");
}

/* just for test */
int main(int argc, char **argv)
{
        int i;
        AES_KEY key;
        char from[1024] = "0123456789abcdef";
        char buf[1024];
        char out[1024];
        char iv[] = "=123456789abcdef";
        char iv2[] = "=123456789abcdef";
        memset(from + 16, 0, 512);
        AES_set_encrypt_key("0123456789abcdef", 128, &key);
        for (i = 0; i < 1024/16; i++)
                AES_cbc_encrypt(from+i*16, buf+i*16, 16, &key, iv, AES_ENCRYPT);
//      AES_encrypt(from + 16, buf + 16, &key);

        print_hex(from, 32);
        print_hex(buf, 1024);
        AES_set_decrypt_key("0123456789abcdef", 128, &key);
        for (i = 0; i < 1024/16; i++)
                AES_cbc_encrypt(buf+i*16, out+i*16, 16, &key, iv2, AES_DECRYPT);
//      AES_set_decrypt_key("0123456789abcdef", 128, &key);
//      AES_decrypt(buf, out, &key);
//      AES_decrypt(buf + 16, out + 16, &key);
        print_hex(out, 1024);
}
