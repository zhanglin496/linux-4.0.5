#include <openssl/evp.h> 
#include <openssl/x509.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>  
#include <stdlib.h>

//公钥加密
//openssl rsautl -encrypt -in test -out test.enc -inkey asn1pub.pem -pubin
//私钥解密
//openssl rsautl -decrypt -in test.enc -out test.dec -inkey asn1enc.pem


void PrintHex(unsigned char *str, unsigned int len)  
{  
	int i;
	for (i =0; i< len; i++) {  
		if(i%4 == 0)
		 	printf("0x");

		printf("%02hhx",str[i]);  
		if (i%4 == 3)
			printf(" ");

		if(i%16 == 15)
			printf("\n");
	}
	printf("\n");
}  

static RSA *create_rsa_by_key(unsigned char *key, int public)
{
	RSA *rsa;
	BIO *keybio = BIO_new_mem_buf(key, -1);
	if (!keybio)
		return NULL;
	if (public) {
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
	} else {
		rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
	}
	BIO_free_all(keybio);
	return rsa;
}

static RSA *create_rsa_by_file(const char *file, int public)
{
	FILE *fp;
	RSA *p_rsa;
	if ((fp = fopen(file, "r")) == NULL)
		return NULL;

	if (public)
		p_rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
	else
		p_rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	return p_rsa;
}


void GetPukfromPEM(const char *file, int public)  
{  
	RSA *rsa;  
	unsigned char n[4096] ={0x0};  
	unsigned char e[4096] ={0x0};  
	unsigned int len;
	rsa = create_rsa_by_file(file, public);

	if(rsa->n != NULL) {
		BN_bn2bin(rsa->n, n);
		len= BN_num_bytes(rsa->n);
		printf("N:\n");
		PrintHex(n,len);
	} else {
		printf("PEM error \n");  
	}

	if (rsa->e != NULL) {  
		BN_bn2bin(rsa->e, e);  
		len= BN_num_bytes(rsa->e);    
		printf("E:\n");  
		PrintHex(e,len);  
	}  else  {  
		printf("PEM error \n");
		return;
	}

	if (rsa->d != NULL) {
		BN_bn2bin(rsa->d, e);
		len= BN_num_bytes(rsa->d);
		printf("D:\n");
		PrintHex(e,len);
	}

	if (rsa->p != NULL) {
		BN_bn2bin(rsa->p, e);
		len= BN_num_bytes(rsa->p);
		printf("P:\n");
		PrintHex(e,len);
	}

	if (rsa->q != NULL) {
		BN_bn2bin(rsa->q, e);
		len= BN_num_bytes(rsa->q);
		printf("Q:\n");
		PrintHex(e,len);
	}

	if (rsa->dmp1 != NULL) {
		BN_bn2bin(rsa->dmp1, e);
		len= BN_num_bytes(rsa->dmp1);
		printf("DP:\n");
		PrintHex(e,len);
	}

	if (rsa->dmq1 != NULL) {
		BN_bn2bin(rsa->dmq1, e);
		len= BN_num_bytes(rsa->dmq1);
		printf("DQ:\n");
		PrintHex(e,len);
	}

	if (rsa->iqmp != NULL) {
		BN_bn2bin(rsa->iqmp, e);
		len= BN_num_bytes(rsa->dmq1);
		printf("QP:\n");
		PrintHex(e,len);
	}
}
  
int main(int argc, char **argv)  
{
	int public;
	if (argc < 3) {
		printf("keyfile -pub/-priv\n");
		return -1;
	}
	if (!strcmp(argv[2], "-pub"))
		public = 1;
	else if (!strcmp(argv[2], "-priv"))
		public = 0;
	else 
		return -1;
	
	GetPukfromPEM(argv[1], public);  
	return 0;
}  
