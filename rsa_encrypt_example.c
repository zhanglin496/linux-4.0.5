#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
//生成私钥
//openssl genrsa -out private.key 2048

//生成公钥
//openssl rsa -in private.key -pubout > public.key

//公钥加密
//openssl rsautl -encrypt -in test -out test.enc -inkey asn1pub.pem -pubin
//私钥解密
//openssl rsautl -decrypt -in test.enc -out test.dec -inkey asn1enc.pem

#define ALIGN(x, a)	(((x) + (a) - 1) & ~((a) - 1))

static inline int align_encrypt_len(int len, int align)
{
	int i;
	unsigned char padding_len;
	i = len % align;
	padding_len = align - i;
	
	return ALIGN(len - i + padding_len, align);
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


/* for small data encrypt */
void *rsa_public_encrypt_fast(RSA *rsa, void *data, int *len, int padding)
{
	int flen, rsa_len;
	int i, j;
	int elen;
	int step;
	unsigned char *to;

	rsa_len = RSA_size(rsa);
	fprintf(stderr, "rsa_len=%d, len=%d\n", rsa_len, *len);

	switch (padding) {
	case RSA_PKCS1_PADDING:
	case RSA_SSLV23_PADDING:
		step = rsa_len - 11;
		break;
	case RSA_PKCS1_OAEP_PADDING:
		/* openssl need minus 1*/
		step = rsa_len - 41 - 1;
		break;
	case RSA_NO_PADDING:
		step = rsa_len;
		/* caller must be padding by oneself */
		if (*len % rsa_len)
			return NULL;
		break;
	default:
		return NULL;
	}

	j = *len / step + !!(*len % step);
	to = malloc(j*rsa_len);
	if (!to)
		return NULL;

	flen = *len;
	*len = 0;
	for (i = 0; i < j; i++) {
		elen = RSA_public_encrypt(flen > step ? step : flen, data, to + *len, rsa, padding);
		if (elen == -1) {
			ERR_load_crypto_strings();
			printf("%s err=%s\n", __func__, ERR_error_string(ERR_get_error(), data));
			goto out;
		}
		data += flen > step ? step : flen;
		flen -= flen > step ? step : flen;
		*len += elen;
	}
	printf("encrypt totalen=%d\n", *len);
	return to;

out:
	free(to);
	return NULL;
}

void *rsa_public_decrypt_fast(RSA *rsa, void *data, int *len, int padding)
{
	int rsa_len;
	int i, j;
	int dlen;
	unsigned char *to;

	rsa_len = RSA_size(rsa);
	if (*len % rsa_len)
		return NULL;

	to = malloc(*len);
	if (!to)
		return NULL;

	j = *len / rsa_len;
	*len = 0;
	for (i = 0; i < j; i++) {
		dlen = RSA_public_decrypt(rsa_len, data + i*rsa_len, to + *len, rsa, padding);
		if (dlen == -1) {
			ERR_load_crypto_strings();
			printf("%s err=%s\n", __func__, ERR_error_string(ERR_get_error(), data));
			goto out;
		}
		*len += dlen;
	}
	printf("decrypt total len =%d\n", *len);
	return to;

out:
	free(to);
	return NULL;
}


void *rsa_private_decrypt_fast(RSA *rsa, void *data, int *len, int padding)
{
	int rsa_len;
	int i, j;
	int dlen;
	unsigned char *to;

	rsa_len = RSA_size(rsa);
	if (*len % rsa_len)
		return NULL;

	to = malloc(*len);
	if (!to)
		return NULL;

	j = *len / rsa_len;
	*len = 0;
	for (i = 0; i < j; i++) {
		dlen = RSA_private_decrypt(rsa_len, data + i*rsa_len, to + *len, rsa, padding);
		if (dlen == -1) {
			ERR_load_crypto_strings();
			printf("%s err=%s\n", __func__, ERR_error_string(ERR_get_error(), data));
			goto out;
		}
		*len += dlen;
	}
	printf("decrypt total len =%d\n", *len);
	return to;

out:
	free(to);
	return NULL;
}

void *rsa_private_encrypt_fast(RSA *rsa, void *data, int *len, int padding)
{
	int flen, rsa_len;
	int i, j;
	int elen;
	int step;
	unsigned char *to;

	rsa_len = RSA_size(rsa);
	fprintf(stderr, "rsa_len=%d, len=%d\n", rsa_len, *len);

	switch (padding) {
	case RSA_PKCS1_PADDING:
		step = rsa_len - 11;
		break;
	case RSA_NO_PADDING:
		step = rsa_len;
		/* caller must be padding by oneself */
		if (*len % rsa_len)
			return NULL;
		break;
	default:
		return NULL;
	}

	j = *len / step + !!(*len % step);
	to = malloc(j*rsa_len);
	if (!to)
		return NULL;

	flen = *len;
	*len = 0;
	for (i = 0; i < j; i++) {
		elen = RSA_private_encrypt(flen > step ? step : flen, data, to + *len, rsa, padding);
		if (elen == -1) {
			ERR_load_crypto_strings();
			printf("err=%s\n", ERR_error_string(ERR_get_error(), data));
			goto out;
		}
		data += flen > step ? step : flen;
		flen -= flen > step ? step : flen;
		*len += elen;
	}
	printf("totalen=%d\n", *len);
	return to;

out:
	free(to);
	return NULL;
}


static char PubKey[] = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6FFoP31u/q4EYpKl1OPZ\n"
"ut+tKcBYoMRC2oR462bjn21osh6AfRc6BufoH65480A4WCTpjF26RhzJrfseBSZr\n"
"gJ2+1kUAF598wy5SNINStVURy+2uXrNoAwptoejXMcVlA4m/9kb0VAhF8G5eBJ9e\n"
"uLrEffEwsp/L8/WMLhSkaywzXJjy9WDAMjNMeaqgbti/AmbuFd10VTMocbgBgMBL\n"
"ZJHeUMHMnnwM3R+kfo4O8g/mcm5WlkQG9uw59foYl7ye2aroMl5sLw1CLJQiYWtq\n"
"UOhTVonBdf/9okraGPm6i2tMkzqApranznJFhkSNWTyYNP8oYEC6iLonu7YhOCcY\n"
"xwIDAQAB\n"
"-----END PUBLIC KEY-----\n";

static char PriveKey[] =  "-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEpAIBAAKCAQEA6FFoP31u/q4EYpKl1OPZut+tKcBYoMRC2oR462bjn21osh6A\n"
"fRc6BufoH65480A4WCTpjF26RhzJrfseBSZrgJ2+1kUAF598wy5SNINStVURy+2u\n"
"XrNoAwptoejXMcVlA4m/9kb0VAhF8G5eBJ9euLrEffEwsp/L8/WMLhSkaywzXJjy\n"
"9WDAMjNMeaqgbti/AmbuFd10VTMocbgBgMBLZJHeUMHMnnwM3R+kfo4O8g/mcm5W\n"
"lkQG9uw59foYl7ye2aroMl5sLw1CLJQiYWtqUOhTVonBdf/9okraGPm6i2tMkzqA\n"
"pranznJFhkSNWTyYNP8oYEC6iLonu7YhOCcYxwIDAQABAoIBABdjisFJmZEeZ+ac\n"
"qQFj5xm/Rym66bFV0P069QmOFECKvU2hcIIngnoLgv0djaO/xWxqWvD8xrIkV9Gi\n"
"RIV0NsJ+HyZnT/kQ33ivAyuyRPNomyASz8lM+p3DwQHZ9UBXhTHz/lWHEzYalx/7\n"
"nI+Ok/S5KOsdCzAQknH/OJuzDFKVsYKv6eX7dwbLlaQ2JL8J0FK6mTjQ8cmNudu6\n"
"6xJN8d7OThzulywmyTt7ICMO1PXgUgq1n2Wr2F8CnkN9rAFaI1pdJClgkE/5IdWE\n"
"DSiDsQrINenuJ066DhoIJj4KZKvKNZ6eIJFzJzoYHlNolmIdlmAPqLEBRfNoZHVN\n"
"F6zfdxECgYEA9jDcisLtc4+q17wbZCb1EhaZzFJCNh2yd7ot3os+7N4Oy2EZDRCK\n"
"nCFg/nxsO9oNV8j6zPdnQye6PsdgyO73igGmZJEYSiV5ocpZ9r6P5T7zsUczdBBr\n"
"TiuHw+2jzDNtWYzw6+5kBBP3lzCurTSkM2vBSj/PHy4EbBj6uJlQjIMCgYEA8ZMK\n"
"/guZDRIst3vXXZpHLrk/l7zZTI2oIjAtJDsSjPpwQmEBITkg9HyQpZz7kUMbARS0\n"
"3z1tVKdtD/lyJKEo2MMzrJUQDu1aIgblt17Y+eqQbOYhGUsk6QoJJeogq5nqziIA\n"
"DGT989cPp8G5MPlfpkskOxCdadHPu+FfQqz+l20CgYEAw7+UC+zzunfYIlLaAKcN\n"
"I0W/Ifuh07+HILVzNUjITrQ9VS6uKXomi//qTE6IDIrTIyKVcBWjEH1tE++ZoAqJ\n"
"3jxznfDUPFhRvvfS0mMwrNmCEEoJulY3y97Gw12XaIzXfGWZRi61bZymt5souGVr\n"
"zcr21F+qAyOmtoCiEdcteZsCgYAA1FFoV9/ZpKNUqe8uWhY+edJXEgXo9l+KZoHx\n"
"KubAZye1gqG/XHPZgwf4GZbfg8x273xDe/GBJeYA9QlISOlb/SeTQxvAAV6a2U02\n"
"mPPDv+NpDE02ygRBbJBlee1MyYV92a4IXNxmVumt2MNrAKAscPuZ3E++CkNdUMPD\n"
"9dYV7QKBgQCBJt0l+lg4m7+MLGgA2KwYETa1WndxO8jhJ+Iu+m+qgn2Ne5sWCq80\n"
"ay2g5pnNMQoZS/tOIVHwqgVRsjgFV2CrzT/81c4r9j86Ir0Vz5+OJoP6tezIlF5l\n"
"gubWKNawvL+FtcekeqwOwvhb+dOf8QK+AwdSPRJN3kGHL7wTjWX5QA==\n"
"-----END RSA PRIVATE KEY-----\n";

//
//./rsa_encrypt_example -d -f opk.tgz.enc  -r private.key
//私钥加密
//./rsa_encrypt_example -e -f opk.tgz  -r private.key
//公钥解密
//./rsa_encrypt_example -d -f opk.tgz.enc  -p public.key

int main(int argc, char **argv)
{
	char *name = NULL;
	char *pub_key = NULL, *pri_key = NULL;
	int de = 0, en = 0;
	char *ptr;
	char *to;
	char *data;
	FILE *rfp;
	FILE *wfp;
	int len;
	int ch;
	RSA *rsa;
	char name2[1024];

	while ((ch = getopt(argc, argv, "f:dep:r:")) != -1) {
		switch (ch) {
		case 'f': //加解密文件
			name = strdup(optarg);
			break;
		case 'd': //解密
			de = 1;
			break;
		case 'e': // 加密
			en = 1;
			break;
		case 'p': //公钥
			pub_key = strdup(optarg);
			break;
		case 'r': //私钥
			pri_key = strdup(optarg);
			break;
		}
	}
	if (!name)
		return -1;
	data = malloc(1024*1024);
	if (!data)
		return -1;
	rfp = fopen(name,  "r");
	if (!rfp)
		return -1;
	snprintf(name2, sizeof(name2), "%s", name);
	if (en)
		strcat(name2, ".enc");
	else if (de)
		strcat(name2, ".dec");
	else
		return -1;

	wfp = fopen(name2,  "w");
	if (!wfp)
		return -1;
	ptr = data;
	while ((len = fread(ptr, 1, 4096, rfp)) > 0) {
		ptr += len;
	}
	if (!feof(rfp))
		return -1;
	len = ptr -data;

	if (pub_key)
		rsa = create_rsa_by_file(pub_key, 1);
	else if (pri_key)
		rsa = create_rsa_by_file(pri_key, 0);
	else
		return -1;
	if (!rsa)
		return -1;

	if (pub_key) {
		if (en) {
			to = rsa_public_encrypt_fast(rsa, data, &len, RSA_PKCS1_PADDING);
			if (!to)
				return -1;
			fwrite(to, len, 1, wfp);
			fclose(rfp);
			fclose(wfp);
		} else {
			to = rsa_public_decrypt_fast(rsa, data, &len, RSA_PKCS1_PADDING);
			if (!to)
				return -1;
			fwrite(to, len, 1, wfp);
			fclose(rfp);
			fclose(wfp);
		}
	} else {
		if (en) {
			to = rsa_private_encrypt_fast(rsa, data, &len, RSA_PKCS1_PADDING);
			if (!to)
				return -1;
			fwrite(to, len, 1, wfp);
			fclose(rfp);
			fclose(wfp);
		} else {
			to = rsa_private_decrypt_fast(rsa, data, &len, RSA_PKCS1_PADDING);
			if (!to)
				return -1;
			fwrite(to, len, 1, wfp);
			fclose(rfp);
			fclose(wfp);
		}
	}
	return 0;
}
