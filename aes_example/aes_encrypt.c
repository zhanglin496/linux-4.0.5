#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>


#include "util.h"

int main(int argc, char **argv)
{
	char name[2048];
	struct stat tat;
	int len;
	char *from = NULL;
	char *to = NULL;
	FILE *fp = NULL;
	FILE *outfp = NULL;
	int ret = -1;
	if (argc < 2)
		goto out;
	fp = fopen(argv[1], "r");
	if (!fp) {
		printf("error open %s error\n", argv[1]);
		goto out;
	}
	snprintf(name, sizeof(name), "%s.enc", argv[1]);
	outfp = fopen(name, "w");
	if (!outfp) {
		printf("error open %s error\n", name);
		goto out;
	}
	if (fstat(fileno(fp), &tat) == -1)
		goto out;
	from = malloc(tat.st_size);
	to = malloc(tat.st_size);
	if (!from || !to)
		goto out;
	if (fread(from, 1, tat.st_size, fp) != tat.st_size)
		goto out;
	if (aes128_cbc_encrypt(from, tat.st_size, "@3pfxd8$pd71#X2>",
			to, &len, "j^*adHs96YU57MZi") < 0)
		goto out;
	if (fwrite(to, 1, len, outfp) != len)
		goto out;

	ret = 0;

out:
	if (ret)
		printf("encrypt %s error\n", argv[1]);
	else
		printf("encrypt %s success\n", argv[1]);
	if (fp)
		fclose(fp);
	if (outfp)
		fclose(outfp);
		
		
	return ret;
}
