#ifndef _UTIL_H_
#define _UTIL_H_

struct wget_info;
typedef int (*wget_write_callback)(struct wget_info *info, FILE *fp);
typedef int (*wget_read_callback)(struct wget_info *info, char *buf, int len);


#define LOG_PATH	"/tmp/.splice.log"

struct wget_info {
	const char *header;
	int post;
	const void *data;
	int data_len;
	void *dst;
	int dst_len;
	FILE *fp;
	int nr;
	unsigned int  is_gzip : 1,
                ecoding : 1;
	void *private;
	wget_write_callback w_callback;
	wget_read_callback r_callback;
};

#define panic(fmt, ...) \
	do { \
		app_log("[panic] "fmt, ##__VA_ARGS__); \
		exit(EXIT_FAILURE); \
	} while (0)

#ifndef min_t
#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })
#endif

#define ALIGN(x, a)	(((x) + (a) - 1) & ~((a) - 1))

static inline int align_encrypt_len(int len, int align)
{
	int i;
	uint8_t padding_len;
	i = len % align;
	padding_len = align - i;
	
	return ALIGN(len - i + padding_len, align);
}

int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len);
#define read_lock(fd, offset, whence, len) \
                         lock_reg((fd), F_SETLK, F_RDLCK, (offset), (whence), (len))
#define readw_lock(fd, offset, whence, len) \
                         lock_reg((fd), F_SETLKW, F_RDLCK, (offset), (whence), (len))
#define write_lock(fd, offset, whence, len) \
                         lock_reg((fd), F_SETLK, F_WRLCK, (offset), (whence), (len))
#define writew_lock(fd, offset, whence, len) \
                         lock_reg((fd), F_SETLKW, F_WRLCK, (offset), (whence), (len))
#define un_lock(fd, offset, whence, len) \
                         lock_reg((fd), F_SETLK, F_UNLCK, (offset), (whence), (len))


int grab_pidlock(const char *path);
char *hex2str(const char *src, char *dst, int src_len, int dst_len);
int wget(const char *src_url, struct wget_info *info);
int app_log(const char *fmt, ...);

int aes128_cbc_decrypt_no_padding(uint8_t *edata, int edata_len, uint8_t *key,
		uint8_t *ddata, int *ddata_len, uint8_t *iv);
int aes128_cbc_encrypt(uint8_t *ddata, int ddata_len, uint8_t *key,
		uint8_t *edata, int *edata_len, uint8_t *iv);
int aes128_cbc_decrypt(uint8_t *edata, int edata_len, uint8_t *key,
		uint8_t *ddata, int *ddata_len, uint8_t *iv);
int aes256_cbc_decrypt(uint8_t *edata, int edata_len, uint8_t *key,
                uint8_t *ddata, int *ddata_len, uint8_t *iv);
int aes256_cbc_decrypt_no_padding(uint8_t *edata, int edata_len, uint8_t *key,
		uint8_t *ddata, int *ddata_len, uint8_t *iv);
int aes128_ecb_decrypt_no_padding(uint8_t *edata, int edata_len, uint8_t *key,
		uint8_t *ddata, int *ddata_len, uint8_t *iv);

RSA *create_rsa_by_key(unsigned char *key, int public);
int get_random_bytes(void *buf, int nbytes);
char *rsa_public_encrypt_key(unsigned char *str, int *p_len, char *path_key);

#endif
