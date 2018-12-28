#include <sys/types.h>	
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "util.h"

struct host_info {
	char *allocated;
	char *host;
	char *path;
	int port;
	int is_https;
};


#ifdef APP_LOG_OUTPUT
int app_log(const char *fmt, ...)
{
	va_list argptr;
	struct stat buf;
	struct timeval tv;
	char log[64];

	FILE *fp = fopen(LOG_PATH, "a");
	if (!fp)
		return -1;

	fstat(fileno(fp), &buf);
	if (buf.st_size >= 10*1024) {
		fp = freopen(LOG_PATH, "w+", fp);
		if (!fp)
			return -1;
	}

	gettimeofday(&tv,NULL);
	strftime(log, sizeof(log), "%m-%d %H:%M:%S", localtime(&tv.tv_sec));
	fprintf(fp, "[%ld] %s ", (long)getpid(), log);

	va_start(argptr, fmt);
	vfprintf(fp, fmt, argptr);
	va_end(argptr);
	fclose(fp);
	return 0;
}
#else
int app_log(const char *fmt, ...)
{
	return 0;
}
#endif


int connect_nonblock(int sockfd, const struct sockaddr *saptr, 
			socklen_t salen, int nsec)
{
	int flags, n, error;
	socklen_t len;
	fd_set rset, wset;
	struct timeval	tval;

	flags = fcntl(sockfd, F_GETFL, 0);
	if (flags == -1)
		return -1;
	if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
		return -1;

	error = 0;
	if ((n = connect(sockfd, saptr, salen)) < 0)
		if (errno != EINPROGRESS)
			return -1;

	if (n == 0)
		goto done;	/* connect completed immediately */

	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);
	wset = rset;
	tval.tv_sec = nsec;
	tval.tv_usec = 0;

	if ((n = select(sockfd + 1, &rset, &wset, NULL,
					 nsec ? &tval : NULL)) == 0) {
		/* timeout */
		errno = ETIMEDOUT;
		return -1;
	}

	if (FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset)) {
		len = sizeof(error);
		if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
			return -1;			
	} else {
		return -1;
	}

done:
	if (fcntl(sockfd, F_SETFL, flags) == -1)	/* restore file status flags */
		return -1;

	if (error) {
		errno = error;
		return -1;
	}
	return 0;
}

struct addrinfo *getaddrlist(const char *name, const char *service, const int socktype)
{
   	struct addrinfo hints, *res = NULL;
    	int n;
    	memset(&hints, 0, sizeof(struct addrinfo));
    	hints.ai_family = AF_INET;  /* ipv4 */
    	hints.ai_socktype = socktype;  

    	if ((n = getaddrinfo(name, service, &hints, &res)) != 0) {
        	app_log("getaddrinfo error for %s : %s\n",
		       	    name , gai_strerror(n));
        	return NULL;
    	}
    	return res;
}

static int get_http_status(FILE *sfp, char *buf, size_t buf_size)
{
	char *cp;
	char *status;

	if (!fgets(buf, buf_size, sfp))
		return -1;

	if (strlen(buf) < 9)
		return -1;
	cp = buf;
	//HTTP/1.1
	cp = buf + 8;

	while (*cp && isspace((int)*cp))
		cp++;
	status = cp;
	while (*cp && isdigit((int)*cp))
		cp++;

	if (cp == status)
		return -1;
	*cp = '\0';

	return atoi(status);
}


static char *gethdr(FILE *fp, char *buf, size_t bufsiz, int *istrunc)
{
	char *s, *hdrval;
	int c;

	*istrunc = 0;

	/* retrieve header line */
	if (!fgets(buf, bufsiz, fp))
		return NULL;

	/* see if we are at the end of the headers */
	for (s = buf; *s == '\r'; ++s)
		;
	if (s[0] == '\n')
		return NULL;

	for (s = buf; isalnum(*s) || *s == '-' || *s == '.' || *s == '_'; ++s)
		;

	/* verify we are at the end of the header name */
	if (*s != ':')
		return NULL;

	/* locate the start of the header value */
	for (*s++ = '\0'; *s == ' ' || *s == '\t'; ++s)
		;
	hdrval = s;

	/* locate the end of header */
	while (*s != '\0' && *s != '\r' && *s != '\n')
		++s;

	/* end of header found */
	if (*s != '\0') {
		*s = '\0';
		return hdrval;
	}

	/* Rats!  The buffer isn't big enough to hold the entire header value. */
	while (c = getc(fp), c != EOF && c != '\n')
		;
	*istrunc = 1;
	return hdrval;
}

FILE *open_socket(struct addrinfo *res)
{
	int sockfd;
	FILE *fp;
	struct timeval timeout;
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    	if (sockfd < 0)
		return NULL;

    	if (connect_nonblock(sockfd, res->ai_addr, res->ai_addrlen, 5) < 0) {
		close(sockfd);
		return NULL;
	}

	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	fp = fdopen(sockfd, "r+");
	if (!fp)
		close(sockfd);

	return fp;
}

static int parse_url(const char *src_url, struct host_info *h)
{
	char *url, *p, *sp;

	h->allocated = NULL;
	/* h->allocated = */ 
	url = strdup(src_url);
	if (!url)
		return -1;

	if (strncasecmp(url, "http://", 7) == 0) {
		h->port = 80;
		h->host = url + 7;
		h->is_https = 0;
	} else if (strncasecmp(url, "https://", 8) == 0) {
		h->port = 443;
		h->host = url + 8;
		h->is_https = 1;
	} else {
		free(url);
		app_log("not an http or https url: %s", src_url);
		return -1;
	}
	//	bb_error_msg_and_die("not an http or ftp url: %s", url);

	// FYI:
	// "Real" wget 'http://busybox.net?var=a/b' sends this request:
	//   'GET /?var=a/b HTTP 1.0'
	//   and saves 'index.html?var=a%2Fb' (we save 'b')
	// wget 'http://busybox.net?login=john@doe':
	//   request: 'GET /?login=john@doe HTTP/1.0'
	//   saves: 'index.html?login=john@doe' (we save '?login=john@doe')
	// wget 'http://busybox.net#test/test':
	//   request: 'GET / HTTP/1.0'
	//   saves: 'index.html' (we save 'test')
	//
	// We also don't add unique .N suffix if file exists...
	sp = strchr(h->host, '/');
	p = strchr(h->host, '?'); if (!sp || (p && sp > p)) sp = p;
	p = strchr(h->host, '#'); if (!sp || (p && sp > p)) sp = p;
	if (!sp) {
		/* must be writable because of bb_get_last_path_component() */
		static char nullstr[] = "";
		h->path = nullstr;
	} else if (*sp == '/') {
		*sp = '\0';
		h->path = sp + 1;
	} else { // '#' or '?'
		// http://busybox.net?login=john@doe is a valid URL
		// memmove converts to:
		// http:/busybox.nett?login=john@doe...
		memmove(h->host-1, h->host, sp - h->host);
		h->host--;
		sp[-1] = '\0';
		h->path = sp;
	}

	sp = strrchr(h->host, '@');
//	h->user = NULL;
	if (sp != NULL) {
//		h->user = h->host;
		*sp = '\0';
		h->host = sp + 1;
	}
	if ((sp = strrchr(h->host, ':'))) {
		*sp = '\0';
		sp++;
		h->port = atoi(sp);
	}

	h->allocated = url;
	return 0;
}

int wget(const char *src_url, struct wget_info *info)
{
	struct addrinfo *addr = NULL;
	struct host_info target;
	FILE *sfp = NULL;
	char buf[4096];	
	char port[8];
	char *str;
	int code, ret, nr, len;
	int chunked = 0, got_len = 0;
	int content_len = 0;
	int try = 3;

	static const char *key1 = "Content-Length";
	static const char *key2 = "transfer-encoding";
	static const char *key3 = "chunked";
	static const char *key4 = "location";
	static const char *key5 = "Content-Encoding";
	static const char *user_agent = "Mozilla/5.0 (Windows NT 6.2; WOW64)"
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36";

	ret = parse_url(src_url, &target);
	if (ret < 0)
		return -1;
	ret = -1;

try_again:
	if (target.is_https)
		goto out; 

	if (!--try) {
		app_log("too many redirections\n");
		goto out;
	}

	snprintf(port, sizeof(port), "%hu", target.port);
	addr = getaddrlist(target.host, port, SOCK_STREAM);
	if (!addr)
		goto out;

	sfp = open_socket(addr);
	if (!sfp)
		goto out;
	if (target.port != 80)
		snprintf(port, sizeof(port), ":%hu", target.port);

	/* Send HTTP request.  */
	len = snprintf(buf, sizeof(buf), "%s /%s HTTP/1.1\r\n"
		"Host: %s%s\r\nUser-Agent: %s\r\n"
		"Accept-Encoding: %s\r\n%s"
		"Content-Length: %d\r\n"
		"Cache-Control: no-cache\r\n"
		"Connection: keep-alive\r\n\r\n", info->post ? "POST" : "GET", target.path, target.host,
		target.port != 80 ? port : "", user_agent, info->ecoding ? "gzip, deflate, sdch" : "", info->header ? info->header : "",
		info->data ? info->data_len : 0);
	if (len >= sizeof(buf))
		goto out;

	fwrite(buf, len, 1, sfp);
	if (info->w_callback)
		info->w_callback(info, sfp);
	else if (info->data)
		fwrite(info->data, info->data_len, 1, sfp);

read_response:

	code = get_http_status(sfp, buf, sizeof(buf));
	if (code < 0)
		goto out;

	switch (code) {
		case 0:
		case 100:
			while (gethdr(sfp, buf, sizeof(buf), &nr))
					/* eat all remaining headers */;
			goto read_response;
		case 200:
			break;
		case 300:	/* redirection */
		case 301:
		case 302:
		case 303:
			break;
		case 404:
		case 206:
			//ignore, not surpport
		default:
			goto out;
	}

	while ((str = gethdr(sfp, buf, sizeof(buf), &nr)) != NULL) {
		if (!strncasecmp(buf, key1, strlen(key1))) {
			content_len = strtoul(str, NULL, 10);
			if (content_len < 0)
				goto out;
			got_len = 1;
		} else if (!strncasecmp(buf, key2, strlen(key2))) {
			if (strncasecmp(str, key3, strlen(key3))) {
				goto out;
			}
			chunked = got_len = 1;
		} else if (!strncasecmp(buf, key4, strlen(key4))) {
			if (str[0] == '/')
				target.path = "/";
			else {
				free(target.allocated);
				freeaddrinfo(addr);
				addr = NULL;
				target.allocated = NULL;
				if (parse_url(str, &target) < 0)
					goto out;
				goto try_again;
			}
		} else if (!strncasecmp(buf, key5, strlen(key5))) {
			if (!strncasecmp(str, "gzip", strlen("gzip"))) {
				info->is_gzip = 1;
			}
		}
	}

	/* read content */
	if (chunked) {
		if (!fgets(buf, sizeof(buf), sfp))
			goto out;
		content_len = strtoul(buf, NULL, 16);
		/* FIXME: error check?? */
		if (content_len < 0) {
			goto out;
		}
	}

	if (content_len == 0) {//|| content_len > info->dst_len)
		ret = 0;
		goto out;
	}

	nr = 0;
	do {
		while (content_len > 0) {
			unsigned rdsz = content_len < sizeof(buf) ? content_len : sizeof(buf);
			len = fread(buf, 1, rdsz, sfp);
			if (len <= 0)
				goto out;
			len = info->r_callback(info, buf, len);
			if (len <= 0)
				goto out;
			#if 0
			unsigned rdsz = content_len < sizeof(buf) ? content_len : sizeof(buf);
			len = fread(buf, 1, rdsz, sfp);
			if (len <= 0)
				goto out;

			content_len -= len;
			if (nr + len > info->dst_len) {
				errno = ENOBUFS;
				goto out;
			}
			memcpy((char *)info->dst + nr, buf, len);
			nr += len;
			#endif
			nr += len;
			content_len -= len;
		}

		if (chunked) {
			//\r\naabc\r\n
			if (!fgets(buf, sizeof(buf), sfp))
				goto out;
			if (!fgets(buf, sizeof(buf), sfp))
				goto out;
			content_len = strtoul(buf, NULL, 16);
			/* FIXME: error check? */
			if (content_len < 0) {
				goto out;
			} else if (content_len == 0) {
				ret = 0;
				chunked = 0; /* all done! */
			}
		} else if (content_len == 0) {
			ret = 0;
		}
	} while (chunked);

out:
	if (target.allocated)
		free(target.allocated);
	if (addr)
		freeaddrinfo(addr);
	if (sfp)
		fclose(sfp);
//	if (!ret)
//		info->dst_len = nr;

	return ret;
}

static int get_random_fd(void)
{
        int fd;
        int i;

        fd = open("/dev/urandom", O_RDONLY);

        if (fd == -1)
                fd = open("/dev/random", O_RDONLY | O_NONBLOCK);

        if (fd >= 0) {
                i = fcntl(fd, F_GETFD);
                if (i >= 0)
                        fcntl(fd, F_SETFD, i | FD_CLOEXEC);
        }

        return fd;
}

int get_random_bytes(void *buf, int nbytes)
{
        int i, n = nbytes, fd = get_random_fd();
        int lose_counter = 0;
        unsigned char *cp = buf;

        if (fd >= 0) {
                while (n > 0) {
                        i = read(fd, cp, n);
                        if (i <= 0) {
                                if (lose_counter++ > 16)
                                        break;
                                continue;
                        }
                        n -= i;
                        cp += i;
                        lose_counter = 0;
                }
		close(fd);
        }

        if (n == 0)
                return 0;

        return -1;
}

static int aes_encrypt(const EVP_CIPHER *cipher, uint8_t *ddata, int ddata_len,
		uint8_t *key, uint8_t *iv, uint8_t *edata, int *edata_len)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int len;
	int ret = -1;

	if (!(ctx = EVP_CIPHER_CTX_new()))
		return -1;

	ret = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
	if (ret != 1)  {
		ret = -1;
		goto out;
	}

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	ret = EVP_EncryptUpdate(ctx, edata, &len, ddata, ddata_len);
	if(ret != 1) {
		ret = -1;
		goto out;
	}

	*edata_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	ret = EVP_EncryptFinal_ex(ctx, edata + len, &len);
	if (ret != 1) {
		ret = -1;
		goto out;
	}
	*edata_len += len;

	ret = 0;
out:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

static int __aes_decrypt(const EVP_CIPHER *cipher, uint8_t *edata, int edata_len,
		uint8_t *key, uint8_t *iv, uint8_t *ddata, int *ddata_len, int padding)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int len;
	int ret = -1;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		return -1;

	ret = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
	if (ret != 1) {
		ret = -1;
		goto out;
	}

	/* padding ? */
	EVP_CIPHER_CTX_set_padding(ctx, !!padding);

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	ret = EVP_DecryptUpdate(ctx, ddata, &len, edata, edata_len);
	if (ret != 1) {
		ret = -1;
		goto out;
	}

	*ddata_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	ret = EVP_DecryptFinal_ex(ctx, ddata + len, &len);
	if (ret != 1) {
		ret = -1;
		goto out;
	}

	*ddata_len += len;

	ret = 0;
out:
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ret;
}

int aes_decrypt(const EVP_CIPHER *cipher, uint8_t *edata, int edata_len,
		uint8_t *key, uint8_t *iv, uint8_t *ddata, int *ddata_len)
{
	return __aes_decrypt(EVP_aes_128_cbc(), edata, edata_len,
			key, iv, ddata, ddata_len, 1);
}

int aes256_cbc_encrypt(uint8_t *ddata, int ddata_len, uint8_t *key,
		uint8_t *edata, int *edata_len, uint8_t *iv)
{
	return aes_encrypt(EVP_aes_256_cbc(), ddata, ddata_len,
			key, iv, edata, edata_len);
}

int aes256_cbc_decrypt(uint8_t *edata, int edata_len, uint8_t *key,
		uint8_t *ddata, int *ddata_len, uint8_t *iv)
{
	return aes_decrypt(EVP_aes_256_cbc(), edata, edata_len, 
			key, iv, ddata, ddata_len);
}

int aes128_cbc_encrypt(uint8_t *ddata, int ddata_len, uint8_t *key,
		uint8_t *edata, int *edata_len, uint8_t *iv)
{
	return aes_encrypt(EVP_aes_128_cbc(), ddata, ddata_len, 
			key, iv, edata, edata_len);
}

int aes128_cbc_decrypt(uint8_t *edata, int edata_len, uint8_t *key,
		uint8_t *ddata, int *ddata_len, uint8_t *iv)
{
	return aes_decrypt(EVP_aes_128_cbc(), edata, edata_len,
			key, iv, ddata, ddata_len);
}

int aes128_cbc_decrypt_no_padding(uint8_t *edata, int edata_len, uint8_t *key,
		uint8_t *ddata, int *ddata_len, uint8_t *iv)
{
	return __aes_decrypt(EVP_aes_128_cbc(), edata, edata_len,
			key, iv, ddata, ddata_len, 0);;
}

int aes256_cbc_decrypt_no_padding(uint8_t *edata, int edata_len, uint8_t *key,
		uint8_t *ddata, int *ddata_len, uint8_t *iv)
{
	return __aes_decrypt(EVP_aes_256_cbc(), edata, edata_len,
			key, iv, ddata, ddata_len, 0);;
}

int aes128_ecb_decrypt_no_padding(uint8_t *edata, int edata_len, uint8_t *key,
		uint8_t *ddata, int *ddata_len, uint8_t *iv)
{
	return __aes_decrypt(EVP_aes_128_ecb(), edata, edata_len,
                        key, iv, ddata, ddata_len, 0);
}

char *hex2str(const char *src, char *dst, int src_len, int dst_len)
{
	int i, k;
	char hex[] = "0123456789abcdef";
	if (dst_len < 2 * src_len + 1)
		return NULL;
	for (i = 0, k = 0; i < src_len; i++) {
		dst[k++] = hex[(src[i] >> 4) & 15];
		dst[k++] = hex[src[i] & 15];
	}
	dst[k] = '\0';
	return dst;
}

RSA *create_rsa_by_key(unsigned char *key, int public)
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

int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
	struct flock    lock;
	
	lock.l_type = type;             /* F_RDLCK, F_WRLCK, F_UNLCK */
	lock.l_start = offset;  /* byte offset, relative to l_whence */
	lock.l_whence = whence; /* SEEK_SET, SEEK_CUR, SEEK_END */
	lock.l_len = len;               /* #bytes (0 means to EOF) */
	
	return(fcntl(fd, cmd, &lock));
}

int grab_pidlock(const char *path)
{
	int pidfd;
	char line[64];

	if ((pidfd = open(path, O_RDWR | O_CREAT, 0666)) < 0)
		return -1;

	if (write_lock(pidfd, 0, SEEK_SET, 0) < 0) {
		if (errno == EACCES || errno == EAGAIN)
			app_log("unable to lock %s, program is running?\n", path);
		close(pidfd);
		return -1;
    	}

	snprintf(line, sizeof(line), "%ld\n", (long)getpid());
	ftruncate(pidfd, 0);
	write(pidfd, line, strlen(line));
	return pidfd;
}

char *rsa_public_encrypt_key(unsigned char *str, int *p_len, char *pubkey)
{
	char *p_en = NULL;
	RSA *p_rsa;
//	FILE *file;
	int flen, rsa_len;

	if ((p_rsa = create_rsa_by_key(pubkey, 1)) == NULL)
		goto out;

//	if ((file = fopen(path_key,"r")) == NULL)
//		return NULL;
	
//	if ((p_rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL)) == NULL)
//		goto out;

	flen = strlen((char *)str);
	rsa_len = RSA_size(p_rsa);
	p_en = malloc(rsa_len);
	if (!p_en)
		goto out;
	memset(p_en, 0, rsa_len);
	if (RSA_public_encrypt(flen, (unsigned char *)str, (unsigned char*)p_en, p_rsa, RSA_PKCS1_PADDING) < 0)
		goto out;
	RSA_free(p_rsa);
//	fclose(file);
	*p_len = rsa_len;
	return p_en;

out:
	if (p_en)
		free(p_en);
	if (p_rsa)
		RSA_free(p_rsa);
//	fclose(file);
	return NULL;
}
