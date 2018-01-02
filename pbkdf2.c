/*
 * Copyright (c) 2014-2016 Thomas Hurst.
 * Copyright (c) 2016-2018 LastPass.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "pbkdf2.h"
#include <string.h>
#include <openssl/hmac.h>

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define ERR_IFZERO(x) if (!(x)) goto err
#define ERR_LABEL err:
#else
#define ERR_IFZERO(x) (x)
#define ERR_LABEL
#endif

int fallback_pkcs5_pbkdf2_hmac(const char *pass, size_t pass_len,
	const unsigned char *salt, size_t salt_len, unsigned int iterations,
	const EVP_MD *digest, size_t key_len, unsigned char *output)
{
	HMAC_CTX *ctx;
	unsigned char *out = output;
	unsigned int iter = 1, count = 1;
	unsigned int cp_len, i, ret = 0;
	unsigned int key_left = key_len;
	unsigned int md_len = EVP_MD_size(digest);

	if (md_len == 0)
		return 0;

	unsigned char tmp_md[md_len];

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	HMAC_CTX real_ctx;
	ctx = &real_ctx;
	HMAC_CTX_init(ctx);
#else
	ctx = HMAC_CTX_new();
	if (!ctx)
		return 0;
#endif

	ERR_IFZERO(HMAC_Init_ex(ctx, pass, pass_len, digest, NULL));

	while (key_left) {
		cp_len = min(key_left, md_len);

		unsigned char c[4];
		c[0] = (count >> 24) & 0xff;
		c[1] = (count >> 16) & 0xff;
		c[2] = (count >> 8) & 0xff;
		c[3] = (count) & 0xff;

		ERR_IFZERO(HMAC_Init_ex(ctx, NULL, 0, digest, NULL));
		ERR_IFZERO(HMAC_Update(ctx, salt, salt_len));
		ERR_IFZERO(HMAC_Update(ctx, c, 4));
		ERR_IFZERO(HMAC_Final(ctx, tmp_md, NULL));
		memcpy(out, tmp_md, cp_len);

		for (iter=1; iter < iterations; iter++) {
			ERR_IFZERO(HMAC_Init_ex(ctx, NULL, 0, digest, NULL));
			ERR_IFZERO(HMAC_Update(ctx, tmp_md, md_len));
			ERR_IFZERO(HMAC_Final(ctx, tmp_md, NULL));

			for (i = 0; i < cp_len; i++) {
				out[i] ^= tmp_md[i];
			}
		}

		key_left -= cp_len;
		out += cp_len;
		count++;
	}
	ret = 1;

ERR_LABEL
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	HMAC_CTX_cleanup(ctx);
#else
	HMAC_CTX_free(ctx);
#endif
	return ret;
}
