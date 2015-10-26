/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2015 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2015 Sandia Corporation. All rights reserved.
 *
 * Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
 * license for use of this work by or on behalf of the U.S. Government.
 * Export of this program may require a license from the United States
 * Government.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-type
 * license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *      Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 *      Neither the name of Sandia nor the names of any contributors may
 *      be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 *      Neither the name of Open Grid Computing nor the names of any
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 *      Modified source versions must be plainly marked as such, and
 *      must not be misrepresented as being the original software.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * auth.c
 *
 *  Created on: May 18, 2015
 *      Author: nichamon
 */

#include <time.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "auth.h"

#define _str(x) #x
#define str(x) _str(x)

static void default_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	fflush(stdout);
}

uint64_t ovis_auth_gen_challenge()
{
#define SBUFSIZE 256
	struct random_data rbuf;
	int c0, c1;
	c0 = c1 = 0;
	unsigned int seed;
	struct timespec t;
	uint64_t r = 0;
	char statebuf[SBUFSIZE];
	memset(&rbuf, 0, sizeof(rbuf));
	memset(statebuf, 0, sizeof(statebuf));
	clock_gettime(CLOCK_REALTIME, &t);
	seed = (unsigned int)t.tv_nsec;

	initstate_r(seed, &(statebuf[0]), sizeof(statebuf), &rbuf);
	random_r(&rbuf, &c0);
	random_r(&rbuf, &c1);
	r = ((uint64_t) c0) << 32;
	r ^= c1;
	return r;
}

struct ovis_auth_challenge *ovis_auth_pack_challenge(uint64_t challenge,
				struct ovis_auth_challenge *chl)
{
	chl->hi = htonl((uint32_t)(challenge >> 32));
	chl->lo = htonl((uint32_t)(challenge));
	return chl;
}

uint64_t ovis_auth_unpack_challenge(struct ovis_auth_challenge *chl)
{
	uint64_t challenge;
	challenge = (uint64_t)(ntohl(chl->hi));
	challenge = challenge << 32;
	challenge |= (uint64_t)ntohl(chl->lo);
	return challenge;
}

#define MAX_LINE_LEN 512

char *ovis_auth_get_secretword(const char *path, ovis_auth_log_fn_t log)
{
	int ret = 0;
	char *word, *s, *ptr;
	int perm;

	/*
	 * If path is NULL or
	 * path is not a full path,
	 * return NULL
	 */
	if (!path || path[0] != '/')
		return NULL;

	if (!log)
		log = default_log;

	struct stat pstat;
	if (stat(path, &pstat)) {
		ret = errno;
		log("Auth error: %s while trying to stat %s\n",
			strerror(errno), path);
		goto err;
	}

	perm = pstat.st_mode & 0077;

	if (perm) {
		log("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
		log("@     WARNING: UNPROTECTED SECRET WORD FILE!     @\n");
		log("Permissions %#04o for '%s' are too open.\n", perm, path);
		log("Your secret word file must NOT accessible by others.\n");
		log("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
		ret = EINVAL;
		goto err;
	}

	FILE *file = fopen(path, "r");
	if (!file) {
		ret = errno;
		log("Auth error(%d): '%m', while trying to open %s\n",
				errno, path);
		goto err;
	}

	char line[MAX_LINE_LEN];
	s = NULL;
	while (fgets(line, MAX_LINE_LEN, file)) {
		if ((line[0] == '#') || (line[0] == '\n'))
			continue;

		if (0 == strncmp(line, "secretword=", 11)) {
			/*
			 * Ignore the comment following the secret word.
			 */
			s = strtok_r(&line[11], "# \t\n", &ptr);
			if (!s) {
				log("Auth error: the secret word is an empty "
								"string.\n");
				ret = EINVAL;
				goto err0;
			}
			break;
		}
	}

	if (!s) {
		/* No secret word in the file */
		ret = ENOENT;
		goto err0;
	}

	if (strlen(s) < MIN_SECRET_WORD_LEN + 1 ||
			strlen(s) > MAX_SECRET_WORD_LEN + 1) {
		log("Auth error: the secret word must be longer than"
				"%d characters and at most %d characters.\n",
				MIN_SECRET_WORD_LEN, MAX_SECRET_WORD_LEN);
		ret = EINVAL;
		goto err0;
	}

	word = strdup(s);
	if (!word) {
		log("Auth error: Out of memory when trying to read the"
				"shared secret word.\n");
		ret = ENOMEM;
		goto err0;
	}

	fclose(file);
	return word;
err0:
	fclose(file);
err:
	errno = ret;
	return NULL;
}

char *ovis_auth_encrypt_password(const uint64_t challenge,
				const char *secretword)
{
	int rc;
	size_t len = strlen(secretword) + strlen(str(UINT64_MAX)) + 1;
	char *psswd = malloc(len);
	if (!psswd)
		return NULL;
	sprintf(psswd, "%" PRIu64 "%s", challenge, secretword);

	EVP_MD_CTX *mdctx;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;

	mdctx = EVP_MD_CTX_create();
	if (!mdctx)
		goto err0;

	if (0 == EVP_DigestInit_ex(mdctx, EVP_sha224(), NULL))
		goto err1;

	if (0 == EVP_DigestUpdate(mdctx, psswd, strlen(psswd)))
		goto err1;

	if (0 == EVP_DigestFinal_ex(mdctx, md_value, &md_len))
		goto err1;

	EVP_MD_CTX_destroy(mdctx);

	free(psswd);
	psswd = malloc(2 * md_len + 1);
	if (!psswd)
		return NULL;

	int i;
	for (i = 0; i < md_len; i++) {
		snprintf(&psswd[2 * i], 3, "%02x", md_value[i]);
	}
	return psswd;
err1:
	EVP_MD_CTX_destroy(mdctx);
err0:
	free(psswd);
	return NULL;
}
