/*
 * challenge.c
 * ptunnel is licensed under the BSD license:
 *
 * Copyright (c) 2004-2011, Daniel Stoedle <daniels@cs.uit.no>,
 * Yellow Lemon Software. All rights reserved.
 *
 * Copyright (c) 2017-2019, Toni Uhlig <matzeton@googlemail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * - Neither the name of the Yellow Lemon Software nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Contacting the author:
 * You can get in touch with me, Daniel Stødle (that's the Norwegian letter oe,
 * in case your text editor didn't realize), here: <daniels@cs.uit.no>
 *
 * The official ptunnel website is here:
 * <http://www.cs.uit.no/~daniels/PingTunnel/>
 *
 * Note that the source code is best viewed with tabs set to 4 spaces.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>

#include "challenge.h"
#include "options.h"
#include "md5.h"
#include "utils.h"

/* generate_challenge: Generates a random challenge, incorporating the current
 * local timestamp to avoid replay attacks.
 */
challenge_t *generate_challenge(void) {
	struct timeval  tt;
	challenge_t     *c;
	int             i;

	c = (challenge_t *) calloc(1, sizeof(challenge_t));
    assert(c != NULL);
	gettimeofday(&tt, 0);
	c->plain.sec      = tt.tv_sec;
	c->plain.usec_rnd = tt.tv_usec + pt_random();
	for (i=0;i<6;i++)
		c->plain.random[i] = pt_random();

	return c;
}

/* generate_response_md5: Generates a response to the given challenge. The response
 * is generated by combining the concatenating the challenge data with the
 * md5 digest of the password, and then calculating the MD5 digest of the
 * entire buffer. The result is stored in the passed-in challenge, overwriting
 * the challenge data.
 */
void generate_response_md5(challenge_plain_t *plain, challenge_digest_t *digest) {
	md5_byte_t  buf[sizeof(*plain) + kMD5_digest_size];
	md5_state_t state;

	digest->hash_type = HT_MD5;
	memcpy(buf, plain, sizeof(*plain));
	memcpy(&buf[sizeof(*plain)], opts.md5_password_digest, kMD5_digest_size);
	memset(plain, 0, sizeof(*plain));

	md5_init(&state);
	md5_append(&state, buf, sizeof(*plain) + kMD5_digest_size);
	md5_finish(&state, (md5_byte_t *) &digest->md5[0]);
}

/* validate_challenge_md5: Checks whether a given response matches the expected
 * response, returning 1 if validation succeeded, and 0 otherwise. Note that
 * overwriting the local challenge with the challenge result is not a problem,
 * as the data will not be used again anyway (authentication either succeeds,
 * or the connection is closed down).
 */
int validate_challenge_md5(challenge_t *local, challenge_digest_t *remote) {
	generate_response_md5(&local->plain, &local->digest);
	if (remote->hash_type == HT_MD5 &&
	    memcmp(&local->digest.md5[0], &remote->md5[0], sizeof(local->digest.md5)) == 0)
	{
		return 1;
	}
	return 0;
}

#ifdef ENABLE_SHA512
void generate_response_sha512(challenge_plain_t *plain, challenge_digest_t *digest)
{
    unsigned char buf[sizeof(*plain) + kSHA512_digest_size];

    digest->hash_type = HT_SHA512;
	memcpy(buf, plain, sizeof(*plain));
	memcpy(&buf[sizeof(*plain)], opts.sha512_password_digest, kSHA512_digest_size);
	memset(plain, 0, sizeof(*plain));

    SHA512(buf, sizeof(*plain) + kSHA512_digest_size, &digest->sha512[0]);
}

int validate_challenge_sha512(challenge_t *local, challenge_digest_t *remote)
{
    generate_response_sha512(&local->plain, &local->digest);

    if (remote->hash_type == HT_SHA512 &&
        memcmp(&local->digest.sha512[0], &remote->sha512[0], sizeof(local->digest.sha512)) == 0)
    {
        return 1;
    }
    return 0;
}
#endif /* ENABLE_SHA512 */
