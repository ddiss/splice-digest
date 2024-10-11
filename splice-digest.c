/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024 SUSE LLC.
 * Generate file digests using the kernel's AF_ALG API with splice().
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/if_alg.h>

#define SPLICE_MAX (1024 * 1024)

void print_hash_result(int outfd)
{
	uint8_t buf[256];
	int i;
	ssize_t got;

	got = recv(outfd, buf, sizeof(buf), 0);
	if (got < 0)
		err(-1, "recv hash result failed");

	for (i = 0; i < got; i++)
		fprintf(stdout, "%02x", buf[i]);
}

int main(int argc, char *argv[])
{
	const char *alg;
	const char *infile;
	int infd, sfd, outfd;
	size_t alg_len, insize;
	ssize_t got, l;
	struct stat st;
	int pipefds[2];
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
	};

	if (argc < 3)
		errx(-1, "Usage: %s algorithm infile", argv[0]);

	alg = argv[1];
	infile = argv[2];
	alg_len = strlen(alg);
	if (alg_len >= sizeof(sa.salg_name))
		errx(-1, "%s algorithm name too long", alg);

	infd = open(infile, O_RDONLY);
	if (infd < 0)
		err(-1, "open infile");

	if (fstat(infd, &st) < 0)
		err(-1, "%s stat failed", infile);
	if (!S_ISREG(st.st_mode))
		errx(-1, "%s not a regular file", infile);

	sfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (sfd < 0) {
		if (errno == EAFNOSUPPORT)
			errx(-1, "kernel AF_ALG support missing. "
			     "CONFIG_CRYPTO_USER_API_HASH required.\n");
		else
			err(-1, "AF_ALG socket");
	}

	/* +1 for zero-terminator */
	memcpy(sa.salg_name, alg, alg_len + 1);
	if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		if (errno == ENOENT)
			errx(-1, "AF_ALG bind(%s): hash missing. "
			     "See /proc/crypto hash algorithm list.\n", alg);
		else
			err(-1, "AF_ALG bind(%s)\n", alg);
	}

	outfd = accept(sfd, NULL, 0);
	if (outfd < 0)
		err(-1, "AF_ALG accept");

	/* can't splice directly from infd to the AF_ALG socket; pipe needed */
	if (pipe(pipefds) < 0)
		err(-1, "pipe");
	if (fcntl(pipefds[0], F_SETPIPE_SZ, SPLICE_MAX) < 0
	 || fcntl(pipefds[1], F_SETPIPE_SZ, SPLICE_MAX) < 0)
		fprintf(stderr, "F_SETPIPE_SZ(%d) failed, using default. "
			"Check /proc/sys/fs/pipe-max-size\n", SPLICE_MAX);

	for (insize = st.st_size; insize; insize -= got) {
		size_t tryl = (insize < SPLICE_MAX ? insize : SPLICE_MAX);

		l = splice(infd, NULL, pipefds[1], NULL, tryl, 0);
		if (l <= 0 || l > tryl)
			err(-1, "splice infile to pipe failed or bogus");

		got = splice(pipefds[0], NULL, outfd, NULL, l, SPLICE_F_MORE);
		if (got < 0)
			err(-1, "splice");
		else if (!got || got != l)
			errx(-1, "splice return: %zd, expected %zd", got, l);
	}

	fprintf(stdout, "Spliced %s(%s): ", alg, infile);
	print_hash_result(outfd);
	putc('\n', stdout);
}
