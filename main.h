/*
 * Copyright (c) 2015 Mohit Goyal, Arjun Singh Bora
 * Copyright (c) 2015-2106 Stony Brook University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <time.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>

#include "common.h"

/* maximum payload size for the buffer */
#define MAX_PAYLOAD 1024

/* maximum buffer size */
#define PAGE_SIZE 4096

/* socket protocol number for MFE Network Services Protocol */
#define NETLINK_USER 31

int sock;
struct sockaddr_nl src_addr;
struct nlmsghdr *nlhdr = NULL;
struct iovec iov;
struct msghdr mesg;

struct job *job = NULL;

int callback_receiver(void)
{
	int err = 0;
	int ret = 0;
	char *ptr;

	sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
	if (sock < 0) {
		printf("Error: Fail to create socket\n");
		err = -1;
		goto out;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();

	bind(sock, (struct sockaddr *) &src_addr, sizeof(src_addr));

	nlhdr = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlhdr, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlhdr->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlhdr->nlmsg_pid = getpid();
	nlhdr->nlmsg_flags = 0;

	iov.iov_base = (void *) nlhdr;
	iov.iov_len = nlhdr->nlmsg_len;
	mesg.msg_iov = &iov;
	mesg.msg_iovlen = 1;

	recvmsg(sock, &mesg, 0);
	ret = strtol((char *) NLMSG_DATA(nlhdr), &ptr, 10);
	printf("\n------------------------------------------\n");
	printf("Job Status:\n%s", ptr);
	if (ret)
		printf("\nError: %s", strerror(-ret));
	printf("\n------------------------------------------\n");
	close(sock);

out:
	return err;
}

/*
 * @npwd: char string to store key after removing new line characater
 * return: the string after new line character removal
 *
 * Description:
 * Removing new line character from the key
 */
char *verify_psswd(char *pwd)
{
	int j = 0, k = 0;
	char *npwd;

	/* memory allocation for temp string */
	npwd = (char *) malloc(strlen(pwd) + 1);
	if (!npwd) {
		perror("Error");
		goto out;
	}

	/* check for new line character */
	while (pwd[j]) {
		if (pwd[j] != '\n') {
			npwd[k] = pwd[j];
			k++;
		}
		j++;
	}
	npwd[k] = '\0';

	strncpy(pwd, npwd, k);
	free(npwd);
	return pwd;

out:
	if (npwd)
		free(npwd);
	return NULL;
}
