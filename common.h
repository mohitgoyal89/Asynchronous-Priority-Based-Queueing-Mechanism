/*
 * Copyright (c) 2015 Mohit Goyal, Arjun Singh Bora
 * Copyright (c) 2015-2106 Stony Brook University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* submitjob system call */
#define __NR_submitjob 359

/* Macro for number of files */
#define MAX_FILES 10

/* Macro for highest priority */
#define MAX_PRIORITY 10

/* Macro for default priority */
#define DEFAULT_PRIORITY 5

/* Macro for size of key to be used */
#define SIZE 16

/* Macro for Debugging */
/* #define DEBUG */

/* Enumeration for operations that can be performed */
#define FOREACH_OPERATION(OPERATION)	\
		OPERATION(ENCRYPTION)	\
		OPERATION(DECRYPTION)	\
		OPERATION(COMPRESSION)	\
		OPERATION(EXTRACTION)	\
		OPERATION(CHECKSUM)	\
		OPERATION(CONCATENATE)	\
		OPERATION(LIST)	\
		OPERATION(CHANGEPRIORITY)	\
		OPERATION(REMOVE)	\
		OPERATION(REMOVEALL)	\

#define GENERATE_ENUM(ENUM) ENUM,
#define GENERATE_STRING(STRING) #STRING,

enum OPERATION_ENUM {
	FOREACH_OPERATION(GENERATE_ENUM)
};

/* Enumeration for algorithms */
enum {
	AES,
	BLOWFISH,
	MD_5,
	SHA1,
	DEFLATE
};

/* structure for job to be done */
struct job {
	int id;
	int code;
	int priority;
	pid_t pid;
	int keylen;
	char *key;
	int infile_count;
	char **infile;
	int algo;
	int nflag;
	int oflag;
};
