/*
 * Copyright (c) 2015 Mohit Goyal, Arjun Singh Bora
 * Copyright (c) 2015-2106 Stony Brook University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "main.h"

int main(int argc, char *argv[])
{
	int err = 0, i = 0, index, op;
	int eflag = 0, dflag = 0, cflag = 0, xflag = 0, sflag = 0, aflag =
	    0;
	int pflag = 0, tflag = 0, hflag = 0, kflag = 0, lflag = 0, Rflag =
	    0;
	int rflag = 0, Cflag = 0, oflag = 0, nflag = 0;
	int job_id = 0, code = 0, files_given = 0, inflags = 0;
	int priority = 1, algo = 0;
	int pid;
	unsigned char digest[MD5_DIGEST_LENGTH];
	char *key = NULL, *verified_key = NULL, *algorithm = NULL;
	char *cwd = NULL, *path = NULL;

	/* process the command line arguments */
	while ((op = getopt(argc, argv, "edr:RC:cxsnoalk:p:t:h")) != -1) {
		switch (op) {
		/* option for remove one job */
		case 'r':
			rflag++;
			code = REMOVE;
			job_id = atoi(optarg);
			if (job_id <= 0) {
				fprintf(stderr, "Invalid Job ID\n");
				err = -EINVAL;
				goto out;
			}
			break;

		/* option for remove all jobs */
		case 'R':
			Rflag++;
			code = REMOVEALL;
			break;

		/* option for remove all jobs */
		case 'n':
			nflag++;
			break;

		/* option for remove all jobs */
		case 'o':
			oflag++;
			break;

		/* option for remove all jobs */
		case 'C':
			Cflag++;
			code = CHANGEPRIORITY;
			job_id = atoi(optarg);
			if (job_id <= 0) {
				fprintf(stderr, "Invalid Job ID\n");
				err = -EINVAL;
				goto out;
			}
			break;

		/* option to list jobs */
		case 'l':
			lflag++;
			code = LIST;
			break;

		/* option for encryption */
		case 'e':
			eflag++;
			code = ENCRYPTION;
			break;

		/* option for decryption */
		case 'd':
			dflag++;
			code = DECRYPTION;
			break;

		/* option for compression */
		case 'c':
			cflag++;
			code = COMPRESSION;
			break;

		/* option for extraction */
		case 'x':
			xflag++;
			code = EXTRACTION;
			break;

		/* option for checksum */
		case 's':
			sflag++;
			code = CHECKSUM;
			break;

		/* option for concatenation */
		case 'a':
			aflag++;
			code = CONCATENATE;
			break;

		/* option for password */
		case 'k':
			kflag++;
			if ((strlen(optarg) < 6)) {
				fprintf(stderr,
					"Password length should be greater than 6\n");
				err = -EINVAL;
				goto out;
			}
			key = (char *) optarg;
			break;

		/* option for priority */
		case 'p':
			pflag++;
			priority = atoi(optarg);
			break;

		/* option for encryption */
		case 't':
			tflag++;
			algorithm = (char *) optarg;
			if (!strcmp("blowfish", algorithm)
			    && (dflag || eflag))
				algo = BLOWFISH;
			else if (!strcmp("aes", algorithm)
				 && (dflag || eflag))
				algo = AES;
			else if (!strcmp("md5", algorithm) && sflag)
				algo = MD_5;
			else if (!strcmp("sha1", algorithm) && sflag)
				algo = SHA1;
			else if (!strcmp("deflate", algorithm)
				 && (xflag || cflag))
				algo = DEFLATE;
			else {
				fprintf(stderr,
					"Incorrect algorithm entered\n");
				err = -EINVAL;
				goto out;
			}
			break;

		/* option for help */
		case 'h':
			hflag++;
			break;

		/* other unknown arguments, if entered */
		case '?':
			fprintf(stderr, "Unknown option character\n");
			err = -EINVAL;
			goto out;

		default:
			err = -EINVAL;
			goto out;
		}
	}

	if (hflag) {
		printf("Usage:\n./main {-e}{-d}{-c}{-x}{-s}{-a}{-l}{-r}{-R}");
		printf("{-C} input_file(s) output_file\n       ");
		printf("[-k key -n -o -l -t <algorithm> -p <priority, ");
		printf("1..%d> -h]\n\n", MAX_PRIORITY);
		printf("-p, -t, -n and -o flags are optional.\n");
		printf("-p => give priority (1 to %d) to job, ", MAX_PRIORITY);
		printf("default priority is %d.\n", DEFAULT_PRIORITY);
		printf("-t => algorithm for compression/uncompression/");
		printf("encryption/decryption.\n");
		printf("-n => if this flag is on, input file will be ");
		printf("deleted.\n-o => if this flag is on, input file will ");
		printf("contain the output data. No separate output file ");
		printf("should be given.\n\n");
		printf("Encryption : ./main -e -k <password> ");
		printf("<input filename> <output filename> -t <cipher algo>\n");
		printf("Decryption : ./main -d -k <password> ");
		printf("<input filename> <output filename> -t <cipher algo>\n");
		printf("Compress   : ./main -c -t <compression_type> ");
		printf("<input filename> <output filename>\n");
		printf("Uncompress : ./main -x -t <compression_type> ");
		printf("<input filename> <output filename>\n");
		printf("CHECKSUM   : ./main -s -t <hashing_algo> ");
		printf("<input filename>\n");
		printf("Concatenate: ./main -a <input file 1> <input file 2>");
		printf(".....<input file n> <output file>\n\n");
		printf("Remove job      : ./main -r <Job ID>\n");
		printf("Remove all jobs : ./main -R\n");
		printf("Change priority : ./main -C <Job ID> -p ");
		printf("<new priority>\n\n");
		printf("-h :  to provide a helpful usage message.\n\n");
		exit(0);
	}

	for (index = optind; index < argc; index++)
		files_given++;

	inflags = (sflag && files_given != 1);
	inflags |= (aflag && (files_given < 3 || files_given > MAX_FILES));
	inflags |= ((xflag || cflag || dflag || eflag) && nflag
		    && files_given != 2);
	inflags |= ((xflag || cflag || dflag || eflag) && oflag
		    && files_given != 1);
	inflags |= ((xflag || cflag || dflag || eflag)
		    && (!oflag && !nflag) && files_given != 2);
	inflags |= (Cflag && (tflag || !pflag) && files_given != 0);
	inflags |= (((rflag || Rflag) && (pflag || tflag))
		    && files_given != 0);

	if (inflags) {
		fprintf(stderr, "Invalid number of arguments. ");
		fprintf(stderr,
			"Please see the command usage with -h\n");
		err = -EINVAL;
		goto out;
	}

	if (eflag + dflag + cflag + xflag + sflag + aflag + Cflag + rflag +
	    Rflag > 1) {
		fprintf(stderr,
			"Error : Only one operation at a time is allowed\n");
		err = -EINVAL;
		goto out;
	}

	if ((eflag || dflag) && !kflag) {
		fprintf(stderr, "Key missing for encryption/decryption, ");
		fprintf(stderr,
			"Please see the command usage with -h\n");
		err = -EINVAL;
		goto out;
	}

	inflags |= (!(eflag || dflag)) && kflag;
	inflags |= aflag && tflag;
	inflags |= oflag && nflag;
	inflags |= (!(eflag || dflag || cflag || xflag)
		    && (nflag || oflag));

	if (inflags) {
		fprintf(stderr, "Incompatiable flags together. ");
		fprintf(stderr,
			"Please see the command usage with -h\n");
		err = -EINVAL;
		goto out;
	}

	if (priority > 10 || priority < 1) {
		fprintf(stderr, "Invalid priority\n");
		err = -EINVAL;
		goto out;
	}

	/* memory allocation for job */
	job = malloc(sizeof(struct job));
	if (job == NULL) {
		printf("Error: Failed to allocate memory for job\n");
		err = -ENOMEM;
		goto out;
	}

	/* setting default values for job parameters */
	job->id = 0;
	job->code = 0;
	job->priority = 0;
	job->keylen = 0;
	job->key = NULL;
	job->infile_count = 0;
	job->infile = NULL;
	job->algo = 0;
	job->nflag = 0;
	job->oflag = 0;

	/* Filling job struct */
	job->id = job_id;
	job->code = code;
	job->algo = algo;
	job->nflag = nflag;
	job->oflag = oflag;

	if (!pflag)
		priority = DEFAULT_PRIORITY;
	job->priority = priority;

	if (!lflag) {
		if (key) {
			/* check the password for new line character */
			verified_key = verify_psswd(key);
			/*
			 * MD5 encryption for encrypting the password
			 */
			job->key = (char *) malloc(SIZE);
			MD5((unsigned char *)verified_key, strlen(verified_key),
			digest);
			memcpy(job->key, digest, SIZE);
		} else
			job->key = key;
	} else {
		job->key = (char *) malloc(PAGE_SIZE);
		memset(job->key, 0, PAGE_SIZE);
	}
	if (key)
		job->keylen = SIZE;

	job->infile_count = files_given;
	if (!lflag) {
		job->infile =
		    (char **) malloc(sizeof(char *) * job->infile_count);
		cwd = getcwd(path, PATH_MAX + 1);
		for (index = optind, i = 0; index < argc; index++, i++) {
			if (argv[index][0] != '/') {
				job->infile[i] = (char *) malloc(PATH_MAX + 1);
				strncpy(job->infile[i], cwd, strlen(cwd));
				strcat(job->infile[i], "/");
				strcat(job->infile[i], argv[index]);
			} else {
				job->infile[i] = (char *) malloc(NAME_MAX + 1);
				strcat(job->infile[i], argv[index]);
			}
		}
	}

	/* create child process to receive message from kernel */
	if (job->code != LIST && job->code != CHANGEPRIORITY
	    && job->code != REMOVE && job->code != REMOVEALL) {
		pid = fork();
		job->pid = pid;
		if (pid == 0) {
			callback_receiver();
			exit(0);
		} else
			usleep(100000);
	}

	err = syscall(__NR_submitjob, (void *) job, sizeof(*job));
	if (err == 0) {
		if (lflag)
			printf("\n%s\n", job->key);
		else if (Cflag) {
			printf("-------------------------------\n");
			printf("Priority changed of job ID: %d\n", job->id);
			printf("-------------------------------\n");
		} else if (!rflag && !Rflag) {
			printf("--------------------------\n");
			printf("Job submitted with ID: %d\n", job->id);
			printf("--------------------------\n");
		}
		if (job->priority == 0) {
			printf("Warning : Job placed in wait queue, ");
			printf("please slow down your speed\n");
		}
	} else
		perror("Error");

out:
	/* memory deallocation */
	if (job != NULL)
		for (i = 0; i < job->infile_count; i++)
			if (job->infile[i] != NULL)
				free(job->infile[i]);

	if (job != NULL && job->infile != NULL)
		free(job->infile);

	if (lflag && job != NULL && job->key != NULL)
		free(job->key);

	if (job != NULL)
		free(job);

	return err;
}
