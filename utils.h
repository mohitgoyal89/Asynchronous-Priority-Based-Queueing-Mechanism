/*
 * Copyright (c) 2015 Mohit Goyal, Arjun Singh Bora
 * Copyright (c) 2015-2106 Stony Brook University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "sys_submitjob.h"

/* default cipher initialization vector value */
#define CEPH_IV "aykahsmamstihom"

/**
 * checking if the infile and outfile are valid
 * check for read and write permissions and if files are same
 **/
int is_file_valid(char *infile)
{
	int err = 0;
	struct file *infilp = NULL;

	infilp = filp_open(infile, O_RDONLY, 0);
	/* check for validity of file */
	if (!infilp || IS_ERR(infilp)) {
		pr_err("Error: Infile does not exist\n");
		err = (int) PTR_ERR(infilp);
		goto out;
	}

	/* checks for read permission of file */
	if (!infilp->f_op->read) {
		pr_err("Error: Read not allowed by file system\n");
		err = -EACCES;
		goto out;
	}

	if (!(infilp->f_mode & FMODE_READ)) {
		pr_err("Error: Infile inaccessible to read\n");
		err = -EIO;
		goto out;
	}

out:
	if (infilp)
		if (!IS_ERR(infilp))
			filp_close(infilp, NULL);
	return err;
}

/**
 * function to encrypt the buf using the key and initialization vector
 **/
int encrypt(void *in_buf, int in_buf_len, void *out_buf, int *out_buf_len,
	    void *key, int keylen, char *cipher)
{
	int err = 0, ivsize;
	struct scatterlist in_sg[1], out_sg[1];
	void *iv = NULL;
	struct crypto_blkcipher *tfm = NULL;
	struct blkcipher_desc desc;

	if (cipher == NULL) {
		pr_err("Error: Encryption cipher can not be null\n");
		err = -EINVAL;
		goto out;
	}

	/* setting the transformation */
	tfm = crypto_alloc_blkcipher(cipher, 0, CRYPTO_ALG_ASYNC);

	err = crypto_blkcipher_setkey(tfm, key, keylen);
	if (err) {
		pr_err("Error: Failed to set encryption key\n");
		goto out;
	}

	/* set descriptor's transformation and flags */
	desc.tfm = tfm;
	desc.flags = 0;

	if (!(desc.tfm) || IS_ERR(desc.tfm)) {
		pr_err("Error: Fail to load transformation for encryption\n");
		err = -PTR_ERR(desc.tfm);
		goto out;
	}

	/* scatterlist initializations with in buf and out buf */
	sg_init_one(in_sg, in_buf, in_buf_len);
	sg_init_one(out_sg, out_buf, in_buf_len);

	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);

	/* set iv to page number and inode number */
	memcpy(iv, (u8 *) CEPH_IV, ivsize);

	err = crypto_blkcipher_encrypt(&desc, out_sg, in_sg, in_buf_len);
	*out_buf_len = in_buf_len;
	crypto_free_blkcipher(tfm);

	if (err < 0) {
		pr_err("Error: Encryption failed\n");
		err = -EFAULT;
		goto out;
	}

out:
	return err;
}

/**
 * function to decrypt the buf using the key and initialization vector
 **/
int decrypt(void *in_buf, int in_buf_len, void *out_buf, int *out_buf_len,
	    void *key, int keylen, char *cipher)
{
	int err = 0, ivsize;
	struct scatterlist in_sg[1], out_sg[1];
	void *iv = NULL;
	struct crypto_blkcipher *tfm;
	struct blkcipher_desc desc;

	if (cipher == NULL) {
		pr_err("Error: Decryption cipher can not be null\n");
		err = -EINVAL;
		goto out;
	}

	/* setting the transformation */
	tfm = crypto_alloc_blkcipher(cipher, 0, CRYPTO_ALG_ASYNC);

	err = crypto_blkcipher_setkey((void *) tfm, key, keylen);
	if (err) {
		pr_err("Error: Failed to set encryption key\n");
		goto out;
	}

	/* set descriptors transformation and flags */
	desc.tfm = tfm;
	desc.flags = 0;

	if (!(desc.tfm) || IS_ERR(desc.tfm)) {
		pr_err("Error: Fail to load transformation for decryption\n");
		err = -PTR_ERR(desc.tfm);
		goto out;
	}

	/* scatterlist initializations with in buf and out buf */
	sg_init_one(in_sg, in_buf, in_buf_len);
	sg_init_one(out_sg, out_buf, in_buf_len);

	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);

	/* set iv to page number and inode number */
	memcpy(iv, (u8 *) CEPH_IV, ivsize);

	err = crypto_blkcipher_decrypt(&desc, out_sg, in_sg, in_buf_len);
	*out_buf_len = in_buf_len;
	crypto_free_blkcipher(tfm);

	if (err < 0) {
		pr_err("Error: Decryption failed\n");
		err = -EFAULT;
		goto out;
	}

out:
	return err;
}

/**
 * function to hash the key using md5 encryption
 **/
int key_hashing(unsigned char *in_buf, unsigned char *out_buf,
		int in_buf_len)
{
	int err = 0;
	struct scatterlist sg[1];

	struct crypto_hash *tfm;
	struct hash_desc desc;

	/* setting the transformation */
	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);

	desc.tfm = tfm;
	desc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	if (!(desc.tfm) || IS_ERR(desc.tfm)) {
		pr_err("Error: Fail to load transformation for encryption\n");
		err = -PTR_ERR(desc.tfm);
		goto out;
	}

	/* scatterlist initialization with in buf */
	sg_init_one(sg, in_buf, in_buf_len);

	err = crypto_hash_digest(&desc, sg, in_buf_len, out_buf);

	if (err < 0) {
		pr_err("Error: Fail while hashing the key\n");
		err = -EFAULT;
		goto out;
	}

out:
	return err;
}

/**
 * writing len bytes from buf into outfilp
 **/
int write_file(struct file *outfilp, void *buf, int len, int offset)
{
	int err = 0, bytes = 0;
	mm_segment_t oldfs;

	/* check for validity of file */
	if (!outfilp || IS_ERR(outfilp)) {
		pr_err("Error: Outfile does not exist\n");
		err = (int) PTR_ERR(outfilp);
		goto out;
	}

	/* check for write permission of file */
	if (!outfilp->f_op->write) {
		pr_err("Error: Write not allowed by file system\n");
		err = -EACCES;
		goto out;
	}

	/* check for write permission of file */
	if (!(outfilp->f_mode & FMODE_WRITE)) {
		pr_err("Error: Outfile inaccessible to write\n");
		err = -EIO;
		goto out;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytes = vfs_write(outfilp, buf, len, &outfilp->f_pos);
	set_fs(oldfs);

	return bytes;

out:
	return err;
}

/**
 * reading len bytes from infilp into buf
 **/
int read_file(struct file *infilp, void *buf, int len, int offset)
{
	int err = 0, bytes = 0;
	mm_segment_t oldfs;

	/* check for validity of file */
	if (!infilp || IS_ERR(infilp)) {
		pr_err("Error: Infile does not exist\n");
		err = (int) PTR_ERR(infilp);
		goto out;
	}

	/* check for read permission of file */
	if (!infilp->f_op->read) {
		pr_err("Error: Read not allowed by file system\n");
		err = -EACCES;
		goto out;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytes = vfs_read(infilp, buf, len, &infilp->f_pos);
	set_fs(oldfs);

	return bytes;

out:
	return err;
}

/**
 * rename file with dentry temp_dentry to file with dentry out_dentry
 **/
int rename_file(struct dentry *temp_dentry, struct dentry *out_dentry)
{
	int err = 0;

	lock_rename(temp_dentry->d_parent, out_dentry->d_parent);
	err = vfs_rename(temp_dentry->d_parent->d_inode,
			 temp_dentry,
			 out_dentry->d_parent->d_inode,
			 out_dentry, NULL, 0);

	/* check for rename success or not */
	if (err < 0) {
		pr_err("Error: Fail to rename temp file\n");
		err = -EFAULT;
	}
	unlock_rename(temp_dentry->d_parent, out_dentry->d_parent);

	return err;
}

/**
 * deleting unused file whose dentry is 'dentry'
 **/
int delete_file(struct dentry *dentry)
{
	int err = 0;

	if (!IS_ERR(dentry)) {
		mutex_lock(&dentry->d_parent->d_inode->i_mutex);
		if (vfs_unlink(dentry->d_parent->d_inode, dentry, NULL) <
		    0) {
			pr_err("Error: Unlink of file failed\n");
			err = -EFAULT;
		}
		mutex_unlock(&dentry->d_parent->d_inode->i_mutex);
	} else
		err = -EBADF;

	return err;
}

/*
 * concatenate files
 * @infile    : pointer to the array of pointers storing file names
 * file_count : number of input files to concatenate
 * @job_id    : job ID of this operation
 */
int concatenate_file(char **infile, int file_count, int job_id)
{
	int err = 0, i = 0;
	int bytes_to_read = 0;
	int read_bytes = 0, written_bytes = 0;
	char ids[10];
	char *temp_name = NULL;
	struct file *infilp[MAX_FILES] = { NULL };
	struct file *temp_filp = NULL, *outfilp = NULL;
	struct dentry *out_dentry = NULL, *temp_dentry = NULL;
	void *in_buf = NULL, *out_buf = NULL;

	for (i = 0; i < file_count - 1; i++) {
		err = is_file_valid(infile[i]);
		if (err < 0) {
			pr_err("Error: Infile %d not valid\n", i);
			goto out;
		}

		infilp[i] = filp_open(infile[i], O_RDONLY, 0);
		if (!infilp[i] || IS_ERR(infilp[i])) {
			pr_err("Error: Input file cannot be accessed\n");
			err = (int) PTR_ERR(infilp[i]);
			goto out;
		}

	}

	temp_name =
	    kzalloc(strlen(infile[file_count - 1]) + 10, __GFP_WAIT);
	sprintf(ids, ".%d", job_id);
	strcat(temp_name, infile[file_count - 1]);
	strcat(temp_name, ids);

	temp_filp = filp_open(temp_name, O_WRONLY | O_CREAT | O_TRUNC,
			      infilp[0]->f_path.dentry->d_inode->i_mode);
	if (!temp_filp || IS_ERR(temp_filp)) {
		pr_err("Error: Temp file cannot be accessed\n");
		err = (int) PTR_ERR(temp_filp);
		goto out;
	}
	temp_dentry = temp_filp->f_path.dentry;

	bytes_to_read = PAGE_SIZE;

	in_buf = kzalloc(bytes_to_read, __GFP_WAIT);
	if (!in_buf) {
		err = -ENOMEM;
		goto out;
	}

	out_buf = kzalloc(bytes_to_read, __GFP_WAIT);
	if (!out_buf) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < file_count - 1; i++) {
repeat:
		read_bytes =
		    read_file(infilp[i], in_buf, bytes_to_read, 0);
		if (read_bytes < 0) {
			pr_err("Error : Read Failed\n");
			err = read_bytes;
			goto out;
		}

		written_bytes =
		    write_file(temp_filp, in_buf, read_bytes, 0);
		if (written_bytes < 0) {
			pr_err("Error : Write Failed\n");
			err = written_bytes;
			goto out;
		}

		if (read_bytes == PAGE_SIZE)
			goto repeat;
	}

	outfilp =
	    filp_open(infile[file_count - 1], O_WRONLY | O_CREAT | O_TRUNC,
		      infilp[0]->f_path.dentry->d_inode->i_mode);
	if (!outfilp || IS_ERR(outfilp)) {
		pr_err("Error: Outfile does not exist\n");
		err = (int) PTR_ERR(outfilp);
		goto out;
	}

	out_dentry = outfilp->f_path.dentry;

	for (i = 0; i < file_count - 1; i++) {
		if (infilp[i]->f_inode->i_ino == outfilp->f_inode->i_ino) {
			pr_err
			    ("Error : Output file is same with infile %d\n",
			     i);
			err = -EINVAL;
			goto out;
		}
	}

out:
	if (err < 0) {
		if (temp_dentry != NULL)
			delete_file(temp_dentry);
	} else {
		if (temp_dentry != NULL && out_dentry != NULL)
			rename_file(temp_dentry, out_dentry);
	}

	if (in_buf != NULL)
		kfree(in_buf);

	if (out_buf != NULL)
		kfree(out_buf);

	if (temp_name != NULL)
		kfree(temp_name);

	for (i = 0; i < file_count - 1; i++) {
		if (infile[i] && IS_ERR(infile[i]))
			filp_close(infilp[i], NULL);
	}

	if (temp_filp && !IS_ERR(temp_filp))
		filp_close(temp_filp, NULL);

	return err;
}

/*
 * Wrapper function for encryption/decryption
 * @infile : pointer to input filename string
 * @outfile: pointer to output filename string
 * @key    : pointer to key string
 * @key_len: length of the key
 * @code   : int code of the operation
 *			 0 -> Encryption, 1-> Decryption
 * @algo   : int code for algorithm to be used
 *			 0->aes, 2->blowfish
 * @job_id : job ID of this operation
 * @oflag  : input file will be overwritten with the output,
 *			 if oflag is set; outfile is not required
 * @nflag  : input file will be removed, if nflag is set
 */
int endecrypt_file(char *infile, char *outfile, char *key, int key_len,
		   int code, int algo, int job_id, int oflag, int nflag)
{
	int err = 0;
	int keylen = 16;
	char ids[10], bytes[2];
	int i = 0, hash_len = 0;
	int read_ret = 0, write_ret = 0, encrypt_ret = 0, read_offset =
	    0, write_offset = 0;
	int enc_ret = 0, dec_ret = 0;
	int infile_size = 0, bytes_to_write = 0, bytes_to_read = 0;
	char *hashed_key = NULL, *cipher = NULL;
	char *temp_name = NULL;
	struct file *infilp = NULL, *temp_filp = NULL, *outfilp = NULL;
	struct inode *in_inode = NULL;
	struct dentry *in_dentry = NULL, *out_dentry = NULL, *temp_dentry =
	    NULL;
	void *in_buf = NULL, *out_buf = NULL;

	hash_len = keylen;
	hashed_key = kzalloc(hash_len, __GFP_WAIT);
	if (hashed_key == NULL) {
		pr_err
		    ("Error: Failed to allocate memory for hashed key\n");
		err = -ENOMEM;
		goto out;
	}

	err = key_hashing(key, hashed_key, hash_len);
	if (err < 0) {
		pr_err("Error: Fail to encrypt key\n");
		goto out;
	}

	/* checking all the params for correctness while debugging */
	#ifdef DEBUG
	pr_debug("infile - %s\n", infile);
	pr_debug("code - %d\n", code);
	pr_debug("key - %s\n", key);
	pr_debug("keylen - %d\n", keylen);
	pr_debug("hashed_key - %s\n", hashed_key);
	pr_debug("hash_len - %d\n", hash_len);
	#endif

	err = is_file_valid(infile);
	if (err < 0) {
		pr_err("Error: Infile not valid\n");
		goto out;
	}

	infilp = filp_open(infile, O_RDONLY, 0);
	if (!infilp || IS_ERR(infilp)) {
		pr_err("Error: Infile does not exist\n");
		err = (int) PTR_ERR(infilp);
		goto out;
	}

	in_dentry = infilp->f_path.dentry;

	temp_name = kzalloc(strlen(infile) + 10, __GFP_WAIT);
	if (!temp_name) {
		err = -ENOMEM;
		goto out;
	}

	sprintf(ids, ".%d", job_id);
	strcat(temp_name, infile);
	strcat(temp_name, ids);

	temp_filp =
	    filp_open(temp_name, O_WRONLY | O_CREAT | O_TRUNC,
		      infilp->f_path.dentry->d_inode->i_mode);
	if (!temp_filp || IS_ERR(temp_filp)) {
		pr_err("Error: Temp file cannot be accessed\n");
		err = (int) PTR_ERR(temp_filp);
		goto out;
	}

	temp_dentry = temp_filp->f_path.dentry;

	/* check if infile and temp file are are same */
	if (((infilp->f_path.dentry->d_inode->i_ino) ==
	     (temp_filp->f_path.dentry->d_inode->i_ino))
	    && ((infilp->f_path.dentry->d_inode->i_sb) ==
		(temp_filp->f_path.dentry->d_inode->i_sb))) {
		pr_err
		    ("Error: Infile and temp file are pointing to same file\n");
		err = -EINVAL;
		goto out;
	}

	in_inode = infilp->f_path.dentry->d_inode;
	infile_size = i_size_read(in_inode);

	if (infile_size < PAGE_SIZE)
		bytes_to_read = infile_size;
	else
		bytes_to_read = PAGE_SIZE;

	/* memory alloctation for in buffer */
	in_buf = kzalloc(bytes_to_read, __GFP_WAIT);
	if (!in_buf) {
		err = -ENOMEM;
		goto out;
	}

	/* memory alloctation for out buffer */
	out_buf = kzalloc(bytes_to_read, __GFP_WAIT);
	if (!out_buf) {
		err = -ENOMEM;
		goto out;
	}

	if (algo == BLOWFISH) {
		sprintf(bytes, "%d", BLOWFISH);
		cipher = "ctr(blowfish)";
	} else {
		sprintf(bytes, "%d", AES);
		cipher = "ctr(aes)";
	}

	/* writing encryption key to outfile as preamble */
	if (code == ENCRYPTION) {
		write_ret =
		    write_file(temp_filp, bytes, strlen(bytes),
			       write_offset);
		if (write_file < 0) {
			pr_err
			    ("Error: Fail while writing algo in outfile\n");
			err = -EIO;
			goto out;
		}
		temp_filp->f_pos = write_ret;
		write_offset += write_ret;

		write_ret =
		    write_file(temp_filp, hashed_key, hash_len,
			       write_offset);
		if (write_ret < 0) {
			pr_err("Error: Fail to write encryption key in outfile\n");
			err = -EIO;
			goto out;
		}
		write_offset += write_ret;
		bytes_to_write = infile_size;
	}

	/* reading preambled encryption key from infile */
	if (code == DECRYPTION) {
		read_ret =
		    read_file(infilp, in_buf, strlen(bytes), read_offset);
		if (read_ret < 0) {
			pr_err("Error: Fail to read infile\n");
			err = read_ret;
			goto out;
		}
		for (i = 0; i < read_ret; i++) {
			if ((((char *) in_buf)[i]) != (bytes[i])) {
				pr_err
				    ("Error: Decryption algo is not valid\n");
				err = -EINVAL;
				goto out;
			}
		}
		infilp->f_pos = read_ret;
		bytes_to_write = infile_size - read_ret;

		read_ret =
		    read_file(infilp, in_buf, hash_len, read_offset);
		if (read_ret < 0) {
			pr_err("Error: Fail to read infile\n");
			err = read_ret;
			goto out;
		}

		for (i = 0; i < SIZE; i++) {
			if ((((char *) in_buf)[i]) != (hashed_key[i])) {
				pr_err
				    ("Error: Decryption key is not valid\n");
				err = -EINVAL;
				goto out;
			}
		}
		read_offset = 0;
		bytes_to_write = bytes_to_write - hash_len;
	}

	while (bytes_to_write > 0) {

		/* reading bytes_to_read bytes from infile into in_buf */
		read_ret =
		    read_file(infilp, in_buf, bytes_to_read, read_offset);

		if (read_ret < 0) {
			pr_err("Error: Fail to read infile\n");
			err = read_ret;
			goto out;
		} else if (read_ret == bytes_to_read) {
			read_offset += 1;
			bytes_to_write -= read_ret;
		} else {
			read_offset += 1;
			bytes_to_write -= read_ret;
		}

		if (code == ENCRYPTION) {
			/* encrypting read_ret bytes from in_buf to out_buf */
			enc_ret =
			    encrypt((char *) in_buf, read_ret,
				    (char *) out_buf, &encrypt_ret, key,
				    keylen, cipher);
			if (enc_ret < 0) {
				pr_err("Error: File encryption fail\n");
				goto out;
			}
		}
		if (code == DECRYPTION) {
			/* decrypting read_ret bytes from in_buf to out_buf */
			dec_ret =
			    decrypt((char *) in_buf, read_ret,
				    (char *) out_buf, &encrypt_ret, key,
				    keylen, cipher);
			if (dec_ret < 0) {
				pr_err("Error: File decryption fail\n");
				goto out;
			}
		}

		/* writing encrypt_ret bytes from out_buf into temp_file */
		write_ret =
		    write_file(temp_filp, out_buf, encrypt_ret,
			       write_offset);

		if (write_ret < 0) {
			pr_err("Error: Fail to write\n");
			err = write_ret;
			goto out;
		} else {
			write_offset += write_ret;
		}
	}

	if (outfile) {
		outfilp =
		    filp_open(outfile, O_WRONLY | O_CREAT | O_TRUNC,
			      infilp->f_path.dentry->d_inode->i_mode);
		if (!outfilp || IS_ERR(outfilp)) {
			pr_err("Error: Outfile does not exist\n");
			err = (int) PTR_ERR(outfilp);
			goto out;
		}

		out_dentry = outfilp->f_path.dentry;

		if (infilp->f_inode->i_ino == outfilp->f_inode->i_ino) {
			pr_err
			    ("Error : Output file is same with input file\n");
			err = -EINVAL;
			goto out;
		}
	}

out:
	if (err < 0) {
		if (temp_dentry != NULL)
			delete_file(temp_dentry);
	} else {
		if (nflag) {
			if (temp_dentry != NULL && out_dentry != NULL)
				rename_file(temp_dentry, out_dentry);
			if (in_dentry != NULL)
				delete_file(in_dentry);
		} else if (oflag) {
			if (temp_dentry != NULL && in_dentry != NULL)
				rename_file(temp_dentry, in_dentry);
			if (out_dentry != NULL)
				delete_file(out_dentry);
		} else if (!oflag) {
			if (temp_dentry != NULL && out_dentry != NULL)
				rename_file(temp_dentry, out_dentry);
		}
	}

	/* closing the infile */
	if (infilp && !IS_ERR(infilp))
		filp_close(infilp, NULL);

	/* closing the temp file */
	if (temp_filp && !IS_ERR(temp_filp))
		filp_close(temp_filp, NULL);

	/* closing the outfile */
	if (outfilp && !IS_ERR(outfilp))
		filp_close(outfilp, NULL);

	if (hashed_key != NULL)
		kfree(hashed_key);

	if (in_buf != NULL)
		kfree(in_buf);

	if (out_buf != NULL)
		kfree(out_buf);

	if (temp_name != NULL)
		kfree(temp_name);

	return err;
}

/*
 * function to find checksum
 */
char *find_checksum(char *infile, int hash_algo)
{
	int err = 0;
	int i, bytes, bytes_to_read, curr, len;
	char *buf = NULL;
	unsigned char *checksum = NULL, *final = NULL, temp[2];
	struct file *infilp = NULL;
	struct scatterlist sg;
	struct crypto_hash *tfm;
	struct hash_desc desc;

	infilp = filp_open(infile, O_RDONLY, 0);
	/* check for validity of file */
	if (!infilp || IS_ERR(infilp)) {
		pr_err("Error: Infile does not exist\n");
		err = (int) PTR_ERR(infilp);
		goto out;
	}

	/* setting the transformation */
	if (hash_algo == SHA1) {
		tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
		len = 20;
	} else {
		tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
		len = 16;
	}

	desc.tfm = tfm;
	desc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	if (!(desc.tfm) || IS_ERR(desc.tfm)) {
		pr_err("Error: Fail to load transformation for hashing\n");
		err = -PTR_ERR(desc.tfm);
		goto out;
	}
	crypto_hash_init(&desc);

	checksum = kzalloc(len, __GFP_WAIT);
	if (!checksum) {
		err = -ENOMEM;
		goto out;
	}

	final = kzalloc(2 * len, __GFP_WAIT);
	if (!final) {
		err = -ENOMEM;
		goto out;
	}

	bytes_to_read = i_size_read(infilp->f_path.dentry->d_inode);
	if (bytes_to_read > PAGE_SIZE)
		curr = PAGE_SIZE;
	else
		curr = bytes_to_read;

	buf = kzalloc(curr, __GFP_WAIT);
	if (!buf) {
		err = -ENOMEM;
		goto out;
	}
	infilp->f_pos = 0;

	do {
		bytes_to_read -= curr;
		bytes = read_file(infilp, buf, curr, 0);
		sg_init_one(&sg, buf, bytes);
		crypto_hash_update(&desc, &sg, bytes);
	} while (bytes_to_read > 0);

	crypto_hash_final(&desc, checksum);

	for (i = 0; i < len; i++) {
		sprintf(temp, "%02x", checksum[i]);
		strcat(final, temp);
	}

out:
	/* closing the outfile */
	if (infilp)
		if (!IS_ERR(infilp))
			filp_close(infilp, NULL);

	if (buf != NULL)
		kfree(buf);

	if (checksum != NULL)
		kfree(checksum);

	if (err < 0)
		return ERR_PTR(err);
	else
		return final;
}

/*
 * Function for compression/uncompression
 * @infile : pointer to input filename string
 * @outfile: pointer to output filename string
 * @code   : int code of the operation
 *			 2 -> Compression, 3-> Uncompression
 * @algo   : int code for algorithm to be used
 * @job_id : job ID of this operation
 * @oflag  : input file will be overwritten with the output,
 *			 if oflag is set; outfile is not required
 * @nflag  : input file will be removed, if nflag is set
 */
int com_uncompress_file
(char *infile, char *outfile, int code,
int algo, int job_id, int oflag, int nflag)
{
	int err = 0;
	int bytes_to_read = 0;
	int read_bytes = 0, written_bytes = 0;
	char *temp_name = NULL, *comp_algo = NULL;
	char ids[3], bytes[4];
	struct crypto_comp *tfm = NULL;
	struct file *infilp = NULL, *temp_filp = NULL, *outfilp = NULL;
	struct dentry *out_dentry = NULL, *in_dentry = NULL, *temp_dentry =
	    NULL;
	void *in_buf = NULL, *out_buf = NULL;
	long int intsize = 0;
	unsigned int *dlen = kmalloc(sizeof(int), GFP_KERNEL);
	char *dst = kzalloc(PAGE_SIZE, __GFP_WAIT);

	/* checking all the params for correctness while debugging */
	#ifdef DEBUG
	pr_debug("infile - %s\n", infile);
	pr_debug("id - %d\n", job_id);
	pr_debug("algo - %d\n", algo);
	#endif

	comp_algo = "deflate";

	err = is_file_valid(infile);
	if (err < 0) {
		pr_err("Error: Infile not valid\n");
		goto out;
	}

	infilp = filp_open(infile, O_RDONLY, 0);
	if (!infilp || IS_ERR(infilp)) {
		pr_err("Error: Infile does not exist\n");
		err = (int) PTR_ERR(infilp);
		goto out;
	}

	in_dentry = infilp->f_path.dentry;

	temp_name = kzalloc(strlen(infile) + 10, __GFP_WAIT);
	if (!temp_name) {
		err = -ENOMEM;
		goto out;
	}

	sprintf(ids, ".%d", job_id);
	strcat(temp_name, infile);
	strcat(temp_name, ids);

	temp_filp = filp_open(temp_name, O_WRONLY | O_CREAT | O_TRUNC,
			      infilp->f_path.dentry->d_inode->i_mode);
	if (!temp_filp || IS_ERR(temp_filp)) {
		pr_err("Error: Temp file cannot be accessed\n");
		err = (int) PTR_ERR(temp_filp);
		goto out;
	}

	temp_dentry = temp_filp->f_path.dentry;

	/* check if infile and temp file are are same */
	if (((infilp->f_path.dentry->d_inode->i_ino) ==
	     (temp_filp->f_path.dentry->d_inode->i_ino))
	    && ((infilp->f_path.dentry->d_inode->i_sb) ==
		(temp_filp->f_path.dentry->d_inode->i_sb))) {
		pr_err
		    ("Error: Infile and temp file are pointing to same file\n");
		err = -EINVAL;
		goto out;
	}

	bytes_to_read = PAGE_SIZE;

	/* memory alloctation for in buffer */
	in_buf = kzalloc(bytes_to_read, __GFP_WAIT);
	if (!in_buf) {
		err = -ENOMEM;
		goto out;
	}

	/* memory alloctation for out buffer */
	out_buf = kzalloc(bytes_to_read, __GFP_WAIT);
	if (!out_buf) {
		err = -ENOMEM;
		goto out;
	}

	/* setting the transformation */
	tfm = crypto_alloc_comp(comp_algo, 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Error: Failed to load transform\n");
		err = PTR_ERR(tfm);
		goto out;
	}

	if (code == COMPRESSION) {
repeat_com:
		*dlen = PAGE_SIZE;
		read_bytes = read_file(infilp, in_buf, bytes_to_read, 0);
		if (read_bytes < 0) {
			pr_err("Error : Read Failed\n");
			err = read_bytes;
			goto out;
		}
		err = crypto_comp_compress(tfm, in_buf, read_bytes, dst, dlen);
		if (err < 0) {
			pr_err("Error: File compression failed\n");
			goto out;
		}

		sprintf(bytes, "%04d", *dlen);
		written_bytes = write_file(temp_filp, bytes, strlen(bytes), 0);
		if (written_bytes < 0) {
			pr_err("Error : Write Failed\n");
			err = written_bytes;
			goto out;
		}

		written_bytes = write_file(temp_filp, dst, *dlen, 0);
		if (written_bytes < 0) {
			pr_err("Error : Write Failed\n");
			err = written_bytes;
			goto out;
		}

		memset(dst, 0, PAGE_SIZE);
		memset(in_buf, 0, PAGE_SIZE);

		if (read_bytes == PAGE_SIZE)
			goto repeat_com;

	} else if (code == EXTRACTION) {
		read_bytes = PAGE_SIZE;
repeat_uncomp:
		read_bytes = read_file(infilp, bytes, 4, 0);
		if (read_bytes < 0) {
			pr_err("Error : Read Failed\n");
			err = read_bytes;
			goto out;
		}
		bytes[4] = '\0';

		err = kstrtol(bytes, 10, &intsize);
		if (err) {
			pr_err("Error: kstrtol failed\n");
			goto out;
		}

		read_bytes = read_file(infilp, in_buf, intsize, 0);
		if (read_bytes < 0) {
			pr_err("Error : Read Failed\n");
			err = read_bytes;
			goto out;
		}

		err = crypto_comp_decompress(tfm, in_buf,
							read_bytes, dst, dlen);
		if (err < 0) {
			pr_err("Error: File uncompression failed - %d.\n", err);
			goto out;
		}

		written_bytes = write_file(temp_filp, dst, *dlen, 0);
		if (written_bytes < 0) {
			pr_err("Error: Write Failed\n");
			err = written_bytes;
			goto out;
		}

		read_bytes = 0;
		memset(dst, 0, PAGE_SIZE);
		memset(in_buf, 0, PAGE_SIZE);

		if (written_bytes == PAGE_SIZE)
			goto repeat_uncomp;
	}

	if (outfile) {
		outfilp =
		    filp_open(outfile, O_WRONLY | O_CREAT | O_TRUNC,
			      infilp->f_path.dentry->d_inode->i_mode);
		if (!outfilp || IS_ERR(outfilp)) {
			pr_err("Error: Outfile does not exist\n");
			err = (int) PTR_ERR(outfilp);
			goto out;
		}

		out_dentry = outfilp->f_path.dentry;

		if (infilp->f_inode->i_ino == outfilp->f_inode->i_ino) {
			pr_err
			    ("Error : Output file is same with input file\n");
			err = -EINVAL;
			goto out;
		}
	}

out:
	if (err < 0) {
		if (temp_dentry != NULL)
			delete_file(temp_dentry);
	} else {
		if (nflag) {
			if (temp_dentry != NULL && out_dentry != NULL)
				rename_file(temp_dentry, out_dentry);
			if (in_dentry != NULL)
				delete_file(in_dentry);
		} else if (oflag) {
			if (temp_dentry != NULL && in_dentry != NULL)
				rename_file(temp_dentry, in_dentry);
			if (out_dentry != NULL)
				delete_file(out_dentry);
		} else if (!oflag) {
			if (temp_dentry != NULL && out_dentry != NULL)
				rename_file(temp_dentry, out_dentry);
		}
	}

	/* closing the infile */
	if (infilp && !IS_ERR(infilp))
		filp_close(infilp, NULL);

	/* closing the temp file */
	if (temp_filp && !IS_ERR(temp_filp))
		filp_close(temp_filp, NULL);

	/* closing the outfile */
	if (outfilp && !IS_ERR(outfilp))
		filp_close(outfilp, NULL);

	if (tfm != NULL)
		crypto_free_comp(tfm);

	if (dlen != NULL)
		kfree(dlen);

	if (dst != NULL)
		kfree(dst);

	if (in_buf != NULL)
		kfree(in_buf);

	if (out_buf != NULL)
		kfree(out_buf);

	if (temp_name != NULL)
		kfree(temp_name);

	return err;
}
