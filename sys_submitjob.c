/*
 * Copyright (c) 2015 Mohit Goyal, Arjun Singh Bora
 * Copyright (c) 2015-2106 Stony Brook University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "utils.h"

struct list_head job_queue;
struct list_head wait_queue;

asmlinkage extern long (*sysptr) (void *arg, int argslen);

/*
 * Consumer thread function to do the job.
 * It takes out a job from main queue and operate on it.
 */
int consumer(void *data)
{
	int err = 0, i = 0;
	char *outfile = NULL;
	char *checksum = NULL;
	struct job *curr_job = NULL, *job_to_move = NULL;
	struct qnode *qnode = NULL;

start:
	wait_event_interruptible(consumer_wq, q_main_len > 0);
	if (thread_exit) {
		pr_debug("Consumer thread exiting\n");
		goto out;
	}

	mutex_lock(&mutex_len);

	if (q_main_len > 0) {
		curr_job = remove_job(&job_queue, work_queue);
		q_main_len--;

		/* Moving job from wait to work queue */
		if (q_wait_len > 0) {
			job_to_move = remove_job(&wait_queue, wt_queue);
			if (job_to_move == NULL) {
				pr_err
				    ("Error: Fail to move job to work queue\n");
				err = PTR_ERR(job_to_move);
				goto free_lock;
			}
			q_wait_len--;
			qnode = kzalloc(sizeof(struct qnode), __GFP_WAIT);
			qnode->job = job_to_move;
			add_to_queue(qnode, &job_queue, q_main_len,
				     work_queue);
			q_main_len++;
		}
	}
	mutex_unlock(&mutex_len);
	wake_up_all(&producer_wq);

	#ifdef DEBUG
	pr_debug("job id : %d\n", curr_job->id);
	pr_debug("code - %d\n", curr_job->code);
	pr_debug("priority - %d\n", curr_job->priority);
	pr_debug("pid - %d\n", curr_job->pid);
	pr_debug("keylen - %d\n", curr_job->keylen);
	pr_debug("key - %s\n", curr_job->key);
	pr_debug("input files - %d\n", curr_job->infile_count);
	for (i = 0; i < curr_job->infile_count; i++)
		pr_debug("files %d - %s\n", i, curr_job->infile[i]);
	pr_debug("algorithm - %d\n", curr_job->algo);
	pr_debug("nflag - %d\n", curr_job->nflag);
	pr_debug("oflag - %d\n", curr_job->oflag);
	pr_debug("\n");
	#endif

	switch (curr_job->code) {
	case ENCRYPTION:

	case DECRYPTION:
		if (!(curr_job->oflag))
			outfile = curr_job->infile[1];

		err = endecrypt_file(curr_job->infile[0],
			  outfile, curr_job->key,
			  curr_job->keylen, curr_job->code,
			  curr_job->algo, curr_job->id,
			  curr_job->oflag, curr_job->nflag);
		send_to_user(err, curr_job->code, curr_job->id,
					 curr_job->pid, NULL);
		break;

	case COMPRESSION:

	case EXTRACTION:
		if (!(curr_job->oflag))
			outfile = curr_job->infile[1];

		err = com_uncompress_file(curr_job->infile[0],
			  outfile, curr_job->code,
			  curr_job->algo, curr_job->id,
			  curr_job->oflag, curr_job->nflag);

		send_to_user(err, curr_job->code, curr_job->id,
					 curr_job->pid, NULL);
		break;

	case CONCATENATE:
		err = concatenate_file(curr_job->infile,
				       curr_job->infile_count,
				       curr_job->id);
		send_to_user(err, curr_job->code, curr_job->id,
					 curr_job->pid, NULL);
		break;

	case CHECKSUM:
		checksum =
			find_checksum(curr_job->infile[0], curr_job->algo);

		if (IS_ERR(checksum)) {
			err = (int) PTR_ERR(checksum);
			send_to_user(err, curr_job->code, curr_job->id,
						curr_job->pid, NULL);
		} else
			send_to_user(err, curr_job->code, curr_job->id,
						curr_job->pid, checksum);
		break;

	default:
		pr_err("Error: Unknown job request\n");
	}
	kfree(curr_job->key);
	for (i = 0; i < curr_job->infile_count; i++)
		kfree(curr_job->infile[i]);
	kfree(curr_job->infile);
	kfree(curr_job);
	schedule();
	goto start;

free_lock:
	mutex_unlock(&mutex_len);
out:
	return err;
}

/*
 * Producer function.
 * In case of List/Remove/RemoveAll/ChangePriority operations,
 * it sends the result/message to the user
 * In case of other file operations it add the job to the
 * main/wait queue. It gets blocked when wait_queue length reaches
 * the maximum.
 */
asmlinkage long submitjob(void *job, int argslen)
{
	int err = 0, i = 0;
	char **temp;
	struct filename *infile = NULL;
	struct job *kjob = NULL;
	struct qnode *qnode = NULL;
	struct list_head *pos_list;
	struct qnode *temp_node = NULL;
	int temp_len = 0;

	/* Validation of address of user arguements */
	if (job == NULL) {
		pr_err("Error: User arguments are not valid\n");
		err = -EINVAL;
		goto out_free;
	}

	/* memory allcation for the user arguments */
	kjob = kmalloc(sizeof(struct job), __GFP_WAIT);
	if (kjob == NULL) {
		err = -ENOMEM;
		goto out_free;
	}

	/* check if user space pointer is valid or not */
	if (!access_ok(VERIFY_READ, job, sizeof(struct job))) {
		pr_err("Error: User space pointer is not valid\n");
		err = -EINVAL;
		goto out_free;
	}

	/* copying user arguments into kernel */
	err = copy_from_user(kjob, job, sizeof(struct job));

	/* check for successful copying of user arguments into kernel */
	if (err) {
		pr_err("List operation failed - %d\n", err);
		goto out_free;
	}

	if (kjob->code == LIST) {
		kjob->key = NULL;
		mutex_lock(&mutex_len);
		err = list_job(job, &job_queue, &wait_queue);
		mutex_unlock(&mutex_len);
		if (err < 0)
			pr_err("Error: Failed to copy to user while list\n");

		goto out_free;
	} else if (kjob->code == CHANGEPRIORITY) {
		mutex_lock(&mutex_len);
		err = change_priority(kjob->id, kjob->priority,
						&job_queue, &wait_queue);
		mutex_unlock(&mutex_len);
		if (err < 0)
			pr_err("Error: Failed to change priority.\n");
		goto free;
	} else if (kjob->code == REMOVE) {
		mutex_lock(&mutex_len);
		err = remove_job_id(kjob->id, &job_queue, &wait_queue);
		mutex_unlock(&mutex_len);
		if (err < 0)
			pr_err("Error: %d\n", err);
		goto free;
	} else if (kjob->code == REMOVEALL) {
		mutex_lock(&mutex_len);
		if (q_main_len > 0)
			free_queue(&job_queue, &q_main_len);
		if (q_wait_len > 0)
			free_queue(&wait_queue, &q_wait_len);
		mutex_unlock(&mutex_len);
		goto free;
	}

	/* check for number of infiles specified */
	if (kjob->infile_count > 10) {
		pr_err("Error: Number of infiles can not be more than 10");
		err = -EPERM;
		goto out_free;
	}

	/* memory allocation for key */
	kjob->key = kzalloc(kjob->keylen, __GFP_WAIT);
	if (!kjob->key) {
		err = -ENOMEM;
		goto out_free;
	}

	err = copy_from_user(kjob->key, ((struct job *) job)->key,
			     kjob->keylen);
	if (err) {
		pr_err("Error: Failed to copy key into kernel space\n");
		goto out_free;
	}

	temp = kmalloc(sizeof(char *) * kjob->infile_count, __GFP_WAIT);
	kjob->infile = temp;

	for (i = 0; i < kjob->infile_count; i++) {
		infile = getname(((struct job *) job)->infile[i]);
		if (IS_ERR(infile)) {
			pr_err
			    ("Error: Fail to copy infile name to kernel\n");
			err = PTR_ERR(infile);
			goto out_free;
		}
		kjob->infile[i] =
		    kzalloc(strlen((char *) infile->name) + 1, __GFP_WAIT);
		strncpy(kjob->infile[i], infile->name,
			strlen((char *) infile->name) + 1);
	}

start:
	mutex_lock(&mutex_len);

	/* adding job to work queue */
	if (q_main_len < MAX_LEN && kjob) {
		id++;
		kjob->id = id;
		qnode = kmalloc(sizeof(struct qnode), __GFP_WAIT);
		qnode->job = (struct job *) kjob;
		add_to_queue(qnode, &job_queue, q_main_len, work_queue);
		q_main_len++;
	}
	/* adding job to wait queue */
	else if (q_wait_len < MAX_LEN && kjob) {
		id++;
		kjob->id = id;
		qnode = kmalloc(sizeof(struct qnode), __GFP_WAIT);
		qnode->job = (struct job *) kjob;
		/* adding job to wait queue based on priority */
		if (work_queue->tail->job->priority >=
		    qnode->job->priority) {
			add_to_queue(qnode, &wait_queue, q_wait_len,
				     wt_queue);
			q_wait_len++;
		} else {
			temp_len = 0;
			list_for_each(pos_list, &job_queue) {
				temp_len++;
				temp_node =
				    list_entry(pos_list, struct qnode,
					       list);
				if (temp_len == MAX_LEN
				    && q_main_len == MAX_LEN) {
					work_queue->tail =
					    list_entry(pos_list->prev,
						       struct qnode, list);
					list_del(pos_list);
					q_main_len--;
					break;
				}
			}
			temp_len = 0;

			add_to_queue(qnode, &job_queue, q_main_len,
				     work_queue);
			q_main_len++;

			add_to_queue(temp_node, &wait_queue, q_wait_len,
				     wt_queue);
			q_wait_len++;
		}
	}
	/* wait queue is also full, throttling the producer */
	else if (q_wait_len == MAX_LEN) {
		mutex_unlock(&mutex_len);
		wait_event_interruptible(producer_wq,
					 q_wait_len < MAX_LEN);
		goto start;
	}

	#ifdef DEBUG
	list_for_each(pos_list, &job_queue) {
		temp_node = list_entry(pos_list, struct qnode, list);
		pr_debug("work queue key is %s\n", (temp_node->job)->key);
	}
	list_for_each(pos_list, &wait_queue) {
		temp_node = list_entry(pos_list, struct qnode, list);
		pr_debug("wait queue key is %s\n", (temp_node->job)->key);
	}
	#endif

	mutex_unlock(&mutex_len);
	wake_up_all(&consumer_wq);

	/* check if user space pointer is valid or not */
	if (!access_ok(VERIFY_WRITE, job, sizeof(struct job))) {
		pr_err("Error: User space pointer is not valid\n");
		err = -EINVAL;
		goto out_free;
	}

	/* copying job id from kernel space to user space */
	err = copy_to_user(&(((struct job *) job)->id),
			   &(((struct job *) kjob)->id), sizeof(int));
	if (err < 0)
		pr_err("Error: Failed to copy data from kernel to user\n");

	if (q_wait_len > 0) {
		int *warn_user = kmalloc(sizeof(int), GFP_KERNEL);
		*warn_user = 0;
		err = copy_to_user(&(((struct job *) job)->priority),
				   warn_user, sizeof(int));
		if (err < 0)
			pr_err("Error: Failed to copy data from kernel to user\n");

		kfree(warn_user);
	}
	goto out;

out_free:
	if (infile && !IS_ERR(infile))
		putname(infile);

	if (kjob->key != NULL)
		kfree(kjob->key);

free:
	if (kjob != NULL)
		kfree(kjob);
out:
	return err;
}

static int __init init_sys_submitjob(void)
{
	int err = 0, i = 0;
	char thread[5];
	char *thread_name = NULL;

	pr_debug("Installed new sys_submitjob module\n");

	job_queue = (struct list_head) LIST_HEAD_INIT(job_queue);
	wait_queue = (struct list_head) LIST_HEAD_INIT(wait_queue);

	work_queue = init_queue();
	wt_queue = init_queue();
	/*mutex_init(&mutex_queue);*/

	if (IS_ERR(work_queue)) {
		pr_err
		    ("Error: Failed to allocate memory to initialize queue\n");
		err = PTR_ERR(work_queue);
		goto out;
	}
	if (IS_ERR(wt_queue)) {
		pr_err
		    ("Error: Failed to allocate memory to initialize queue\n");
		err = PTR_ERR(wt_queue);
		goto out;
	}

	init_waitqueue_head(&producer_wq);
	init_waitqueue_head(&consumer_wq);
	mutex_init(&mutex_len);

	thread_name = kzalloc(strlen("consumer") + 10, GFP_KERNEL);
	if (!thread_name) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 1; i <= NUMBER_OF_CONSUMERS; i++) {
		strncpy(thread_name, "consumer", strlen("consumer"));
		sprintf(thread, "%d", i);
		strcat(thread_name, thread);
		consumer_thread =
		    kthread_create(consumer, NULL, thread_name);
		wake_up_process(consumer_thread);
		memset(thread_name, 0, strlen("consumer") + 10);
	}

	sock = netlink_kernel_create(&init_net, NETLINK_USER, NULL);
	if (!sock) {
		pr_err("Error: Fail to create socket\n");
		return -ENOMEM;
	}

	if (sysptr == NULL)
		sysptr = submitjob;

out:
	if (thread_name != NULL)
		kfree(thread_name);

	return err;
}

static void __exit exit_sys_submitjob(void)
{
	if (sysptr != NULL)
		sysptr = NULL;

	pr_debug("Removed sys_submitjob module\n");

	thread_exit = 1;
	q_main_len++;
	wake_up_all(&consumer_wq);

	free_queue(&job_queue, &q_main_len);
	free_queue(&wait_queue, &q_wait_len);

	kfree(work_queue);
	kfree(wt_queue);

	netlink_kernel_release(sock);
}

module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Operating System assignment - Asynchronous producer consumer.");
MODULE_AUTHOR("Mohit Goyal, Arjun Singh Bora");
