/*
 * Copyright (c) 2015 Mohit Goyal, Arjun Singh Bora
 * Copyright (c) 2015-2106 Stony Brook University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/stat.h>
#include <linux/kthread.h>
#include <linux/namei.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/aes.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <crypto/compress.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include "common.h"

/* socket protocol number for MFE Network Services Protocol */
#define NETLINK_USER 31

/* maximum queue length */
#define MAX_LEN 5

/* Macro for number of consumer thread */
#define NUMBER_OF_CONSUMERS 3

/* soceket to used for callback */
struct sock *sock = NULL;

/* queue node structure */
struct qnode {
	struct job *job;
	struct list_head list;
};

struct queue {
	struct qnode *head;
	struct qnode *tail;
};

struct queue *work_queue;
struct queue *wt_queue;
wait_queue_head_t producer_wq, consumer_wq;

/* protecting main/wait queues */
struct mutex mutex_len;

/* protecting queue
struct mutex mutex_queue;*/
struct task_struct *consumer_thread;

int id = 0;
int q_main_len = 0;
int q_wait_len = 0;
int thread_exit = 0;

static const char * const operation[] = {
		FOREACH_OPERATION(GENERATE_STRING)
};

/*
 * Just changes all except the first letter of @str to lowercase.
 * eg. ENCRYPTION to Encryption
 * @str    : input string
 * @newstr : resulted string
 */
void *changecase(const char *str, char *newstr)
{
	int i = 1;

	for (i = 1; str[i]; i++)
		newstr[i] = tolower(str[i]);

	newstr[0] = str[0];
	newstr[i] = str[i];
	return NULL;
}

/*
 * Function to list all the jobs stored in main and wait queues.
 * It takes out a job from main queue and operate on it.
 * @job        : user job for List operation
 * @job_queue  : list head for main queue
 * @wait_queue : list head for wait queue
 * Writes data into job->key, and returns 0 on success
 * returns error code in cas of failure
 */
int list_job(struct job *job, struct list_head *job_queue,
			 struct list_head *wait_queue)
{
	char *info = NULL;
	int err = 0;
	char *job_detail = NULL;
	char *op = NULL;
	struct list_head *pos_list;
	struct qnode *temp_node = NULL;

	info = kzalloc(PAGE_SIZE, __GFP_WAIT);
	if (info == NULL) {
		err = -ENOMEM;
		goto out;
	}

	job_detail = kzalloc(PAGE_SIZE, __GFP_WAIT);
	if (job_detail == NULL) {
		err = -ENOMEM;
		goto out;
	}
	op = kzalloc(20, GFP_KERNEL);
	if (op == NULL) {
		err = -ENOMEM;
		goto out;
	}
	sprintf(info, "%-7s|", "Job ID");
	strcat(job_detail, info);
	sprintf(info, "  %-15s|", "Job Type");
	strcat(job_detail, info);
	sprintf(info, "  %-13s|", "Job Priority");
	strcat(job_detail, info);
	sprintf(info, "    %-14s\n", "Queue");
	strcat(job_detail, info);
	strcat(job_detail,
		   "------------------------------------------------------\n");

	list_for_each(pos_list, job_queue) {
		temp_node = list_entry(pos_list, struct qnode, list);
		changecase(operation[temp_node->job->code], op);
		sprintf(info, "  %-5d|", temp_node->job->id);
		strcat(job_detail, info);
		sprintf(info, "  %-15s|", op);
		strcat(job_detail, info);
		sprintf(info, "      %-9d|", temp_node->job->priority);
		strcat(job_detail, info);
		sprintf(info, "  %-7s\n", "Work Queue");
		strcat(job_detail, info);
	}
	list_for_each(pos_list, wait_queue) {
		temp_node = list_entry(pos_list, struct qnode, list);
		changecase(operation[temp_node->job->code], op);
		sprintf(info, "  %-5d|", (temp_node->job)->id);
		strcat(job_detail, info);
		sprintf(info, "  %-15s|", op);
		strcat(job_detail, info);
		sprintf(info, "      %-9d|", (temp_node->job)->priority);
		strcat(job_detail, info);
		sprintf(info, "  %-7s\n", "Wait Queue");
		strcat(job_detail, info);
	}
	err = copy_to_user(job->key, job_detail, strlen(job_detail));

out:
	kfree(op);
	kfree(info);
	kfree(job_detail);

	return err;
}

/*
 * Function for netlink callback
 * It unicast a message to a process
 * @pid : PID of the process the message is to be sent
 * @msg : Message to be sent
 */
static void netlink_callback(int pid, char *msg)
{
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	int msg_size;
	int res;

	msg_size = strlen(msg);
	skb_out = nlmsg_new(msg_size, 0);
	if (!skb_out) {
		pr_err("Error: Failed to allocate new skbuff\n");
		return;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0;
	strncpy(nlmsg_data(nlh), msg, msg_size);
	res = nlmsg_unicast(sock, skb_out, pid);

	if (res)
		pr_err("Error: Failed to send message to user - %d\n", res);
}

/*
 * Function to prepare a message and send to the user process.
 * @err    : error number to be sent
 * @code   : int code for the operation
 * @pid    : PID of the process the message is to be sent
 * @op_msg : any custom message consumer wants to send to the user process
 * It just prepares a message into a single string and pass it to
 * netlink_callback() function for actual transmission.
 */
void send_to_user(int err, int code, int job_id, int pid, char *op_msg)
{
	char *op = NULL;
	char ids[3];
	char *msg = NULL;

	op = kzalloc(sizeof(char) * 32, GFP_KERNEL);
	msg = kzalloc(sizeof(char) * 1024, GFP_KERNEL);
	changecase(operation[code], op);

	sprintf(ids, "%d", err);
	strcat(msg, ids);
	strcat(msg, "Job ID: ");
	sprintf(ids, "%d", job_id);
	strcat(msg, ids);
	if (op_msg != NULL) {
		strcat(msg, "\nChecksum: ");
		strcat(msg, op_msg);
	}
	if (err < 0) {
		strcat(msg, "\n");
		strcat(msg, op);
		strcat(msg, " failed");
	} else {
		strcat(msg, "\n");
		strcat(msg, op);
		strcat(msg, " done");
	}
	netlink_callback(pid, msg);
	if (op_msg != NULL)
		kfree(op_msg);
	kfree(op);
	kfree(msg);
}

/* Initialization of queue */
struct queue *init_queue(void)
{
	int err = 0;
	struct queue *queue = kzalloc(sizeof(struct queue), __GFP_WAIT);

	if (queue == NULL) {
		err = -ENOMEM;
		goto out;
	}

	queue->head = NULL;
	queue->tail = NULL;

	return queue;

out:
	return ERR_PTR(err);
}

/*
 * It adds a job node to a queue and update the head/tail pointers
 * for the queue. The calling function has to increase the length of
 * the queue.
 * @qnode     : struct for the job
 * @job_queue : list_head for the queue qnode is to be added to
 * @queue_len : length of the job_queue before this addition
 * @queue     : struct queue of job_queue
 */
void add_to_queue
(struct qnode *qnode, struct list_head *job_queue,
		int queue_len, struct queue *queue)
{
	int added = 0;
	struct list_head *pos_list;
	struct qnode *temp_node = NULL;

	/*mutex_lock(&mutex_queue);*/
	if (qnode && job_queue) {
		list_for_each(pos_list, job_queue) {
			temp_node = list_entry(pos_list, struct qnode, list);
			if (qnode->job->priority > temp_node->job->priority) {
				list_add(&(qnode->list), temp_node->list.prev);
				added = 1;
				if (qnode->list.prev == job_queue)
					queue->head = qnode;
				break;
			}
		}
		/* inserting first job */
		if (!added && !queue_len) {
			#ifdef DEBUG
			pr_debug("adding first job\n");
			#endif
			list_add(&(qnode->list), job_queue);
			queue->head = qnode;
			queue->tail = qnode;
		}
		/* inserting lowest priority job */
		else if (!added && queue_len) {
			list_add_tail(&(qnode->list), job_queue);
			queue->tail = qnode;
		}
	} else
		pr_err("Error: Node to be added to queue can not be null\n");
	#ifdef DEBUG
	pr_debug("queue len is %d\n", queue_len);
	pr_debug("queue head's id is %d\n", queue->head->job->id);
	pr_debug("queue tail's id is %d\n", queue->tail->job->id);
	#endif
	/*mutex_unlock(&mutex_queue);*/
}

/*
 * It removes and returns the first job from the queue.
 * The calling function has to decrease the length of the queue.
 * @job_queue : list_head for the queue qnode is to be removed from
 * @queue     : struct queue of job_queue
 */
struct job *remove_job(struct list_head *job_queue, struct queue *queue)
{
	struct list_head *pos_list, *q;
	struct qnode *temp_node = NULL;
	struct job *job = NULL;

	list_for_each_safe(pos_list, q, job_queue) {
		temp_node = list_entry(pos_list, struct qnode, list);
		queue->head = list_entry(pos_list->next, struct qnode, list);
		list_del(pos_list);
		break;
	}
	job = temp_node->job;
	if (temp_node != NULL)
		kfree(temp_node);

	return job;
}

/*
 * It removes a particular job from main/wait queue.
 * This function changes the length of the queue, so the calling
 * function should not change the length of any queue.
 * @job_id : ID of the job to be removed
 * @job_queue : list_head for the main queue
 * @wait_queue : list_head for the wait queue
 */
int remove_job_id(int job_id, struct list_head *job_queue,
				  struct list_head *wait_queue)
{
	int err = 0, i = 0;
	int job_found = 0;
	int removed_pid = 0;
	char jobid[3];
	char *msg = NULL;
	struct job *job_to_move = NULL;
	struct list_head *pos_list;
	struct qnode *qnode = NULL, *temp_node = NULL;

	list_for_each(pos_list, job_queue) {
		i++;
		temp_node = list_entry(pos_list, struct qnode, list);
		if (temp_node->job->id == job_id) {
			if (i == 1)
				work_queue->head = list_entry(pos_list->next,
							struct qnode, list);
			else if (i == q_main_len)
				work_queue->tail = list_entry(pos_list->prev,
							struct qnode, list);
			list_del(pos_list);
			q_main_len--;
			removed_pid = temp_node->job->pid;
			job_found = 1;
			kfree(temp_node->job->key);
			for (i = 0; i < temp_node->job->infile_count; i++)
				kfree(temp_node->job->infile[i]);
			kfree(temp_node->job->infile);
			kfree(temp_node->job);
			kfree(temp_node);
			break;
		}
	}
	if (job_found && q_wait_len > 0) {
		job_to_move = remove_job(wait_queue, wt_queue);
		if (job_to_move == NULL) {
			pr_err("Error: Fail to move job to work queue\n");
			err = PTR_ERR(job_to_move);
			goto out;
		}
		qnode = kzalloc(sizeof(struct qnode), __GFP_WAIT);
		qnode->job = job_to_move;
		add_to_queue(qnode, job_queue, q_main_len, work_queue);
		q_main_len++;
		q_wait_len--;
	}
	if (!job_found && q_wait_len > 0) {
		i = 0;
		list_for_each(pos_list, wait_queue) {
			i++;
			temp_node = list_entry(pos_list, struct qnode, list);
			if (temp_node->job->id == job_id) {
				if (i == 1)
					wt_queue->head = list_entry(pos_list->
						next, struct qnode, list);
				else if (i == q_wait_len)
					wt_queue->tail = list_entry(pos_list->
						prev, struct qnode, list);
					list_del(pos_list);
					q_wait_len--;
					removed_pid = temp_node->job->pid;
					job_found = 1;
					kfree(temp_node->job->key);
					for (i = 0; i < temp_node->job->
							infile_count; i++)
						kfree(temp_node->job->
								infile[i]);
					kfree(temp_node->job->infile);
					kfree(temp_node->job);
					kfree(temp_node);
					break;
			}
		}
	}
	if (!job_found) {
		pr_err("Error: Job to be removed does not exist\n");
		err = -EINVAL;
	} else {
		pr_debug("Job removed\n");
		msg = kzalloc(sizeof(char) * 256, GFP_KERNEL);
		sprintf(jobid, "%d", job_id);
		strcat(msg, "Job ID: ");
		strcat(msg, jobid);
		strcat(msg, "- Job deleted by user\n");
		/*
		 * sending netlink message back to the removed process
		 * which is waiting for some message from kernel.
		 */
		netlink_callback(removed_pid, msg);
		kfree(msg);
	}

out:
	return err;
}

/*
 * It changes hte priority of a particular job.
 * This function changes the length of the queue, if needed.
 * So the calling function should not change the length of any queue.
 * @job_id : ID of the job whose priority is to be changed
 * @job_queue : list_head for the main queue
 * @wait_queue : list_head for the wait queue
 */
int change_priority(int job_id, int priority,
		struct list_head *job_queue, struct list_head *wait_queue)
{
	int err = 0, i = 0;
	int job_found = 0;
	int temp_len = 0;
	struct list_head *pos_list;
	struct qnode *temp_node = NULL;
	struct job *last_in_main = NULL, *first_in_wait = NULL;

	list_for_each(pos_list, job_queue) {
		i++;
		temp_node = list_entry(pos_list, struct qnode, list);
		if (temp_node->job->id == job_id) {
			if (i == 1)
				work_queue->head = list_entry(pos_list->
						next, struct qnode, list);
			else if (i == q_main_len)
				work_queue->tail = list_entry(pos_list->
						prev, struct qnode, list);
			list_del(pos_list);
			q_main_len--;
			temp_node->job->priority = priority;
			add_to_queue(temp_node, job_queue,
						q_main_len, work_queue);
			q_main_len++;
			job_found = 1;
			break;
		}
	}

	if (!job_found && q_wait_len > 0) {
		i = 0;
		list_for_each(pos_list, wait_queue) {
			i++;
			temp_node = list_entry(pos_list, struct qnode, list);
			if (temp_node->job->id == job_id) {
				if (i == 1)
					wt_queue->head = list_entry(pos_list->
						      next, struct qnode, list);
				else if (i == q_wait_len)
					wt_queue->tail = list_entry(pos_list->
						      prev, struct qnode, list);
				list_del(pos_list);
				q_wait_len--;
				temp_node->job->priority = priority;
				add_to_queue(temp_node, wait_queue,
						q_wait_len, wt_queue);
				q_wait_len++;
				job_found = 1;
				break;
			}
		}
	}

	if (job_found && q_wait_len > 0) {
		list_for_each(pos_list, job_queue) {
			temp_len++;
			temp_node = list_entry(pos_list, struct qnode, list);
			if (temp_len == MAX_LEN && q_main_len == MAX_LEN) {
				work_queue->tail = list_entry(pos_list->prev,
							struct qnode, list);
				list_del(pos_list);
				q_main_len--;
				break;
			}
		}
		last_in_main = temp_node->job;
		first_in_wait = remove_job(wait_queue, wt_queue);
		q_wait_len--;
		if (last_in_main->priority >= first_in_wait->priority) {
			temp_node->job = last_in_main;
			add_to_queue(temp_node, job_queue,
							q_main_len, work_queue);
			q_main_len++;

			temp_node = kzalloc(sizeof(struct qnode), __GFP_WAIT);
			temp_node->job = first_in_wait;
			add_to_queue(temp_node, wait_queue,
							q_wait_len, wt_queue);
			q_wait_len++;
		} else {
			temp_node->job = first_in_wait;
			add_to_queue(temp_node, job_queue,
							q_main_len, work_queue);
			q_main_len++;

			temp_node = kmalloc(sizeof(struct qnode), __GFP_WAIT);
			temp_node->job = last_in_main;
			add_to_queue(temp_node, wait_queue,
							q_wait_len, wt_queue);
			q_wait_len++;
		}
	}
	if (!job_found) {
		pr_err("Error: Job does not exist\n");
		err = -EINVAL;
		goto out;
	} else {
		pr_debug("Priority changed\n");
	}
out:
	return err;
}

/* deallocating all the memory allocated to work queue or wait queue */
void free_queue(struct list_head *job_queue, int *queue_len)
{
	int i = 0;
	struct list_head *pos_list, *q;
	struct qnode *temp_node = NULL;
	char *msg = NULL;
	char ids[3];

	msg = kzalloc(sizeof(char) * 256, GFP_KERNEL);
	list_for_each_safe(pos_list, q, job_queue) {
		temp_node = list_entry(pos_list, struct qnode, list);
		if (temp_node && temp_node->job && temp_node->job->id) {
			sprintf(ids, "%d", temp_node->job->id);
			strcat(msg, "Job ID: ");
			strcat(msg, ids);
			strcat(msg, "- Job deleted by user.\n");
		}
		netlink_callback(temp_node->job->pid, msg);
		memset(msg, 0, sizeof(char) * 256);
		list_del(pos_list);
		(*queue_len)--;
		kfree(temp_node->job->key);
		for (i = 0; i < temp_node->job->infile_count; i++)
			kfree(temp_node->job->infile[i]);
		kfree(temp_node->job->infile);
		kfree(temp_node->job);
		kfree(temp_node);
	}
	kfree(msg);
}
