
#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/rhashtable.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/kthread.h>
#include <linux/time.h>

#define INSERT 		0
#define GET 		1
#define DELETE 		2
#define DELETE_KEY 	3

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Niklas, Königsson, Niclas Nyström, Lorenz Gerber");
MODULE_DESCRIPTION("A keystore module");

static struct task_struct *thread1;
static void keystore(struct sk_buff *skb);

#define NETLINK_USER 31
struct sock *nl_sk = NULL;

static struct rhashtable ht;

// netlink socket com struct
struct keyvalue {
		int operation;
		int key;
		char *value;
};

// rhashtable storage struct
struct hashed_object {
	int key;
	struct rhash_head node;
	char *value;
};


// defining the parameter for the rhashtable as static as they
// are used with every hashtable operation
static const struct rhashtable_params rhash_kv_params = {
			.nelem_hint = 100,
			.head_offset = offsetof(struct hashed_object, node),
			.key_offset = offsetof(struct hashed_object, key),
			.key_len = FIELD_SIZEOF(struct hashed_object, key),
			.max_size = 1000,
			.min_size = 0,
			.automatic_shrinking = true,
};

int thread_fn(void* data) {
	struct sk_buff *skb;
	int rc;

	printk(KERN_INFO "In thread1");

	skb = skb_recv_datagram(nl_sk, 0, 0, &rc);
	keystore(skb);
	printk("passed the code of interest\n");


	return 0;
}


/**
 * Initialization of rhashtable
 */
void init_hashtable(void){

	rhashtable_init(&ht, &rhash_kv_params);
}

/**
 * wrapper for rhashtable insert function
 */
void insert(struct hashed_object *hash_data){
	int res;

	res = rhashtable_insert_fast(&ht, &(hash_data->node), rhash_kv_params);
	printk(KERN_INFO "res insert_fast %d\n", res);

}

/**
 * wrapper for rhashtable lookup function
 */
struct hashed_object* lookup(int key){
	return (struct hashed_object*) rhashtable_lookup(&ht, &key, rhash_kv_params);

}

/**
 * @hash_data Entry to remove from hash table.
 *
 * Wrapper for rhashtable remove function which returns 0 on success else -ENOENT
 * if the entry could not be found. Shrinks the hashtable automatically if
 * "shrink_decision" function is specified in init_hashtable().
 */
void delete(struct hashed_object *hash_data) {
	int res;
	res = rhashtable_remove_fast(&ht, &(hash_data->node), rhash_kv_params);
	printk(KERN_INFO "Result for remove_fast: %d\n", res);
}

/**
 * @hash_data Object key/index to remove from hash table.
 *
 * Wrapper for rhashtable remove function which returns 0 on success else -ENOENT
 * if the entry could not be found. Shrinks the hashtable automatically if
 * "shrink_decision" function is specified in init_hashtable().
 */
void delete_key(int key) {
	struct hashed_object *retrievedObj = lookup(key);
	if (retrievedObj != NULL) {
		int res;
		res = rhashtable_remove_fast(&ht, &(retrievedObj->node), rhash_kv_params);
		printk(KERN_INFO "Result for remove_fast (by key %d): %d\n", key, res);
	} else {
		printk(KERN_INFO "Result for remove_fast (by key %d): Could not find object.\n", key);
	}
}


/**
 * netsocket callback function - should be renamed to something
 * more meaningful.
 *
 * This is actually the function where most of the logic will be
 * implemented. It reads the socket,
 */
static void keystore(struct sk_buff *skb) {

	/*
	 * Initialization
	 */
	struct nlmsghdr *nlh;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;
	int operation;
	int res;

	// creating data containers
	char *msg;
	struct hashed_object *hash_data;


	printk(KERN_INFO "Entering: %s\n", __FUNCTION__);



	/*
	 * Get Userspace Data
	 */
	nlh=(struct nlmsghdr*)skb->data;
	printk(KERN_INFO "Netlink received msg payload:%s\n",
			((struct keyvalue*) nlmsg_data(nlh))->value);
	pid = nlh->nlmsg_pid; /*pid of sending process */

	// hash_data container
	hash_data = kmalloc(sizeof(struct hashed_object), GFP_KERNEL);
	if(((struct keyvalue*) nlmsg_data(nlh))->operation == 0 ){
		hash_data->value = kmalloc(sizeof(char)*(strlen(((struct keyvalue*) nlmsg_data(nlh))->value)+1), GFP_KERNEL);
	}

	operation = ((struct keyvalue*) nlmsg_data(nlh))->operation;



	/*
	 * Hashtable operations
	 */
	switch(operation) {
		case INSERT:
			printk(KERN_INFO "Inserting %s with key %d\n",
					((struct keyvalue*) nlmsg_data(nlh))->value,
					((struct keyvalue*) nlmsg_data(nlh))->key );
			hash_data->key = ((struct keyvalue*) nlmsg_data(nlh))->key;
			strcpy(hash_data->value, ((struct keyvalue*) nlmsg_data(nlh))->value);
			insert(hash_data);
			msg = kmalloc(sizeof(char)*15, GFP_KERNEL);
			strcpy(msg, "insert success");
			break;
		case GET:
			memcpy(hash_data, lookup(((struct keyvalue*) nlmsg_data(nlh))->key),
					sizeof(struct hashed_object));
			printk(KERN_INFO "lookup value from rhastable:%s\n", hash_data->value);
			msg = kmalloc(sizeof(char)*(strlen(hash_data->value)+1), GFP_KERNEL);
			strcpy(msg, hash_data->value);
			break;
		case DELETE:
			printk(KERN_INFO "Removing %s with key %d\n",
					((struct keyvalue*) nlmsg_data(nlh))->value,
					((struct keyvalue*) nlmsg_data(nlh))->key );
			hash_data->key = ((struct keyvalue*) nlmsg_data(nlh))->key;
			strcpy(hash_data->value, ((struct keyvalue*) nlmsg_data(nlh))->value);
			delete(hash_data);
			msg = kmalloc(sizeof(char)*15, GFP_KERNEL);
			strcpy(msg, "DELETE success");
			break;
		case DELETE_KEY:
			printk(KERN_INFO "Removing object with key %d\n",
						((struct keyvalue*) nlmsg_data(nlh))->key );
			delete_key(((struct keyvalue*) nlmsg_data(nlh))->key);
			msg = kmalloc(sizeof(char)*19, GFP_KERNEL);
			strcpy(msg, "DELETE_KEY success");
			break;
		default:
			break;
	}



	/*
	 * Return data to Userspace
	 */
	msg_size=strlen(msg)+1;
	skb_out = nlmsg_new(msg_size,0);

	if(!skb_out){
		printk(KERN_ERR "Failed to allocate new skb\n");
		return;
	}

	nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0);
	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
	strncpy(nlmsg_data(nlh),msg,msg_size);

	res=nlmsg_unicast(nl_sk,skb_out,pid);

	if(res<0)
	printk(KERN_INFO "Error while sending back to user\n");
}


static void input(struct sk_buff *skb){

	printk("now in input\n");
	wake_up_interruptible(sk_sleep(skb->sk));

}

static int __init os_keystore_init(void) {

	// netlink configuration struct that
	// contains the call back function
	struct netlink_kernel_cfg cfg = {
		.input = input,
	};

	 char  our_thread[8]="thread1";
	    printk(KERN_INFO "in init");


	init_hashtable();

	printk("Entering: %s\n",__FUNCTION__);

	// setting up the netlink socket
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);

	if(!nl_sk){
		printk(KERN_ALERT "Error creating socket.\n");
		return -10;
	}

	thread1 = kthread_create(thread_fn,NULL,our_thread);
		    if((thread1))
		        {
		        printk(KERN_INFO "in if");
		        wake_up_process(thread1);
		        }

	return 0;
}


static void __exit os_keystore_exit(void) {

	int ret;
	 ret = kthread_stop(thread1);
	 if(!ret)
	  printk(KERN_INFO "Thread stopped");

	printk(KERN_INFO "exiting hello module\n");
	netlink_kernel_release(nl_sk);
}

module_init(os_keystore_init);
module_exit(os_keystore_exit);

