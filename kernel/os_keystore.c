
#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/rhashtable.h>
#include <linux/string.h>
#include <linux/slab.h>

#define INSERT 		0
#define GET 		1
#define DELETE 		2
#define DELETE_KEY 	3

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Niklas, Königsson, Niclas Nyström, Lorenz Gerber");
MODULE_DESCRIPTION("A keystore module");

#define NETLINK_USER 31
struct sock *nl_sk = NULL;

static struct rhashtable ht;

// netlink socket com struct
struct keyvalue {
		int operation;
		int key;
		char value[100];
};

// rhashtable storage struct
struct hashed_object {
	int key;
	struct rhash_head node;
	char value[100];
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
	int res = rhashtable_remove_fast(&ht, &(hash_data->node), rhash_kv_params);
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
		int res = rhashtable_remove_fast(&ht, &(retrievedObj->node), rhash_kv_params);
		printk(KERN_INFO "Result for remove_fast (by key %d): %d\n", key, res);
	} else {
		printk(KERN_INFO "Result for remove_fast (by key %d): Could not find object.\n", key, res);
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
	char msg[100];
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
			strcpy(msg, "insert success");
			break;
		case GET:
			memcpy(hash_data, lookup(((struct keyvalue*) nlmsg_data(nlh))->key),
					sizeof(struct hashed_object));
			printk(KERN_INFO "lookup value from rhastable:%s\n", hash_data->value);
			strcpy(msg, hash_data->value);
			break;
		case DELETE:
			printk(KERN_INFO "Removing %s with key %d\n",
					((struct keyvalue*) nlmsg_data(nlh))->value,
					((struct keyvalue*) nlmsg_data(nlh))->key );
			hash_data->key = ((struct keyvalue*) nlmsg_data(nlh))->key;
			strcpy(hash_data->value, ((struct keyvalue*) nlmsg_data(nlh))->value);
			DELETE(hash_data);
			strcpy(msg, "DELETE success");
			break;
		case DELETE_KEY:
			printk(KERN_INFO "Removing object with key %d\n",
						((struct keyvalue*) nlmsg_data(nlh))->key );
			memcpy(hash_data, lookup(((struct keyvalue*) nlmsg_data(nlh))->key),
							sizeof(struct hashed_object));
			DELETE(hash_data);
			strcpy(msg, "DELETE_KEY success");
			break;
		default:
			break;
	}



	/*
	 * Return data to Userspace
	 */
	msg_size=strlen(msg);
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

static int __init os_keystore_init(void) {

	// netlink configuration struct that
	// contains the call back function
	struct netlink_kernel_cfg cfg = {
		.input = keystore,
	};

	init_hashtable();

	printk("Entering: %s\n",__FUNCTION__);

	// setting up the netlink socket
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);

	if(!nl_sk){
		printk(KERN_ALERT "Error creating socket.\n");
		return -10;
	}

	return 0;
}


static void __exit os_keystore_exit(void) {

	printk(KERN_INFO "exiting hello module\n");
	netlink_kernel_release(nl_sk);
}

module_init(os_keystore_init);
module_exit(os_keystore_exit);

