
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
#define BACKUP		4

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


int backup_length(void){

	int ret;
	int length = 0;
	struct rhashtable_iter iter;
	struct hashed_object* data;
	printk("we're in backup, lenght calc\n");

	ret = rhashtable_walk_init(&ht, &iter, GFP_ATOMIC);
	if (ret){
		return -1;
	}

	ret = rhashtable_walk_start(&iter);
	if (ret && ret != -EAGAIN)
		goto err;

	while ((data = rhashtable_walk_next(&iter))) {
		// Here we have to take care of the data
		char str[10];
		sprintf(str, "%d", data->key);
		length += strlen(str)+1;
		length += strlen(data->value)+1;
	}

err:
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	return length;


}

char* backup_msg(int length){

	int ret;
	char *msg;
	int write_pos = 0;
	struct rhashtable_iter iter;
	struct hashed_object* data;
	msg = kmalloc(sizeof(char)*length, GFP_KERNEL);
	memset(msg, 0, length);

	ret = rhashtable_walk_init(&ht, &iter, GFP_ATOMIC);
	if (ret){
		return NULL;
	}

	ret = rhashtable_walk_start(&iter);
	if (ret && ret != -EAGAIN)
		goto err;

	while ((data = rhashtable_walk_next(&iter))) {
		// Here we have to take care of the data
		char str[10];
		sprintf(str, "%d", data->key);
		memcpy(msg+write_pos, str, strlen(str));
		write_pos += strlen(str)+1;
		memcpy(msg+write_pos, data->value, strlen(data->value));
		write_pos += strlen(data->value)+1;
	}

err:
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	return msg;

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
			if(lookup(((struct keyvalue*) nlmsg_data(nlh))->key)!= NULL){
				printk("Key value pair is already in store!\n");
				msg = kmalloc(sizeof(char)*36, GFP_KERNEL);
				msg_size = 36;
				strcpy(msg, "Key-value pair is already in store!");
			} else {
				printk(KERN_INFO "Inserting %s with key %d\n",
						((struct keyvalue*) nlmsg_data(nlh))->value,
						((struct keyvalue*) nlmsg_data(nlh))->key );
				hash_data->key = ((struct keyvalue*) nlmsg_data(nlh))->key;
				strcpy(hash_data->value, ((struct keyvalue*) nlmsg_data(nlh))->value);
				insert(hash_data);
				msg = kmalloc(sizeof(char)*15, GFP_KERNEL);
				msg_size = 15;
				strcpy(msg, "INSERT success");
			}
			break;
		case GET:
			if(lookup(((struct keyvalue*) nlmsg_data(nlh))->key)!= NULL){
				memcpy(hash_data, lookup(((struct keyvalue*) nlmsg_data(nlh))->key),
						sizeof(struct hashed_object));
				printk(KERN_INFO "lookup value from rhastable:%s\n", hash_data->value);
				msg = kmalloc(sizeof(char)*(2*(strlen(hash_data->value)+1)), GFP_KERNEL);
				memset(msg,0, sizeof(char)*(2*(strlen(hash_data->value)+1)) );
				strcpy(msg, hash_data->value);
				strcpy(msg+(strlen(hash_data->value)+1),hash_data->value);
				msg_size = strlen(msg)+1;
			} else {
				printk("key not found!\n");
				msg = kmalloc(sizeof(char)*26, GFP_KERNEL);
				msg_size = 26;
				strcpy(msg, "Key-value pair not found!");
			}
			break;
		case DELETE:
			printk(KERN_INFO "Removing %s with key %d\n",
					((struct keyvalue*) nlmsg_data(nlh))->value,
					((struct keyvalue*) nlmsg_data(nlh))->key );
			hash_data->key = ((struct keyvalue*) nlmsg_data(nlh))->key;
			strcpy(hash_data->value, ((struct keyvalue*) nlmsg_data(nlh))->value);
			delete(hash_data);
			msg = kmalloc(sizeof(char)*15, GFP_KERNEL);
			msg_size = 15;
			strcpy(msg, "DELETE success");
			break;
		case DELETE_KEY:
			printk(KERN_INFO "Removing object with key %d\n",
						((struct keyvalue*) nlmsg_data(nlh))->key );
			delete_key(((struct keyvalue*) nlmsg_data(nlh))->key);
			msg = kmalloc(sizeof(char)*19, GFP_KERNEL);
			msg_size = 19;
			strcpy(msg, "DELETE_KEY success");
			break;
		case BACKUP:
			printk(KERN_INFO "Backing up Key-value store\n");
			msg_size = backup_length();
			if(msg_size == 0){
				msg = NULL;
			} else {
				msg = backup_msg(msg_size);
			}
			break;
		default:
			break;
	}



	/*
	 * Return data to Userspace
	 */
	//msg_size=strlen(msg)+1;
	skb_out = nlmsg_new(msg_size,0);

	if(!skb_out){
		printk(KERN_ERR "Failed to allocate new skb\n");
		return;
	}

	nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0);
	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
	if(msg_size!=0){
		memcpy(nlmsg_data(nlh),msg,msg_size);
	}
	res=nlmsg_unicast(nl_sk,skb_out,pid);
	if(msg!=NULL){
		kfree(msg);
	}
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

