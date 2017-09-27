
#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/rhashtable.h>
#include <linux/string.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Niklas, Königsson, Niclas Nyström, Lorenz Gerber");
MODULE_DESCRIPTION("A keystore module");

#define NETLINK_USER 31
struct sock *nl_sk = NULL;

// static test variable to implement
// some sort of state from one user
// call to the next
static int sum = 0;

// static rhashtable to be accessible
// from inside the netlink socket callback construct
static struct rhashtable ht;

// struct currently used for
// communication with netlink sockets
struct keyvalue {
		int key;
		char value[100];
};

// struct currently used for
// storage in the rhashtable
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
 * netsocket callback function - should be renamed to something
 * more meaningful.
 *
 * This is actually the function where most of the logic will be
 * implemented. It reads the socket,
 */
static void hello_nl_recv_msg(struct sk_buff *skb) {

	// net socked related initialization
	struct nlmsghdr *nlh;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;


	// creating data / data containers
	char *msg="Hello from kernel";
	int res;
	struct hashed_object *test;
	struct hashed_object *out;


	printk(KERN_INFO "Entering: %s\n", __FUNCTION__);
	msg_size=strlen(msg);

	// obtain/read data from the socket buffer
	nlh=(struct nlmsghdr*)skb->data;


	printk(KERN_INFO "Netlink received msg payload:%s\n",((struct keyvalue*) nlmsg_data(nlh))->value);
	pid = nlh->nlmsg_pid; /*pid of sending process */


	// allocate dyn mem for objects that shall be added/obtained
	// from the rhashtable
	test = kmalloc(sizeof(struct hashed_object), GFP_KERNEL);
	out = kmalloc(sizeof(struct hashed_object), GFP_KERNEL);


	// testing to create state: adding up the key values
	sum += ((struct keyvalue*) nlmsg_data(nlh))->key;
	printk(KERN_INFO "New sum:%d\n", sum);


	// inserting data into the rhashtable
	test->key = sum;
	strcpy(test->value, ((struct keyvalue*) nlmsg_data(nlh))->value);
	insert(test);

	// obtaining data from the rhashtable
	memcpy(out, lookup(sum), sizeof(struct hashed_object));
	printk(KERN_INFO "lookup value from rhastable:%s\n", out->value);



	// The rest of this function is concerned with
	// sending data back to user space through netlink socket
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
		.input = hello_nl_recv_msg,
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
