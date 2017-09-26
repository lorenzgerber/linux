
#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/rhashtable.h>

struct keyvalue {
		int key;
		char value[100];
};

struct hashed_object {
	int key;
	struct rhash_head node;
	int value;
};

#define NETLINK_USER 31

struct sock *nl_sk = NULL;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Niklas, Königsson, Niclas Nyström, Lorenz Gerber");
MODULE_DESCRIPTION("A keystore module");

void init_hashtable(void){

	struct rhashtable ht;
	struct hashed_object test;


	static const struct rhashtable_params rhash_kv_params = {
		.nelem_hint = 100,
		.head_offset = offsetof(struct hashed_object, node),
		.key_offset = offsetof(struct hashed_object, key),
		.key_len = FIELD_SIZEOF(struct hashed_object, key),
		.max_size = 1000,
		.min_size = 0,
		.automatic_shrinking = true,
	};

	rhashtable_init(&ht, &rhash_kv_params);


	test.key = 10;
	test.value = 100;


	rhashtable_insert_fast(&ht, &test.node, rhash_kv_params);




}

static void hello_nl_recv_msg(struct sk_buff *skb) {

	struct nlmsghdr *nlh;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;
	char *msg="Hello from kernel";
	int res;

	printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

	msg_size=strlen(msg);

	nlh=(struct nlmsghdr*)skb->data;

	printk(KERN_INFO "Netlink received msg payload:%s\n",((struct keyvalue*) nlmsg_data(nlh))->value);
	pid = nlh->nlmsg_pid; /*pid of sending process */

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
	printk(KERN_INFO "Error while sending bak to user\n");
}

static int __init os_keystore_init(void) {



	struct netlink_kernel_cfg cfg = {
		.input = hello_nl_recv_msg,
	};

	init_hashtable();

	printk("Entering: %s\n",__FUNCTION__);

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
