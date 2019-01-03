#include <linux/printk.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>

MODULE_DESCRIPTION("ethernetflow module");
MODULE_LICENSE("GPL v2");

extern void ethernet_flow_init(void);
extern void ethernet_flow_cleanup(void);
extern void ethernetflow_add_frame(const unsigned char macs[]);

extern void ethernet_flow_macs_collection_init(void);
extern void ethernet_flow_macs_collection_cleanup(void);
extern int ethernet_flow_macs_collection_find(const unsigned char mac[]);
extern void ethernet_flow_macs_collection_add(const unsigned char mac[]);

static rx_handler_result_t ethernetFlowStatistics_handle_frame(struct sk_buff **pskb) {

	struct sk_buff *skb = *pskb;

	const unsigned char *dest = eth_hdr(skb)->h_dest;
	const unsigned char *src = eth_hdr(skb)->h_source;

	if (!ethernet_flow_macs_collection_find(src)) {
		ethernet_flow_macs_collection_add(src);
	}

	ethernetflow_add_frame(dest);

	return RX_HANDLER_PASS;
}

static int ethernetflow_add_if(struct net_device *dev) {
	int err;

	err = netdev_rx_handler_register(dev, ethernetFlowStatistics_handle_frame, 0);
	if (err) {
		printk(KERN_WARNING "%s fail on %s\n", __FUNCTION__, dev->name);
		return -EINVAL;
	}

	err = dev_set_promiscuity(dev, 1);
	if (err)
		return 0;

	return 0;
}

static int ethernetflow_remove_if(struct net_device *dev) {

	netdev_rx_handler_unregister(dev);

	dev_set_promiscuity(dev, -1);

	return 0;
}

static int ethernetflow_device_event(struct notifier_block *unused, unsigned long event, void *ptr) {
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	switch (event) {
	case NETDEV_CHANGEMTU:
		break;

	case NETDEV_CHANGEADDR:
		break;

	case NETDEV_CHANGE:
		break;

	case NETDEV_FEAT_CHANGE:
		break;

	case NETDEV_DOWN:
		if ((dev->priv_flags & IFF_EBRIDGE)) {
			printk(KERN_INFO "%s if %s down\n", __FUNCTION__, dev->name);
			ethernetflow_remove_if(dev);
		}
		break;

	case NETDEV_UP:
		if ((dev->priv_flags & IFF_EBRIDGE)) {
			printk(KERN_INFO "%s if %s up\n", __FUNCTION__, dev->name);
			ethernetflow_add_if(dev);
		}
		break;

	case NETDEV_UNREGISTER:
		break;

	case NETDEV_CHANGENAME:
		break;

	case NETDEV_PRE_TYPE_CHANGE:
		/* Forbid underlaying device to change its type. */
		return NOTIFY_BAD;

	case NETDEV_RESEND_IGMP:
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block ethernetflow_device_notifier = {
	.notifier_call = ethernetflow_device_event
};

struct proc_dir_entry *ethernetflow_root;

static int ethernetflow_init(void)
{

	ethernetflow_root = proc_mkdir("ethernet_flow", NULL);

	if(ethernetflow_root == NULL)
	{
		printk(KERN_ERR "Cannot proc_mkdir ethernet_flow");
		return -1;
	}

	ethernet_flow_init();

	ethernet_flow_macs_collection_init();

	if (register_netdevice_notifier(&ethernetflow_device_notifier)) {
		printk(KERN_WARNING "register_netdevice_notifier failed\n");
	}

	return 0;
}

static void ethernetflow_cleanup(void)
{
	unregister_netdevice_notifier(&ethernetflow_device_notifier);

	ethernet_flow_cleanup();

	ethernet_flow_macs_collection_cleanup();

	if (ethernetflow_root)
		proc_remove(ethernetflow_root);
}

module_init(ethernetflow_init);
module_exit(ethernetflow_cleanup);

