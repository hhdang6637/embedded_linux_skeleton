#include "linux/printk.h"
#include <linux/netdevice.h>
#include <linux/proc_fs.h>

#define MAC_COLLECTION_MAX 50

static unsigned char mac_collection[MAC_COLLECTION_MAX][ETH_ALEN];
static int mac_collection_num = 0;
static int mac_collection_start_index = 0;

void mac_collection_add(const unsigned char mac[]) {
	if(mac_collection_num >= MAC_COLLECTION_MAX) {
		memcpy(mac_collection[mac_collection_start_index], mac, 6);
		mac_collection_start_index++;
		mac_collection_start_index %= MAC_COLLECTION_MAX;
	} else {
		memcpy(mac_collection[mac_collection_num++], mac, 6);
	}
}

int mac_collection_get(int index, unsigned char mac[]) {

	if (index + 1 > mac_collection_num) {
		return 0;
	}

	if (mac_collection_num < MAC_COLLECTION_MAX) {
		memcpy(mac, mac_collection[index], 6);
	} else {
		memcpy(mac, mac_collection[(mac_collection_start_index + index) % MAC_COLLECTION_MAX], 6);
	}

	return 1;
}

int mac_collection_find(const unsigned char mac[]) {

	int i;
	unsigned char src_mac[6];

	for(i = 0; i < MAC_COLLECTION_MAX; i++) {

		if (mac_collection_get(i, src_mac)) {

			if (memcmp(src_mac, mac, 6) == 0) {
				return 1;
			}

		} else {
			return 0;
		}
	}

	return 0;
}

static struct proc_dir_entry *ethernetFlowStatistics_proc_dir_ent;

static rx_handler_result_t ethernetFlowStatistics_handle_frame(struct sk_buff **pskb) {

	struct sk_buff *skb = *pskb;

	// const unsigned char *dest = eth_hdr(skb)->h_dest;
	const unsigned char *src = eth_hdr(skb)->h_source;

	// printk(KERN_WARNING "%s receive frame on %s: received SRC MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",
	// 	__FUNCTION__,
	// 	skb->dev->name,
	// 	(unsigned char) src[0],
	// 	(unsigned char) src[1],
	// 	(unsigned char) src[2],
	// 	(unsigned char) src[3],
	// 	(unsigned char) src[4],
	// 	(unsigned char) src[5]);
	if (!mac_collection_find(src)) {
		mac_collection_add(src);
	}

	return RX_HANDLER_PASS;
}

int ethernetFlowStatistics_add_if(struct net_device *dev) {
	int err;

	err = netdev_rx_handler_register(dev, ethernetFlowStatistics_handle_frame, 0);
	if (err) {
		printk(KERN_WARNING "%s fail on %s\n", __FUNCTION__, dev->name);
		return -EINVAL;
	}

	return 0;
}

int ethernetFlowStatistics_del_if(struct net_device *dev) {

	netdev_rx_handler_unregister(dev);

	return 0;
}

static int ethernetFlowStatistics_device_event(struct notifier_block *unused, unsigned long event, void *ptr) {
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
			printk(KERN_WARNING "%s if %s down\n", __FUNCTION__, dev->name);
			ethernetFlowStatistics_del_if(dev);
		}
		break;

	case NETDEV_UP:
		if ((dev->priv_flags & IFF_EBRIDGE)) {
			printk(KERN_WARNING "%s if %s up\n", __FUNCTION__, dev->name);
			ethernetFlowStatistics_add_if(dev);
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

static struct notifier_block ethernetFlowStatistics_device_notifier = {
	.notifier_call = ethernetFlowStatistics_device_event
};

static ssize_t mac_collection_ops_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos)
{
	int i;
	char buff[64];
	unsigned char src_mac[6];
	int len;
	int pos = 0;

	if(*ppos > 0) {
		return 0;
	}

	for(i = 0; i < MAC_COLLECTION_MAX; i++) {

		if (mac_collection_get(i, src_mac)) {

			len = sprintf(buff, "%02d: %02x:%02x:%02x:%02x:%02x:%02x\n",
				i,
				(unsigned char) src_mac[0],
				(unsigned char) src_mac[1],
				(unsigned char) src_mac[2],
				(unsigned char) src_mac[3],
				(unsigned char) src_mac[4],
				(unsigned char) src_mac[5]);

			pos += len;

			if (pos <= count) {

				if(copy_to_user(ubuf + (pos - len), buff, len)) {
					return -EFAULT;
				}

			}
		}
	}

	*ppos = pos;
	return pos;
}

static struct file_operations mac_collection_ops =
{
    .owner = THIS_MODULE,
    .read = mac_collection_ops_read,
};

void ethernet_flow_statistics_init(void) {
	int err;

	printk(KERN_WARNING "ethernet_flow_statistics_init\n");

	err = register_netdevice_notifier(&ethernetFlowStatistics_device_notifier);
	if (err) {
		printk(KERN_WARNING "register_netdevice_notifier failed\n");
	}

	ethernetFlowStatistics_proc_dir_ent = proc_mkdir("ethernetFlowStatistics", NULL);

	if(ethernetFlowStatistics_proc_dir_ent == NULL)
	{
		printk(KERN_ERR "Cannot proc_mkdir ethernetFlowStatistics");
		return;
	}

	proc_create("mac_collection", 0444, ethernetFlowStatistics_proc_dir_ent, &mac_collection_ops);

}

void ethernet_flow_statistics_cleanup(void){
	printk(KERN_WARNING "ethernet_flow_statistics_cleanup\n");

	unregister_netdevice_notifier(&ethernetFlowStatistics_device_notifier);

	proc_remove(ethernetFlowStatistics_proc_dir_ent);
}