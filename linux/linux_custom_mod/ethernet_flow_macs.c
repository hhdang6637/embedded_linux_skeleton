#include <linux/printk.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>

#define MAC_COLLECTION_MAX 50

static unsigned char ethernet_flow_macs_collection[MAC_COLLECTION_MAX][ETH_ALEN];
static int ethernet_flow_macs_collection_num = 0;
static int ethernet_flow_macs_collection_start_index = 0;

void ethernet_flow_macs_collection_add(const unsigned char mac[]) {
	if(ethernet_flow_macs_collection_num >= MAC_COLLECTION_MAX) {
		memcpy(ethernet_flow_macs_collection[ethernet_flow_macs_collection_start_index], mac, 6);
		ethernet_flow_macs_collection_start_index++;
		ethernet_flow_macs_collection_start_index %= MAC_COLLECTION_MAX;
	} else {
		memcpy(ethernet_flow_macs_collection[ethernet_flow_macs_collection_num++], mac, 6);
	}
}

int ethernet_flow_macs_collection_get(int index, unsigned char mac[]) {

	if (index + 1 > ethernet_flow_macs_collection_num) {
		return 0;
	}

	if (ethernet_flow_macs_collection_num < MAC_COLLECTION_MAX) {
		memcpy(mac, ethernet_flow_macs_collection[index], 6);
	} else {
		memcpy(mac, ethernet_flow_macs_collection[(ethernet_flow_macs_collection_start_index + index) % MAC_COLLECTION_MAX], 6);
	}

	return 1;
}

int ethernet_flow_macs_collection_find(const unsigned char mac[]) {

	int i;
	unsigned char src_mac[6];

	for(i = 0; i < MAC_COLLECTION_MAX; i++) {

		if (ethernet_flow_macs_collection_get(i, src_mac)) {

			if (memcmp(src_mac, mac, 6) == 0) {
				return 1;
			}

		} else {
			return 0;
		}
	}

	return 0;
}

static void ethernet_flow_macs_collection_clear(void) {

	ethernet_flow_macs_collection_num = 0;
	ethernet_flow_macs_collection_start_index = 0;

}

static ssize_t ethernet_flow_macs_collection_ops_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) {
	int i;
	char buff[64];
	unsigned char src_mac[6];
	int len;
	int pos = 0;

	if(*ppos > 0) {
		return 0;
	}

	for(i = 0; i < MAC_COLLECTION_MAX; i++) {

		if (ethernet_flow_macs_collection_get(i, src_mac)) {

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

static struct file_operations ethernet_flow_macs_collection_ops =
{
	.owner = THIS_MODULE,
	.read = ethernet_flow_macs_collection_ops_read,
};

static ssize_t ethernet_flow_macs_collection_clear_ops_write(struct file *file, const char __user *buf,
				    size_t size, loff_t *_pos)
{
	char str[6];
	int n;

	n = size > sizeof(str) - 1 ? sizeof(str) - 1 : size;

	if (copy_from_user (str, buf, n) != 0) {
		return ENOMEM;
	}

	*_pos = n;

	if (str[0] == '1') {
		ethernet_flow_macs_collection_clear();
	}

	return n;
}

static struct file_operations ethernet_flow_macs_collection_clear_ops =
{
	.owner = THIS_MODULE,
	.write = ethernet_flow_macs_collection_clear_ops_write,
};

extern struct proc_dir_entry *ethernetflow_root;
static struct proc_dir_entry *ethernet_flow_macs_collection_table_proc;
static struct proc_dir_entry *ethernet_flow_macs_collection_clear_proc;

void ethernet_flow_macs_collection_init(void) {

	printk(KERN_INFO "ethernet_flow_macs_collection_init\n");

	ethernet_flow_macs_collection_table_proc = proc_create("macs_table", 0444, ethernetflow_root, &ethernet_flow_macs_collection_ops);
	ethernet_flow_macs_collection_clear_proc = proc_create("macs_clear", 0220, ethernetflow_root, &ethernet_flow_macs_collection_clear_ops);
}

void ethernet_flow_macs_collection_cleanup(void){
	printk(KERN_INFO "ethernet_flow_macs_collection_cleanup\n");

	if (ethernet_flow_macs_collection_table_proc)
		proc_remove(ethernet_flow_macs_collection_table_proc);

	if (ethernet_flow_macs_collection_clear_proc)
		proc_remove(ethernet_flow_macs_collection_clear_proc);
}
