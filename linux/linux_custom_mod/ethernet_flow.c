#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>

typedef struct ethernetflow {
	char 			macs[12];	// both dst and src
	unsigned long int 	packet;
} ethernetflow;

static int ethernet_flow_max = 50;
static ethernetflow *current_statistic;
static int current_statistic_num = 0;

void ethernetflow_add_frame(const unsigned char macs[]) {
	int i;

	for(i = 0; i < current_statistic_num; i++) {
		if (memcmp(macs, current_statistic[i].macs, 12) == 0) {
			current_statistic[i].packet++;
			return;
		}
	}

	if (current_statistic_num < ethernet_flow_max) {
		memcpy(current_statistic[current_statistic_num].macs, macs, 12);
		current_statistic[i].packet = 1;;
		current_statistic_num++;
	}
}

extern struct proc_dir_entry *ethernetFlowStatistics_proc_dir_ent;

static ssize_t ethernetflow_table_ops_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos)
{
	int i;
	char buff[64];
	int len;
	int pos = 0;

	if(*ppos > 0) {
		return 0;
	}

	for(i = 0; i < current_statistic_num; i++) {

		{
			len = sprintf(buff, "%02d: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x : %08lu\n",
				i,
				// dst mac
				(unsigned char) current_statistic[i].macs[0],
				(unsigned char) current_statistic[i].macs[1],
				(unsigned char) current_statistic[i].macs[2],
				(unsigned char) current_statistic[i].macs[3],
				(unsigned char) current_statistic[i].macs[4],
				(unsigned char) current_statistic[i].macs[5],
				// src mac
				(unsigned char) current_statistic[i].macs[6],
				(unsigned char) current_statistic[i].macs[7],
				(unsigned char) current_statistic[i].macs[8],
				(unsigned char) current_statistic[i].macs[9],
				(unsigned char) current_statistic[i].macs[10],
				(unsigned char) current_statistic[i].macs[11],
				current_statistic[i].packet);

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

static struct file_operations ethernetflow_table_ops =
{
	.owner = THIS_MODULE,
	.read = ethernetflow_table_ops_read,
};

static ssize_t ethernetflow_size_ops_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos)
{
	char buff[64];
	int len;
	int pos = 0;

	if(*ppos > 0) {
		return 0;
	}

	len = sprintf(buff, "%d", ethernet_flow_max);
	pos += len;

	if (pos <= count) {
		if(copy_to_user(ubuf + (pos - len), buff, len)) {
			return -EFAULT;
		}
	}

	*ppos = pos;
	return pos;
}

static ssize_t ethernetflow_size_ops_write(struct file *file, const char __user *buf,
				    size_t size, loff_t *_pos)
{
	char str[32];
	int n;
	int val;

	val = 0;

	n = size > sizeof(str) - 1 ? sizeof(str) - 1 : size;

	if (copy_from_user (str, buf, n) != 0) {
		return ENOMEM;
	}

	*_pos = n;

	str[n] = '\0';

	if (sscanf(str, "%d\n", &val) == 1) {
		if (val > 5 && val < 1000 && val != ethernet_flow_max) {

			current_statistic_num = 0;

			if (current_statistic) {
				kfree(current_statistic);
			}

			ethernet_flow_max = val;
			current_statistic = kmalloc(sizeof(ethernetflow) * ethernet_flow_max, GFP_KERNEL);
		}
	}

	return n;
}


static struct file_operations ethernetflow_size_ops =
{
	.owner = THIS_MODULE,
	.read = ethernetflow_size_ops_read,
	.write = ethernetflow_size_ops_write,
};

static ssize_t ethernetflow_clear_ops_write(struct file *file, const char __user *buf,
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
		current_statistic_num = 0;
	}

	return n;
}

static struct file_operations ethernetflow_clear_ops =
{
	.owner = THIS_MODULE,
	.write = ethernetflow_clear_ops_write,
};

extern struct proc_dir_entry *ethernetflow_root;
static struct proc_dir_entry *ethernetflow_table_proc;
static struct proc_dir_entry *ethernetflow_size_proc;
static struct proc_dir_entry *ethernetflow_clear_proc;

void ethernet_flow_init(void) {

	printk(KERN_INFO "ethernet_flow_init\n");

	current_statistic = kmalloc(sizeof(ethernetflow) * ethernet_flow_max, GFP_KERNEL);

	ethernetflow_table_proc = proc_create("flow_table", 0444, ethernetflow_root, &ethernetflow_table_ops);
	ethernetflow_size_proc = proc_create("flow_size", 0660, ethernetflow_root, &ethernetflow_size_ops);
	ethernetflow_clear_proc = proc_create("flow_clear", 0220, ethernetflow_root, &ethernetflow_clear_ops);
}

void ethernet_flow_cleanup(void){
	printk(KERN_INFO "ethernet_flow_cleanup\n");

	if (ethernetflow_table_proc)
		proc_remove(ethernetflow_table_proc);

	if (ethernetflow_size_proc)
		proc_remove(ethernetflow_size_proc);

	if (ethernetflow_clear_proc)
		proc_remove(ethernetflow_clear_proc);

	if (current_statistic)
		kfree(current_statistic);
}
