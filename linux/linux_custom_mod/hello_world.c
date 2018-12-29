#include "linux/printk.h"
#include "linux/module.h"
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#include "ethernet_flow.h"

MODULE_DESCRIPTION("hello world module");
MODULE_LICENSE("GPL v2");

static char *hello_world_str = "hello world";
module_param(hello_world_str, charp, 0);

static struct proc_dir_entry *ent;

#define BUFSIZE 512
static char hello_world_buf[BUFSIZE];

static ssize_t hello_world_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos)
{
    ssize_t len = strlen(hello_world_buf);
    if(*ppos > 0 || count < len) {
        return 0;
    }

    if(copy_to_user(ubuf, hello_world_buf, len)) {
        return -EFAULT;
    }

    *ppos = len;
    return len;
}

static ssize_t hello_world_write(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos)
{
    if(*ppos > 0 || count > (BUFSIZE - 1)) {
        return -EFAULT;
    }

    if(copy_from_user(hello_world_buf, ubuf, count)) {
        return -EFAULT;
    }

    hello_world_buf[count] = '\0';

    return count;
}


static struct file_operations hello_world_ops =
{
    .owner = THIS_MODULE,
    .read = hello_world_read,
    .write = hello_world_write,
};

static int hello_world_init(void)
{
    ent = proc_create("hello_world", 0660, NULL, &hello_world_ops);
    printk(KERN_WARNING "hello_world_init\n");
    snprintf(hello_world_buf, BUFSIZE, hello_world_str);

    ethernet_flow_statistics_init();

    return 0;
}

static void hello_world_cleanup(void)
{
    printk(KERN_WARNING "hello_world_cleanup\n");
    proc_remove(ent);

    ethernet_flow_statistics_cleanup();
}

module_init(hello_world_init);
module_exit(hello_world_cleanup);
