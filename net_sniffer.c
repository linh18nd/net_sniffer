#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <net/ip.h>
#include <net/tcp.h>

#define DEVICE_NAME "net_sniffer"
#define CLASS_NAME  "sniffer"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple packet sniffer");

static struct nf_hook_ops netfilter_ops;
static int major_number;
static struct class* sniffer_class = NULL;
static struct device* sniffer_device = NULL;
static char message[256] = {0};
static struct cdev sniffer_cdev;

unsigned int main_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    if (skb) {
        struct iphdr *ip = ip_hdr(skb);
        struct tcphdr *tcp;

        if (ip->protocol == IPPROTO_TCP) {
            tcp = tcp_hdr(skb);
            snprintf(message, sizeof(message),
                     "TCP packet: SRC=%pI4:%d DST=%pI4:%d\n",
                     &ip->saddr, ntohs(tcp->source),
                     &ip->daddr, ntohs(tcp->dest));
        }
    }
    return NF_ACCEPT;
}

static int dev_open_fn(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "net_sniffer: Device has been opened\n");
    return 0;
}

static ssize_t dev_read_fn(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    int error_count = copy_to_user(buffer, message, strlen(message));

    if (error_count == 0) {
        printk(KERN_INFO "net_sniffer: Sent %zu characters to the user\n", strlen(message));
        return (strlen(message) == 0) ? 0 : strlen(message);
    } else {
        printk(KERN_INFO "net_sniffer: Failed to send %d characters to the user\n", error_count);
        return -EFAULT;
    }
}

static int dev_release_fn(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "net_sniffer: Device successfully closed\n");
    return 0;
}

static struct file_operations fops = {
    .open = dev_open_fn,
    .read = dev_read_fn,
    .release = dev_release_fn,
};

static int __init sniffer_init(void) {
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "net_sniffer failed to register a major number\n");
        return major_number;
    }
    printk(KERN_INFO "net_sniffer: registered correctly with major number %d\n", major_number);

    sniffer_class = class_create(CLASS_NAME);
    if (IS_ERR(sniffer_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(sniffer_class);
    }
    printk(KERN_INFO "net_sniffer: device class registered correctly\n");

    sniffer_device = device_create(sniffer_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(sniffer_device)) {
        class_destroy(sniffer_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(sniffer_device);
    }
    printk(KERN_INFO "net_sniffer: device class created correctly\n");

    cdev_init(&sniffer_cdev, &fops);
    sniffer_cdev.owner = THIS_MODULE;
    if (cdev_add(&sniffer_cdev, MKDEV(major_number, 0), 1) == -1) {
        device_destroy(sniffer_class, MKDEV(major_number, 0));
        class_destroy(sniffer_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return -1;
    }

    netfilter_ops.hook = main_hook;
    netfilter_ops.pf = PF_INET;
    netfilter_ops.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &netfilter_ops);
    printk(KERN_INFO "Packet sniffer loaded\n");
    return 0;
}

static void __exit sniffer_exit(void) {
    nf_unregister_net_hook(&init_net, &netfilter_ops);
    cdev_del(&sniffer_cdev);
    device_destroy(sniffer_class, MKDEV(major_number, 0));
    class_unregister(sniffer_class);
    class_destroy(sniffer_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_INFO "Packet sniffer unloaded\n");
}

module_init(sniffer_init);
module_exit(sniffer_exit);

