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
#include <linux/udp.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#define DEVICE_NAME "net_sniffer"
#define CLASS_NAME  "sniffer"
#define PROC_FILENAME "sniffer"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Team 17 L03");
MODULE_DESCRIPTION("A simple packet sniffer");

static struct nf_hook_ops nf_pre_routing_ops;
static struct nf_hook_ops nf_post_routing_ops;

// Procfile log 
static char *log_buf;
static size_t log_buf_size = 0;
static size_t log_buf_capacity = 4096;

static int major_number;
static struct class* sniffer_class = NULL;
static struct device* sniffer_device = NULL;
static char message[256] = {0};
static struct cdev sniffer_cdev;

static void log_packet(const char *prefix, struct sk_buff *skb)
{
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph;
    struct udphdr *udph;
    int len;

    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);

        // Print into message buffer
        snprintf(message, sizeof(message),
                     "%12s [TCP]: SRC=%pI4:%d DST=%pI4:%d\n",prefix,
                     &iph->saddr, ntohs(tcph->source),
                     &iph->daddr, ntohs(tcph->dest));
            
        // Print into procfile buffer
        len = snprintf(log_buf + log_buf_size, 256,
                       "%12s [TCP]: SRC: %pI4:%d, DST: %pI4:%d\n",
                       prefix, &iph->saddr, ntohs(tcph->source), &iph->daddr, ntohs(tcph->dest));

    }  else if (iph->protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);

        // Print into message buffer
        snprintf(message, sizeof(message),
                     "%12s [UDP]: SRC=%pI4:%d DST=%pI4:%d\n",prefix,
                     &iph->saddr, ntohs(udph->source),
                     &iph->daddr, ntohs(udph->dest));

        // Print into procfile buffer
        len = snprintf(log_buf + log_buf_size, 256,
                       "%12s [UDP]: SRC: %pI4:%d, DST: %pI4:%d\n",
                       prefix, &iph->saddr, ntohs(udph->source), &iph->daddr, ntohs(udph->dest));
    } else {
        return;  // Not TCP or UDP, skip logging
    }

    if (log_buf_size + len > log_buf_capacity) {
        log_buf_size = 0;  // Reset the buffer if it exceeds capacity
    }

    log_buf_size += len;
}

unsigned int pre_routing_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    log_packet("PRE_ROUTING", skb);
    return NF_ACCEPT;
}

unsigned int post_routing_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    log_packet("POST_ROUTING", skb);
    return NF_ACCEPT;
}

static int proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "%s", log_buf);
    return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show, NULL);
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

static const struct proc_ops proc_file_ops = {
    .proc_open = proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
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

    // Procfile
    log_buf = kzalloc(log_buf_capacity, GFP_KERNEL);
    if (!log_buf) {
        printk(KERN_ERR "Failed to allocate memory for log buffer\n");
        return -ENOMEM;
    }

    proc_create(PROC_FILENAME, 0, NULL, &proc_file_ops);

    // Pre-routing
    nf_pre_routing_ops.hook = pre_routing_hook;
    nf_pre_routing_ops.pf = PF_INET;
    nf_pre_routing_ops.hooknum = NF_INET_PRE_ROUTING;
    nf_pre_routing_ops.priority = NF_IP_PRI_FIRST;

    // Post-routing
    nf_post_routing_ops.hook = post_routing_hook;
    nf_post_routing_ops.pf = PF_INET;
    nf_post_routing_ops.hooknum = NF_INET_PRE_ROUTING;
    nf_post_routing_ops.priority = NF_IP_PRI_FIRST;


    nf_register_net_hook(&init_net, &nf_pre_routing_ops);
    nf_register_net_hook(&init_net, &nf_post_routing_ops);

    printk(KERN_INFO "Packet sniffer loaded\n");
    return 0;
}

static void __exit sniffer_exit(void) {
    nf_unregister_net_hook(&init_net, &nf_pre_routing_ops);
    nf_unregister_net_hook(&init_net, &nf_post_routing_ops);

    remove_proc_entry(PROC_FILENAME, NULL);
    kfree(log_buf);

    cdev_del(&sniffer_cdev);
    device_destroy(sniffer_class, MKDEV(major_number, 0));
    class_unregister(sniffer_class);
    class_destroy(sniffer_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_INFO "Packet sniffer unloaded\n");
}

module_init(sniffer_init);
module_exit(sniffer_exit);
