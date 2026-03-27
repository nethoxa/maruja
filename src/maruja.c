/**********************
        INCLUDES
 **********************/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/string.h>
#include <linux/inet.h>
#include <linux/cdev.h>
#include <linux/device.h>


/**********************
        DEFINES
 **********************/
#define OK 0
#define IPADDR_LEN 16
#define IPADDR(addr) ((unsigned char *)&addr)[3], \
                     ((unsigned char *)&addr)[2], \
                     ((unsigned char *)&addr)[1], \
                     ((unsigned char *)&addr)[0]


/**********************
      GLOBAL VARS
 **********************/
static unsigned int fw_ip_count_max = 10;
module_param(fw_ip_count_max, uint, S_IWUSR | S_IRUSR);

static dev_t dev_num;
static struct cdev maruja_cdev;
static struct class *maruja_class;
static unsigned int fw_ip_count = 0;
static struct nf_hook_ops *hooker_ops_struct = NULL;
static char **firewall_rules;
static DEFINE_RWLOCK(fw_lock);


/**********************
       DEVNODE
 **********************/
static char *maruja_devnode(const struct device *dev, umode_t *mode)
{
    if (mode)
        *mode = 0666;
    return NULL;
}


/**********************
         FUNCS
 **********************/
static unsigned int firewall(const char *str)
{
    for (int i = 0; i < fw_ip_count; ++i) {
        if (!strcmp(str, firewall_rules[i]))
            return NF_DROP;
    }

    return NF_ACCEPT;
}


static unsigned int hooker(
        void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
    unsigned int ret;
    char str[IPADDR_LEN];
    struct iphdr *iph;
    u32 saddr;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    saddr = ntohl(iph->saddr);
    sprintf(str, "%u.%u.%u.%u", IPADDR(saddr));

    read_lock_bh(&fw_lock);
    ret = firewall(str);
    read_unlock_bh(&fw_lock);

    return ret;
}


static ssize_t maruja_read(
        struct file *file,
        char __user *buf,
        size_t count,
        loff_t *offset)
{
    size_t len = 0;
    char *temp_buf;
    int index = 0;

    if (*offset > 0)
        return 0;

    read_lock_bh(&fw_lock);

    for (int i = 0; i < fw_ip_count; ++i)
        len += strlen(firewall_rules[i]) + 1;

    if (len == 0) {
        read_unlock_bh(&fw_lock);
        return 0;
    }

    if (count < len) {
        read_unlock_bh(&fw_lock);
        return -EINVAL;
    }

    temp_buf = kmalloc(len, GFP_ATOMIC);
    if (!temp_buf) {
        read_unlock_bh(&fw_lock);
        return -ENOMEM;
    }

    for (int i = 0; i < fw_ip_count; ++i) {
        sprintf(temp_buf + index, "%s\n", firewall_rules[i]);
        index += strlen(firewall_rules[i]) + 1;
    }

    read_unlock_bh(&fw_lock);

    if (copy_to_user(buf, temp_buf, len)) {
        kfree(temp_buf);
        return -EFAULT;
    }

    kfree(temp_buf);
    *offset = len;
    return len;
}


static ssize_t maruja_write(
        struct file *file,
        const char __user *buf,
        size_t count,
        loff_t *offset)
{
    char input[IPADDR_LEN];
    char *ip_to_block;
    unsigned int i;
    __be32 addr;
    u8 *b;

    if (count == 0 || count > IPADDR_LEN)
        return -EINVAL;

    if (copy_from_user(input, buf, count))
        return -EFAULT;

    input[count - 1] = '\0';

    if (!in4_pton(input, -1, (u8 *)&addr, -1, NULL))
        return -EINVAL;

    // normalize to canonical form so strcmp always matches the hook format
    ip_to_block = kmalloc(IPADDR_LEN, GFP_KERNEL);
    if (!ip_to_block)
        return -ENOMEM;

    b = (u8 *)&addr;
    snprintf(ip_to_block, IPADDR_LEN, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);

    write_lock_bh(&fw_lock);

    // toggle: remove rule if it already exists
    for (i = 0; i < fw_ip_count; ++i) {
        if (strcmp(ip_to_block, firewall_rules[i]) == 0) {
            kfree(firewall_rules[i]);
            firewall_rules[i] = firewall_rules[fw_ip_count - 1];
            firewall_rules[fw_ip_count - 1] = NULL;
            --fw_ip_count;

            write_unlock_bh(&fw_lock);
            printk(KERN_INFO "MARUJA: rule %s removed\n", ip_to_block);
            kfree(ip_to_block);
            return count;
        }
    }

    if (fw_ip_count >= fw_ip_count_max) {
        write_unlock_bh(&fw_lock);
        kfree(ip_to_block);
        return -ENOSPC;
    }

    firewall_rules[fw_ip_count] = ip_to_block;
    ++fw_ip_count;

    write_unlock_bh(&fw_lock);
    printk(KERN_INFO "MARUJA: rule %s added\n", ip_to_block);
    return count;
}


static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .read  = maruja_read,
    .write = maruja_write,
};


static int __init maruja_init(void)
{
    int ret;

    firewall_rules = kcalloc(fw_ip_count_max, sizeof(char *), GFP_KERNEL);
    if (!firewall_rules)
        return -ENOMEM;

    hooker_ops_struct = kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (!hooker_ops_struct) {
        ret = -ENOMEM;
        goto err_hook_alloc;
    }

    hooker_ops_struct->hook     = (nf_hookfn *)hooker;
    hooker_ops_struct->hooknum  = NF_INET_PRE_ROUTING;
    hooker_ops_struct->pf       = NFPROTO_IPV4;
    hooker_ops_struct->priority = NF_IP_PRI_FIRST + 1;

    ret = nf_register_net_hook(&init_net, hooker_ops_struct);
    if (ret)
        goto err_hook_reg;

    ret = alloc_chrdev_region(&dev_num, 0, 1, "maruja");
    if (ret < 0)
        goto err_chrdev_alloc;

    cdev_init(&maruja_cdev, &fops);
    ret = cdev_add(&maruja_cdev, dev_num, 1);
    if (ret < 0)
        goto err_cdev_add;

    maruja_class = class_create("maruja");
    if (IS_ERR(maruja_class)) {
        ret = PTR_ERR(maruja_class);
        goto err_class;
    }
    maruja_class->devnode = maruja_devnode;

    if (IS_ERR(device_create(maruja_class, NULL, dev_num, NULL, "maruja"))) {
        ret = -ENOMEM;
        goto err_device;
    }

    printk(KERN_INFO "MARUJA: loaded (max %d rules)\n", fw_ip_count_max);
    return OK;

err_device:
    class_destroy(maruja_class);
err_class:
    cdev_del(&maruja_cdev);
err_cdev_add:
    unregister_chrdev_region(dev_num, 1);
err_chrdev_alloc:
    nf_unregister_net_hook(&init_net, hooker_ops_struct);
err_hook_reg:
    kfree(hooker_ops_struct);
err_hook_alloc:
    kfree(firewall_rules);
    return ret;
}


static void __exit maruja_exit(void)
{
    write_lock_bh(&fw_lock);
    for (int i = 0; i < fw_ip_count; ++i)
        kfree(firewall_rules[i]);
    write_unlock_bh(&fw_lock);

    device_destroy(maruja_class, dev_num);
    class_destroy(maruja_class);
    cdev_del(&maruja_cdev);
    unregister_chrdev_region(dev_num, 1);
    nf_unregister_net_hook(&init_net, hooker_ops_struct);
    kfree(hooker_ops_struct);
    kfree(firewall_rules);

    printk(KERN_INFO "MARUJA: unloaded\n");
}


module_init(maruja_init);
module_exit(maruja_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nethoxa");
MODULE_DESCRIPTION("Lightweight IP-based packet filtering using Netfilter");
MODULE_VERSION("0.2");
