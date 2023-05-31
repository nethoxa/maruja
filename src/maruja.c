/**********************
        INCLUDES
 **********************/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>


/**********************
        DEFINES
 **********************/
#define OK 0
#define ERROR -1
#define IPADDR_LEN 16
#define IPADDR_MIN_LEN 8
#define IPADDR(addr) ((unsigned char *)&addr)[3], \
                     ((unsigned char *)&addr)[2], \
                     ((unsigned char *)&addr)[1], \
                     ((unsigned char *)&addr)[0]


/**********************
      GLOBAL VARS
 **********************/
static unsigned int fw_ip_count_max = 10;
module_param(fw_ip_count_max, int, S_IWUSR | S_IRUSR);

static int major;
static unsigned int fw_ip_count = 0;
static struct nf_hook_ops *hooker_ops_struct = NULL;
static struct file_operations fops;

static char **firewall_rules;


/**********************
         FUNCS
 **********************/
static unsigned int firewall(char *str) {
    for(int i = 0; i < fw_ip_count; ++i) {
        if (!strcmp(str, firewall_rules[i])) {
            // rule triggered, packet out
            // DBG printk(KERN_INFO "Packet from %s rejected\n", str);
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}


static unsigned int hooker(
        void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state
)
{
    if(!skb) {
        // idle ~~
        return NF_ACCEPT;

    } else {
        // store ip header and source addr
        char *str = (char *)kmalloc(16, GFP_KERNEL);
        struct iphdr *iph =ip_hdr(skb);
        u32 saddr = ntohl(iph->saddr);

        // ip format
        sprintf(str, "%u.%u.%u.%u", IPADDR(saddr));

        // printk(KERN_INFO "DBG -> Packet from %s", str);

        return firewall(str);
    }
}


// TODO lil weird bug
/*
static ssize_t maruja_read(
        struct file *file,
        char *buf,
        size_t count,
        loff_t *offset
)
{
    // tamaño de todas las cadenas más separador
    size_t len = 0;
    for (int i = 0; i < fw_ip_count; ++i) {
        len += strlen(firewall_rules[i]) + 1; // Add 1 for the separator
    }

    // checks
    if (count < len) {
        printk(KERN_ERR "El buffer para copiar todas las reglas es muy pequeño\n");
        return -EINVAL;
    }

    char *temp_buf = (char *)kmalloc(len, GFP_KERNEL);
    if (temp_buf == NULL) {
        printk(KERN_ERR "No hay suficiente memoria en maruja_read, wtf\n");
        return -ENOMEM;
    }

    // concatenamos
    int index = 0;
    for (int i = 0; i < fw_ip_count; ++i) {
        sprintf(temp_buf + index, "%s\n", firewall_rules[i]);
        index += strlen(firewall_rules[i]) + 1; // Add 1 for the separator
        // DBG printk(KERN_INFO "EING -> %s y %d\n", temp_buf, fw_ip_count);
    }

    // copiamos al buffer
    if (copy_to_user(buf, temp_buf, len)) {
        printk(KERN_ERR "Failed to copy rules to user buffer\n");
        kfree(temp_buf);
        return -EFAULT;
    }


    kfree(temp_buf);
    return len;
}*/


static ssize_t maruja_write(
        struct file *file,
        const char *buf,
        size_t count,
        loff_t *offset
)
{
    char *ip_to_block;
    unsigned int i;

    if(fw_ip_count == fw_ip_count_max) {
        printk(KERN_ERR "Firewall is full\n");
        return -EINVAL;
    }

    // sanitizer ~~ kinda
    if(count < IPADDR_MIN_LEN || count > IPADDR_LEN) {
        printk(KERN_ERR "Bad ip\n");
        return -EINVAL;
    }

    // IP stuff
    ip_to_block = (char*) kmalloc(count, GFP_KERNEL);
    if (ip_to_block == NULL) {
        printk(KERN_ERR "MARUJA no mem in 1, wtf\n");
        return -ENOMEM;
    }

    // copy
    if (copy_from_user(ip_to_block, buf, count) != 0) {
        kfree(ip_to_block);
        return -EFAULT;
    }


    // fuck C strings
    if (ip_to_block[count - 1] == '\n') {
        ip_to_block[count - 1] = '\0';
    }

    // delete rule from firewall if it did exist
    for (i = 0; i < fw_ip_count; ++i) {
        // DBG printk(KERN_INFO "Checking %s with %s with result %d\n", ip_to_block, firewall_rules[i], strcmp(ip_to_block, firewall_rules[i]));
        if (strcmp(ip_to_block, firewall_rules[i]) == 0) {
            firewall_rules[i] = firewall_rules[fw_ip_count - 1];
            kfree(firewall_rules[fw_ip_count - 1]);
            --fw_ip_count;

            printk(KERN_INFO "Rule %s deleted\n", ip_to_block);
            kfree(ip_to_block);
            return count;
        }
    }

    // firewall stuff
    firewall_rules[fw_ip_count] = (char*) kmalloc(count, GFP_KERNEL);
    if (ip_to_block == NULL) {
        printk(KERN_ERR "MARUJA no mem in 2, wtf\n");
        return -ENOMEM;
    }

    // add rule
    printk(KERN_INFO "Rule %s added\n", ip_to_block);
    firewall_rules[fw_ip_count] = ip_to_block;
    ++fw_ip_count;
    return count;
}



static int __init maruja_init(void) {
    firewall_rules = (char **)kmalloc(sizeof(char), GFP_KERNEL);
    if(firewall_rules == NULL) {
        return -ENOMEM;
    }


    // rellenar el struct I...
    hooker_ops_struct = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (hooker_ops_struct != NULL) {
        hooker_ops_struct->hook = (nf_hookfn*)hooker;
        hooker_ops_struct->hooknum = NF_INET_PRE_ROUTING;
        hooker_ops_struct->pf = NFPROTO_IPV4;
        hooker_ops_struct->priority = NF_IP_PRI_FIRST + 1;

        nf_register_net_hook(&init_net, hooker_ops_struct);

    } else {
        printk(KERN_ERR "MARUJA no mem in 3, wtf\n");
        return -ENOMEM;

    }

    fops.owner = THIS_MODULE;
    fops.write = maruja_write;
    // fops.read = maruja_read; TODO lil weird bug

    major = register_chrdev(0, "MARUJA", &fops);
    if(major < 0) {
        printk(KERN_ERR "MARUJA no chardev\n");
        return ERROR;

    }

    printk(KERN_INFO "MARUJA registered chardev correctly with major %d and firewall size of %d\n", major, fw_ip_count_max);

    return OK;
}


static void __exit maruja_exit(void) {
    if(fw_ip_count) {
        for(int i = 0; i < fw_ip_count; ++i) {
            kfree(firewall_rules[i]);
        }
    }

    nf_unregister_net_hook(&init_net, hooker_ops_struct);
    kfree(hooker_ops_struct);
    unregister_chrdev(major, "MARUJA");
    printk(KERN_INFO "MARUJA bye bye\n");
}

module_init(maruja_init);
module_exit(maruja_exit);

MODULE_LICENSE("GPL");

