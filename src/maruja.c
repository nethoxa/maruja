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
            // regla activada, paquete a la basura
            // DBG printk(KERN_INFO "Paquete de %s rechazado\n", str); // TODO para ver los rechazados
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
        // si no hay si no hay paquetes, pasamos
        return NF_ACCEPT;

    } else {
        // hay paquete, maruja en marcha
        // variable para almacenar la ip del paquete
        char *str = (char *)kmalloc(16, GFP_KERNEL);

        // cabecera ip y dirección de origen
        struct iphdr *iph =ip_hdr(skb);
        u32 saddr = ntohl(iph->saddr);

        // ip format
        sprintf(str, "%u.%u.%u.%u", IPADDR(saddr));

        // printk(KERN_INFO "DBG -> Paquete de %s", str); // TODO para ver los entrantes

        return firewall(str);
    }
}

/* está perfecta, pero en mi ordenador el cat devuelve un de forma infinita la lista de IPs, dale a los DBG para verlo

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
        printk(KERN_ERR "El firewall está lleno\n");
        return -EINVAL;
    }

    // sanitizer ~~ kinda
    if(count < IPADDR_MIN_LEN || count > IPADDR_LEN) {
        printk(KERN_ERR "Mala ip\n");
        return -EINVAL;
    }

    // bloque para la IP
    ip_to_block = (char*) kmalloc(count, GFP_KERNEL);
    if (ip_to_block == NULL) {
        printk(KERN_ERR "MARUJA dice que no hay memoria en el maruja_write, wtf\n");
        return -ENOMEM;
    }

    // copy
    if (copy_from_user(ip_to_block, buf, count) != 0) {
        kfree(ip_to_block);
        return -EFAULT;
    }


    // esto me ha dado más problemas que su...
    if (ip_to_block[count - 1] == '\n') {
        ip_to_block[count - 1] = '\0';
    }

    // si la regla ya estaba, se elimina del firewall
    for (i = 0; i < fw_ip_count; ++i) {
        // DBG printk(KERN_INFO "Comprobando %s con %s de resultado %d\n", ip_to_block, firewall_rules[i], strcmp(ip_to_block, firewall_rules[i]));
        if (strcmp(ip_to_block, firewall_rules[i]) == 0) {
            firewall_rules[i] = firewall_rules[fw_ip_count - 1];
            kfree(firewall_rules[fw_ip_count - 1]);
            --fw_ip_count;
            // TODO nota mental ==> SIEMPRE PON \n EN EL KERNEL
            printk(KERN_INFO "Regla %s eliminada\n", ip_to_block);
            kfree(ip_to_block);
            return count;
        }
    }

    // bloque del firewall
    firewall_rules[fw_ip_count] = (char*) kmalloc(count, GFP_KERNEL);
    if (ip_to_block == NULL) {
        printk(KERN_ERR "MARUJA dice que no hay memoria en el maruja_write, wtf\n");
        return -ENOMEM;
    }

    // añadimos la regla
    printk(KERN_INFO "Regla %s añadida\n", ip_to_block);
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
        printk(KERN_ERR "MARUJA dice que no hay memoria en el maruja_init, wtf\n");
        return -ENOMEM;

    }

    // rellenar el struct II...
    fops.owner = THIS_MODULE;
    fops.write = maruja_write;
    // fops.read = maruja_read; // TODO para que no pete la comento

    major = register_chrdev(0, "MARUJA", &fops);
    if(major < 0) {
        printk(KERN_ERR "MARUJA dice que no se puede registrar como chardev\n");
        return ERROR;

    }

    printk(KERN_INFO "MARUJA chardev registrado correctamente con major %d y tamaño del firewall de %d\n", major, fw_ip_count_max);

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
    printk(KERN_INFO "MARUJA se ha ido\n");
}

module_init(maruja_init);
module_exit(maruja_exit);

MODULE_LICENSE("GPL");

