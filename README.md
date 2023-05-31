# MARUJA
## Index
- [MARUJA](#maruja)
  - [Index](#index)
  - [Layout](#layout)
  - [Video](#video)
  - [Description](#description-\(in Spanish,-\(->-_-\)->\))
  - [Usage](#usage)

## Layout
- `bin` --- location of `maruja.ko`
- `video` --- POC
- `src` --- location of `maruja.c` and `Makefile`
- `README.md` --- this file
- `run.sh` --- pseudo terminal to interact with maruja
- `install.sh` --- to install the driver without running a pseudo terminal

## Video
https://github.com/erebus-eth/maruja/assets/135072738/bcf61fe8-e5b4-43bb-942a-dd25a9ea40bf

## Description (in Spanish, (->-_-)->)
El driver consiste en un firewall en miniatura que por ahora sólo sirve para bloquear IPs. Tiene dos fallos mínimos:
1. permite que se le pasen cadenas diferentes a una IP, siempre que estén en la longitud establecida (en python haces un isX() y listo, en C era como un gato con un ovillo de lana ~~)
2. la función `read` no va porque se queda haciendo un bucle infinito llamando a `maruja_read` al hacerle el `cat /dev/maruja`.

En el bloque de los `defines`, lo que hay que destacar es el macro `IPADDR` para sacar una IP de un buffer de caracteres:

```c
#define IPADDR(addr) ((unsigned char *)&addr)[3], \
                     ((unsigned char *)&addr)[2], \
                     ((unsigned char *)&addr)[1], \
                     ((unsigned char *)&addr)[0]
```

Posteriormente definimos las variables globales a usar

```c
static unsigned int fw_ip_count_max = 10;
module_param(fw_ip_count_max, int, S_IWUSR | S_IRUSR);

static int major;
static unsigned int fw_ip_count = 0;
static struct nf_hook_ops *hooker_ops_struct = NULL;
static struct file_operations fops;

static char **firewall_rules;
```

donde `fw_ip_count_max` es el número máximo de reglas distintas permitidas en el firewall, el cual se le puede pasar al driver al inicializarlo con `sudo insmod maruja.ko`. El `fw_ip_count` es un contador clásico para llevar el número de reglas, el `hooker_ops_struct` lo utilizamos para declarar un hooker que posteriormente lo usaremos para inspeccionar los paquetes recibidos. El `firewall_rules` será el buffer donde guardaremos las claves (es mejor un `dict` pero estamos en C -_-).

La función `firewall`

```c
static unsigned int firewall(char *str)
```

recorre `firewall_rules` comprobando si el paquete viene de una dirección bloqueada y lo rechaza con `NF_DROP`. Si no, lo acepta con `NF_ACCEPT`.

La función `hooker`

```c
static unsigned int hooker(
        void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state
)
```

extrae la cabecera IP y la dirección de origen y se la pasa a la función `firewall`, devolviendo su valor (`NF_DROP` o `NF_ACCEPT`)

```c
// store ip header and source addr
char *str = (char *)kmalloc(16, GFP_KERNEL);
struct iphdr *iph =ip_hdr(skb);
u32 saddr = ntohl(iph->saddr);

// ip format
sprintf(str, "%u.%u.%u.%u", IPADDR(saddr));

// printk(KERN_INFO "DBG -> Packet from %s", str);

return firewall(str);
```

La función `maruja_read`

```c
static ssize_t maruja_read(
        struct file *file,
        char *buf,
        size_t count,
        loff_t *offset
)
```

es la función `read` de los chrdevs, sólo que, como he dicho antes, hace un bucle infinito llamándose a sí misma. No tengo ni idea del porqué. Su funcionamiento es muy simpe, devolver un buffer con todas las reglas del firewall separadas por un `'\n'` y lo hace bien, pero el kernel hace de las suyas y no sé cómo arreglarlo.

La función `maruja-write`

```c
static ssize_t maruja_write(
        struct file *file,
        const char *buf,
        size_t count,
        loff_t *offset
)
```

comienza comprobando si el número de reglas es igual al máximo (con un dict esto no es necesario), para luego ver que, al menos, la IP tiene una longitud normal con
```c
// sanitizer ~~ kinda
if(count < IPADDR_MIN_LEN || count > IPADDR_LEN)
```

Posteriormente inicializa un hueco en el firewall, ve si estaba ya la IP a bloquear. Si es así, la elimina del firewall y la almacena en caso contrario.

La función `maruja_init`

```c
static int __init maruja_init(void) 
```

reserva un hueco de memoria para el `firewall`. Posteriormente, rellena el `hooker_ops_struct` para registrar el hooker de red en el sistema con

```c
nf_register_net_hook(&init_net, hooker_ops_struct);
```

luego el `fops` típico para los `read`/`write`de siempre y devuelve un mensaje en el log indicando que se ha cargado correctamente.

La función `maruja_exit`

```c
static void __exit maruja_exit(void)
```

simplemente libera la memoria perteneciente a las reglas del `firewall`, elimina el hooker de red y el chrdev y libera la memoria de los structs asociados, indicando con un mensaje en el log que se ha eliminado correctamente del sistema.


## Usage
Abre una terminal en el directorio raíz del proyecto y ejecuta

```bash
./run.sh
```

y se debería abrir un programa que sirve para compilar e instrumentalizar el driver. Si quieres instalarlo y hacer las peticiones tú mismo, ejecuta

```bash
./install.sh
```

para instalarlo. Para el `write`

```bash
echo <IP> > /dev/maruja
```

y para el `read` que NO FUNCIONA

```bash
cat /dev/maruja
```
