#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <linux/version.h>
#if 0
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	#include <linux/config.h>
#else
	#include <linux/autoconf.h>
#endif
#endif
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/delay.h>
#include <linux/netfilter_ipv4.h>
#include <linux/spi/spi.h>
#include <linux/gpio.h>
#include <linux/irq.h>

#include <linux/tcp.h>
#include <net/tcp.h>

#include <asm/uaccess.h>
#include <asm/unaligned.h>
//#include <asm/system.h>
#include <linux/spinlock.h>

volatile unsigned *_rGPFDAT;
#include "w5x00.h"
#include "queue.h"

//#define DEBUG_PKT
#if 0
#define DPRINTK(format,args...) printk(format,##args)
#else
#define DPRINTK(format,args...)
#endif

#if BUSWIDTH==BUS8
	#define BUS_SHIFT 0
#endif

#define W5X00_SHADOW_TIMEOUT	2
#define LOCAL_PORT 	3010


#include <linux/spi/spi.h>
#include "queue.h"

#include <linux/gpio.h>
#include "w5x00.h"


/****************************************************************************
 *
 * driver/queue.c
 */


static LIST_HEAD(tx_skb);

SKB_NODE *alloc_skb_node(void)
{
	SKB_NODE *p = kmalloc(sizeof(SKB_NODE), GFP_KERNEL);

	return p;
}

void free_skb_node(SKB_NODE *p)
{
	kfree(p);
}

void push_skb(SKB_NODE *p)
{
	list_add_tail(&(p->list), &tx_skb);
}

SKB_NODE *pop_skb(void)
{
	struct list_head *head;

	if(list_empty(&tx_skb))
	{
		return NULL;
	}

	head = tx_skb.next;
	list_del(head);

	return list_entry(head, SKB_NODE, list);
}






/****************************************************************************
 *
 * driver/netdrv.c
 */

/*********************************************
 * network interface driver support
 *********************************************/

extern struct spi_device *spi_device;
extern struct workqueue_struct *w5x00_wq;

//#define DEBUG_PKT
#if 0
#define DPRINTK(format,args...) printk(format,##args)
#else
#define DPRINTK(format,args...)
#endif

/*
 * Open/initialize the board. This is called (in the current kernel)
 * sometime after booting when the 'ifconfig' program is run.
 *
 * This routine should set everything up anew at each open, even
 * registers that "should" only need to be set once at boot, so that
 * there is non-reboot way to recover if something goes wrong.
 */
static int
wiznet_open(struct net_device *dev)
{
	struct wiz_private *wp = netdev_priv(dev);
	int r;

	/* create socket */
	r = iinchip_netif_create(dev);
	if (r < 0) {
		printk("%s: can't create socket\n", dev->name);
		return -EFAULT;
	}

	/* open socket */
	r = iinchip_open(wp->s, WSOCK_MACL_RAWM, 0);
	if (r < 0) {
		printk("%s: can't open socket\n", dev->name);
		return -EFAULT;
	}

	/*
	 * start driver.
	 */
	netif_start_queue(dev);

	return 0;
}


/*
 * The inverse routine to net_open().
 */
static int
wiznet_close(struct net_device *dev)
{
	struct wiz_private *wp = netdev_priv(dev);

	/*
	 * stop driver.
	 */
	netif_stop_queue(dev);

	// close socket
	iinchip_close(wp->s);

	// delete interface
	iinchip_netif_delete(dev);

	return 0;
}

/* This will only be invoked if the driver is _not_ in XOFF state.
 * What this means is that we need not check it, and that this
 * invariant will hold if we make sure that the netif_*_queue()
 * calls are done at the proper times.
 */
static int
wiznet_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct wiz_private *wp = netdev_priv(dev);
	SKB_NODE *p;

	p = alloc_skb_node();
	if(p == NULL) {
		printk("skb alloc failed\n");
		return 0;
	}

	p->skb = skb;
	push_skb(p);

	queue_work(w5x00_wq, &(wp->wiz->tx_work));
	return 0;
}

/*
 * Get the current statistics.
 * This may be called with the card open or closed.
 */
static struct net_device_stats *
wiznet_get_stats(struct net_device *dev)
{
	struct wiz_private *wp = netdev_priv(dev);

	return (&wp->stats);
}

/*
 * set MAC address of the interface. called from the core after a
 * SIOCSIFADDR ioctl, and from the bootup above.
 */
static int
wiznet_set_address(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	/* update */
	iinchip_socket_sethwaddr(addr->sa_data);

	/* remember it */
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

	return 0;
}

/*
 * Set or clear the multicast filter for this adaptor.
 * num_addrs == -1	Promiscuous mode, receive all packets
 * num_addrs == 0	Normal mode, clear multicast list
 * num_addrs > 0	Multicast mode, receive normal and MC packets,
 *			and do best-effort filtering.
 */
static void
wiznet_set_multicast(struct net_device *dev)
{
	if (dev->flags & IFF_PROMISC) {
		/* promiscuous mode */

	} else if (dev->flags & IFF_ALLMULTI) {
		/* MC mode, receive normal and MC packets */

	} else {
		/* Normal, clear the mc list */

	}
}

static void
wiznet_tx_timeout(struct net_device *dev)
{
	struct wiz_private *wp = netdev_priv(dev);

	wp->stats.tx_errors++;
}

/* ioctl service */
static int
wiznet_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct s_wiznet_ioctl req;
	int err = 0;

	if (!capable (CAP_NET_ADMIN))
		return -EPERM;

	if (dev == NULL)
		return -ENODEV;

	if (cmd != WIZNETIOCTL)
		return -ENOTTY;

	err = copy_from_user(&req, ifr->ifr_data, sizeof(struct s_wiznet_ioctl));
	if (err)
		return -EFAULT;

	switch (req.cmd) {

	case WZIOC_SETOID:
		DPRINTK("ioctl: Set REG 0x%x: data %p, len %d\n", req.oid, req.data, req.len);
		if (!access_ok(VERIFY_READ, req.data, req.len))
			return -EFAULT;
		iinchip_copy_to(req.oid, req.data, req.len);
		if (copy_to_user(ifr->ifr_data, &req, sizeof(struct s_wiznet_ioctl)))
			err = -EFAULT;
		break;

	case WZIOC_GETOID:
		DPRINTK("ioctl: Get REG 0x%x, len %d\n", req.oid, req.len);
		if (!access_ok(VERIFY_WRITE, req.data, req.len))
			return -EFAULT;
		iinchip_copy_from(req.oid, req.data, req.len);
		if (copy_to_user(ifr->ifr_data, &req, sizeof(struct s_wiznet_ioctl)))
			err = -EFAULT;
		break;

	default:
		err = -EOPNOTSUPP;
	}

	return err;
}

/* create network device driver */
static const struct net_device_ops netdev_ops = {
	.ndo_open		= wiznet_open,
	.ndo_stop		= wiznet_close,
	.ndo_get_stats		= wiznet_get_stats,
	.ndo_start_xmit		= wiznet_start_xmit,
	.ndo_tx_timeout		= wiznet_tx_timeout,
	.ndo_set_mac_address	= wiznet_set_address,
	.ndo_do_ioctl		= wiznet_ioctl,
	.ndo_set_rx_mode 	= wiznet_set_multicast,
	.ndo_change_mtu		= eth_change_mtu,
	.ndo_validate_addr	= eth_validate_addr,
};

struct net_device *
wiznet_drv_create(wiz_t *wz)
{
	struct net_device *dev;
	struct wiz_private *wp;

	/* create ethernet device */
	dev = alloc_etherdev(sizeof(struct wiz_private));
	if (dev == NULL) {
		printk("%s: can't create device\n", DRV_NAME);
		return NULL;
	}

	/* initialize private device structure */

	/* initialize network device structure */
	wp = netdev_priv(dev);

	dev_set_drvdata(&spi_device->dev, wp);
	SET_NETDEV_DEV(dev, &spi_device->dev);

	wp->s = 0;
	wp->wiz = wz;
	memcpy(dev->dev_addr, wz->macaddr, 6);
	dev->base_addr = wz->base;
	dev->irq = wz->irq;
	dev->netdev_ops = &netdev_ops;
	dev->watchdog_timeo	= 2 * HZ;

	/* override Name */
	strcpy(dev->name, "tf%d");

	/* register driver */
	if (register_netdev(dev)) {
		printk("%s: register_netdev() failed\n", DRV_NAME);
		kfree(dev);
		return NULL;
	}

	return dev;
}

void wiznet_drv_delete(struct net_device *dev)
{
	/* unregister driver */
	unregister_netdev(dev);
}




/****************************************************************************
 *
 * driver/dev.c
 */

/*********************************************
 * Device management support
 *********************************************/


/*
 * Information that need to be kept for each board.
 */
struct net_local {
	/* socket */
	struct sock	*gSocket[MAX_SOCK_NUM];

	/* network interface */
	struct net_device *dev;

	/* tasklet */
	struct tasklet_struct rx_tasklet[MAX_SOCK_NUM];

	/* Rx buffer pointer */
	unsigned long	rx_ptr[MAX_SOCK_NUM];

	/* Tx buffer pointer */
	unsigned long	tx_ptr[MAX_SOCK_NUM];

	/* status register */
	unsigned long	gStatus[MAX_SOCK_NUM];

	/* Tx control lock.  This protects the transmit buffer ring
	 * state along with the "tx full" state of the driver.  This
	 * means all netif_queue flow control actions are protected
	 * by this lock as well.
	 */
	spinlock_t		lock;

	/* W5X00 IRQ no. and pins */
	int             irq;
	int             pin_interrupt;
	int             pin_reset;

	/* functions and structures specific to W5500 or W5200 respectively */
	void (*w5x00_write)(u32, u8);
	u8 (*w5x00_read)(u32);
	u16 (*w5x00_write_buf)(u32, const u8*, u16);
	u16 (*w5x00_read_buf)(u32, u8*, u16);
	int (*iinchip_w5x00_write_buf)(int, unsigned char*, int);
	void (*iinchip_w5x00_read_buf)(struct net_local*, int, u8*, int);

	struct w5x00_regs regs;

	int w5x00_type;
};

/* prototypes */
static inline u8 iinchip_inb(u32 adr);
static inline void iinchip_outb(u32 adr, u8 val);
static void iinchip_mac_rx_tasklet(unsigned long data);

/* variables */
struct workqueue_struct *w5x00_wq;

static spinlock_t spi_lock;
unsigned int local_port;
unsigned int SMASK[MAX_SOCK_NUM];
unsigned int RMASK[MAX_SOCK_NUM];
unsigned int SSIZE[MAX_SOCK_NUM];
unsigned int RSIZE[MAX_SOCK_NUM];
unsigned int SBASE[MAX_SOCK_NUM];
unsigned int RBASE[MAX_SOCK_NUM];

static struct net_local iinchip_local_p;
static unsigned char txsize[MAX_SOCK_NUM] = {
	16, 0, 0, 0, 0, 0, 0, 0 //see iinchip_sysinit
};
static unsigned char rxsize[MAX_SOCK_NUM] = {
	16, 0, 0, 0, 0, 0, 0, 0 //see iinchip_sysinit
};

extern struct spi_device *spi_device;
extern void w5x00_tx_irq_work(struct work_struct *work);

/* macros */



/*
 * Print a hex-dump of the given block data
 */
void
iinchip_print_hexbuf(char *txt, char *data, int len)
{
	int i,j;

	printk("\n    ---- <%s:%d> ----\n", txt, len);
	for(i=0; i<len; i+=16) {
		printk("    %04X : ", i);
		for(j=i; (j<i+16) && (j<len);  j++) {
			printk("%02X ", (unsigned char)*(data+j));
		}
		printk("\n");
	}
	printk("    ----- <%s> ----\n\n", txt);
}


/*
 * Interrupt (un)lock.
 */
static inline void iinchip_irq_lock(void)
{
	struct net_local *lp = &iinchip_local_p;
	if (!in_irq()) disable_irq(lp->irq);
}

static inline void iinchip_irq_unlock(void)
{
	struct net_local *lp = &iinchip_local_p;
	if (!in_irq()) enable_irq(lp->irq);
}

static inline void iinchip_outb(u32 adr, u8 val)
{
	struct net_local *lp = &iinchip_local_p;
	lp->w5x00_write(adr, val);
}

static inline void iinchip_outs(u32 adr, u16 val)
{
	struct net_local *lp = &iinchip_local_p;
	char buf[2];

	buf[0] = ((val >> 8) & 0xff);
	buf[1] = (val  & 0xff);
	lp->w5x00_write_buf(adr, buf, 2);
}

static inline void iinchip_outl(u32 adr, u32 val)
{
	struct net_local *lp = &iinchip_local_p;
	char buf[4];

	buf[0] = ((val >> 24) & 0xff);
	buf[1] = ((val >> 16) & 0xff);
	buf[2] = ((val >> 8) & 0xff);
	buf[3] = (val & 0xff);

	lp->w5x00_write_buf(adr, buf, 4);
}

static inline u8 iinchip_inb(u32 adr)
{
	struct net_local *lp = &iinchip_local_p;
	return lp->w5x00_read(adr);
}

static inline u16 iinchip_ins(u32 adr)
{
	struct net_local *lp = &iinchip_local_p;
	u16 val = 0;
	char buf[2];

	lp->w5x00_read_buf(adr, buf, 2);

	val = buf[0] << 8;
	val |= buf[1];

	return val;
}

static inline u32 iinchip_inl(u32 adr)
{
	struct net_local *lp = &iinchip_local_p;
	u32 val = 0;
	char buf[4];

	lp->w5x00_read_buf(adr, buf, 4);

	val = buf[0] << 24;
	val |= buf[1] << 16;
	val |= buf[2] << 8;
	val |= buf[3];

	return val;
}

void iinchip_copy_from(u32 adr, u8 *buf, ssize_t len)
{
	struct net_local *lp = &iinchip_local_p;
	lp->w5x00_read_buf(adr, buf, len);
}

void iinchip_copy_to(u32 adr, const u8 *buf, ssize_t len)
{
	struct net_local *lp = &iinchip_local_p;
	lp->w5x00_write_buf(adr, buf, len);
}

/*
 * Get Rx Buffer pointer.
 */
static void iinchip_get_rxbuffer(struct net_local *lp, int s)
{
	// gCRxWrPtr is never used, we comment it out for now
	// get Rx Write pointer.
	// lp->gCRxWrPtr[s] = iinchip_ins(RX_WR_PTR(s));
	// get Rx Read pointer.
	lp->rx_ptr[s] = iinchip_ins(RX_RD_PTR(s));

	DPRINTK("s(%d): rx_rptr(0x%x)\n", s, lp->rx_ptr[s]);
}

/*
 * Get Rx Buffer Size.
 */
int iinchip_get_rxsize(int s)
{
	int l1, l2;
 retry:
	l1 = iinchip_ins(RX_RECV_SIZE_PTR(s));
	if (l1 == 0)
		return 0;
	l2 = iinchip_ins(RX_RECV_SIZE_PTR(s));
	if (l1 != l2)
		goto retry;

	DPRINTK("s(%d): rx_len(%d)\n", s, l1);

	return l1;
}

/*
 * Get Tx Buffer pointer.
 */
static void iinchip_get_txbuffer(struct net_local *lp, int s)
{
	// gCTxRdPtr is never used, comment out for now
	// Get Tx Read pointer.
	// lp->gCTxRdPtr[s] = iinchip_ins(TX_RD_PTR(s));
	// Get Tx Write pointer.
	lp->tx_ptr[s] = iinchip_ins(TX_WR_PTR(s));

	DPRINTK("s(%d): tx_wptr(0x%x)\n", s, lp->tx_ptr[s]);
}

/*
 * Get Tx Buffer Size.
 */
int iinchip_get_txsize(int s)
{
#if BUSWIDTH==BUS8
	int l1, l2;
 retry:
	l1 = iinchip_ins(TX_FREE_SIZE_PTR(s));
	if (l1 == 0)
		return 0;
	l2 = iinchip_ins(TX_FREE_SIZE_PTR(s));
	if (l1 != l2)
		goto retry;

	return l1;
#endif
}

void iinchip_socket_setdport(int s, u16 port)
{
	iinchip_outs(DST_PORT_PTR(s), htons(port) );
}

void iinchip_socket_setdipaddr(int s, u32 addr)
{
	iinchip_outl(DST_IP_PTR(s), htonl(addr) );
}

void iinchip_socket_sethwaddr(char *addr)
{
	struct net_local *lp = &iinchip_local_p;
	printk("%s():%d=%x:%x:%x:%x:%x:%x\n", __FUNCTION__, __LINE__,
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	iinchip_copy_to(lp->regs.REG_MAC_SRC, addr, 6);
}

void iinchip_setport(int s, int port)
{
	iinchip_outs(SRC_PORT_PTR(s), port);
}

#define MAX_CNT 100000 // udelay(2) * 100000 = 200msec. @2013.12.25
int iinchip_socket_send(int s, int wait)
{
	struct net_local *lp = &iinchip_local_p;
	int free_buf_size;
    int cnt, ret;

	iinchip_outb(COMMAND(s), CSEND);
	while(iinchip_inb(COMMAND(s)));
    cnt = 0;
	ret = 1;

	do{
		udelay(2);
		free_buf_size = iinchip_get_txsize(s);
		cnt++;
		if(cnt % 1000 == 0) {
			printk("socket_send(%d): free_buf_size %d\n", cnt, free_buf_size);
		}

		if(cnt>MAX_CNT)
		{
			// Reset phy if such a register is available
			// What do we do here if we can't reset the phy?
			if(lp->regs.REG_PHYCFGR != 0) {
				printk("----PHY RESET----\n");
				iinchip_outb(lp->regs.REG_PHYCFGR,0x38); //PHY RESET - Reset bit is low
				udelay(50);
				iinchip_outb(lp->regs.REG_PHYCFGR,0xC8); //PHY RESET - Reset bit is high
			}

			cnt = 0;
			ret = 0;
			break;
		}
	}while(free_buf_size != SSIZE[s]);

	return ret;
}

void iinchip_socket_recv(int s)
{
	iinchip_outb(COMMAND(s), CRECV);
	while(iinchip_inb(COMMAND(s)));
}

void iinchip_rxrdptr_update(int s, unsigned long addr)
{
	iinchip_outs(RX_RD_PTR(s), addr);
}

void iinchip_txwrptr_update(int s, unsigned long addr)
{
	iinchip_outs(TX_WR_PTR(s), addr);
}


static void
iinchip_update_rx_bufptr(struct net_local *lp, int s, int len)
{
	/* update address */
	lp->rx_ptr[s] += len;
}



void w5x00_tx_irq_work(struct work_struct *work)
{
	struct net_local *lp = &iinchip_local_p;
	wiz_t *wz = container_of(work, wiz_t, tx_work);
	struct wiz_private *wp = netdev_priv(wz->dev);
	struct sk_buff *skb;
	SKB_NODE *p;
	int r;

	while((p = pop_skb()) != NULL)
	{
		skb = p->skb;

		/* send */
		r = lp->iinchip_w5x00_write_buf(wp->s, skb->data, skb->len);

		if (r < 0) {
			wp->stats.tx_dropped++;
		} else {
			/* update counter */
			wp->stats.tx_bytes += skb->len;
			wp->stats.tx_packets++;
			//wz->dev->trans_start = jiffies;
		}

		/* release skb */
		dev_kfree_skb(skb);

		free_skb_node(p);
	}
}


/*
 * w5200 specific functions
 */

void w5200_write(u32 addrbsb, u8 data)
{
	u8  addr[5];
	//unsigned long irqflags;

	addr[0] = (addrbsb & 0x00FF0000) >> 16 ;
	addr[1] = (addrbsb & 0x0000FF00) >> 8;
	addr[2] = 1 << 7; // op = write
	addr[3] = 1;
	addr[4] = data;

	iinchip_irq_lock();
	//spin_lock_irqsave(&spi_lock, irqflags);

	spi_write(spi_device, addr, 5);

	//spin_unlock_irqrestore(&spi_lock, irqflags);
	iinchip_irq_unlock();
}

u8 w5200_read(u32 addrbsb)
{
	u8 data, addr[4];
	//unsigned long irqflags;

	addr[0] = (addrbsb & 0x00FF0000) >> 16 ;
	addr[1] = (addrbsb & 0x0000FF00) >> 8;
	addr[2] = 0; // op = read
	addr[3] = 1;

	iinchip_irq_lock();
	//spin_lock_irqsave(&spi_lock, irqflags);

	spi_write_then_read(spi_device, addr, 4, &data, 1);

	//spin_unlock_irqrestore(&spi_lock, irqflags);
	iinchip_irq_unlock();

	return data;
}

u16 w5200_write_buf(u32 addrbsb, const u8 *buf, u16 len)
{
	u8 addr[SPI_BURST_SIZE + 4];
	unsigned int i, l, r;
	//unsigned long irqflags;

	l = len / SPI_BURST_SIZE;
	r = len % SPI_BURST_SIZE;

	iinchip_irq_lock();
	//spin_lock_irqsave(&spi_lock, irqflags);

	for(i = 0 ; i < l ; i++)
	{
		addr[0] = (addrbsb & 0x00FF0000) >> 16 ;
		addr[1] = (addrbsb & 0x0000FF00) >> 8;
		addr[2] = 1 << 7; // op = write
		addr[3] = SPI_BURST_SIZE;

		memcpy(addr + 4, buf + (i * SPI_BURST_SIZE), SPI_BURST_SIZE);
		spi_write_then_read(spi_device, addr, SPI_BURST_SIZE + 4, NULL, 0);
		addrbsb += (SPI_BURST_SIZE << 8);
	}

	if(r > 0)
	{
		addr[0] = (addrbsb & 0x00FF0000) >> 16 ;
		addr[1] = (addrbsb & 0x0000FF00) >> 8;
		addr[2] = 1 << 7; // op = write
		addr[3] = r;

		memcpy(addr + 4, buf + (i * SPI_BURST_SIZE), r);
		spi_write_then_read(spi_device, addr, r + 4, NULL, 0);
	}

	//spin_unlock_irqrestore(&spi_lock, irqflags);
	iinchip_irq_unlock();

	return len;
}

u16 w5200_read_buf(u32 addrbsb, u8 *buf, u16 len)
{
	u8 addr[4];
	unsigned int i, l, r;
	//unsigned long irqflags;

	l = len / SPI_BURST_SIZE;
	r = len % SPI_BURST_SIZE;

	iinchip_irq_lock();
	//spin_lock_irqsave(&spi_lock, irqflags);

	for(i = 0 ; i < l; i++)
	{
		addr[0] = (addrbsb & 0x00FF0000) >> 16;
		addr[1] = (addrbsb & 0x0000FF00) >> 8;
		addr[2] = 0; // op = read
		addr[3] = SPI_BURST_SIZE;

		spi_write_then_read(spi_device, addr, 4, buf + (i * SPI_BURST_SIZE), SPI_BURST_SIZE);
		addrbsb += (SPI_BURST_SIZE << 8);
	}

	if(r > 0)
	{
		addr[0] = (addrbsb & 0x00FF0000) >> 16;
		addr[1] = (addrbsb & 0x0000FF00) >> 8;
		addr[2] = 0; // op = read
		addr[3] = r;
		spi_write_then_read(spi_device, addr, 4, buf + (i * SPI_BURST_SIZE), r);
	}

	//spin_unlock_irqrestore(&spi_lock, irqflags);
	iinchip_irq_unlock();

	return len;
}


int iinchip_w5200_write_buf(int s, unsigned char *buf, int len)
{
	struct net_local *lp = &iinchip_local_p;
	u32 addr;
	u16 tx_ptr;
	int bufsize;
	u16 send_succ;
	u16 upper, lower;


	/* check buffer */
	bufsize = iinchip_get_txsize(s);
	DPRINTK("%s: s(%d), tx_len(%d), tx_buf(%d)\n", __FUNCTION__, s, len, bufsize);

	if (!bufsize || len > bufsize) {
		printk("s(%d): tx buffer(%d) is not enough for pkt(%d)\n", s, bufsize, len);
		return -1;
	}

	/* get write offset address */
	tx_ptr = iinchip_ins(TX_WR_PTR(s));

	addr = SBASE[s] + (tx_ptr & SMASK[s]);

	/* write to buffer */
	if(addr + len > SBASE[s] + SSIZE[s]) {
		upper = SBASE[s] + SSIZE[s] - addr;
		lp->w5x00_write_buf(addr << 8, buf, upper);
		lower = len - upper;
		addr = SBASE[s];
		lp->w5x00_write_buf(addr << 8, buf + upper, lower);
	} else {
		lp->w5x00_write_buf(addr << 8, buf, len);
	}

	/* update write offset address */
	iinchip_txwrptr_update(s, tx_ptr + len);

	bufsize = iinchip_get_txsize(s);

	/* command send */
	send_succ = iinchip_socket_send(s, 0);
    if(send_succ== 0) {
		printk("socket_send error: %d\n", send_succ);
		len = -1;
	}

#ifdef DEBUG_PKT
	iinchip_print_hexbuf("Tx", buf, len);
#endif

	return len;
}

void iinchip_w5200_read_buf(struct net_local *lp, int s, u8 *buf, int len)
{
	u32 rx_ptr, addr;
	u16 upper, lower;

	/* read from ASIC's buffer */
	rx_ptr = lp->rx_ptr[s];

	addr = RBASE[s] + (rx_ptr & RMASK[s]);

	/* read from buffer */
	if(addr + len > RBASE[s] + RSIZE[s]) {
		upper = RBASE[s] + RSIZE[s] - addr;
		lp->w5x00_read_buf(addr << 8, buf, upper);
		lower = len - upper;
		addr = RBASE[s];
		lp->w5x00_read_buf(addr << 8, buf + upper, lower);
	} else {
		lp->w5x00_read_buf(addr << 8, buf, len);
	}

#ifdef DEBUG_PKT
	iinchip_print_hexbuf("Rx", buf, len);
#endif
}


void w5200_init(void) {
	struct net_local *lp = &iinchip_local_p;
	struct w5x00_regs regs = {
		.REG_TMODE = 0x000000,
		.REG_IP_GATEWAY = 0x000100,
		.REG_IP_SUBNET = 0x000500,
		.REG_MAC_SRC = 0x000900,
		.REG_IP_SRC = 0x000F00,

		.REG_INT_LL_TIMER0 = 0x001300,
		.REG_INT_LL_TIMER1 = 0x001400,
		.REG_INT_ST = 0x001500,
		.REG_INT_MASK = 0x001600,

		.REG_SIR = 0x003400,
		.REG_SIMR = 0x003600,
		.REG_RTRY_TIMEOUT = 0x001700,
		.REG_RTRY_COUNT = 0x001900,

		.REG_PTIMER = 0x002800,
		.REG_PMAGIC = 0x002900,
		.REG_PPP_MAC_DST = 0, // Not available in w5200

		.REG_PSID = 0, // Not available in w5200
		.REG_PMR = 0, // Not available in w5200
		.REG_UIPR = 0, // Not available in w5200
		.REG_UPORT = 0, // Not available in w5200
		.REG_PHYCFGR = 0, // Not available in w5200
		.REG_VERSIONR = 0x001F00,

		.CH_BASE = 0x400000,
		.CH_OFFSET_SHIFT = 16
	};

	lp->w5x00_write = w5200_write;
	lp->w5x00_read = w5200_read;
	lp->w5x00_write_buf = w5200_write_buf;
	lp->w5x00_read_buf = w5200_read_buf;
	lp->iinchip_w5x00_write_buf = iinchip_w5200_write_buf;
	lp->iinchip_w5x00_read_buf = iinchip_w5200_read_buf;

	lp->regs = regs;

	lp->w5x00_type = W5X00_VERSION_W5200;
}





/*
 * w5500 specific functions
 */

void w5500_write(u32 addrbsb, u8 data)
{
	u8  addr[4];
	//unsigned long irqflags;

	addr[0] = (addrbsb & 0x00FF0000) >> 16;
	addr[1] = (addrbsb & 0x0000FF00) >> 8;
	addr[2] = (addrbsb & 0x000000F8) + 4;
	addr[3] = data;

	iinchip_irq_lock();
	//spin_lock_irqsave(&spi_lock, irqflags);

	spi_write(spi_device, addr, 4);

	//spin_unlock_irqrestore(&spi_lock, irqflags);
	iinchip_irq_unlock();
}

u8 w5500_read(u32 addrbsb)
{
	u8 data, addr[3];
	//unsigned long irqflags;

	addr[0] = (addrbsb & 0x00FF0000) >> 16;
	addr[1] = (addrbsb & 0x0000FF00) >> 8;
	addr[2] = (addrbsb & 0x000000F8);


	iinchip_irq_lock();
	//spin_lock_irqsave(&spi_lock, irqflags);

	spi_write_then_read(spi_device, addr, 3, &data, 1);

	//spin_unlock_irqrestore(&spi_lock, irqflags);
	iinchip_irq_unlock();

	return data;
}

u16 w5500_write_buf(u32 addrbsb, const u8 *buf, u16 len)
{
	u8 addr[SPI_BURST_SIZE + 3];
	unsigned int i, l, r;
	//unsigned long irqflags;

	l = len / SPI_BURST_SIZE;
	r = len % SPI_BURST_SIZE;

	iinchip_irq_lock();
	//spin_lock_irqsave(&spi_lock, irqflags);

	for(i = 0 ; i < l ; i++)
	{
		addr[0] = (addrbsb & 0x00FF0000) >> 16;
		addr[1] = (addrbsb & 0x0000FF00) >> 8;
		addr[2] = (addrbsb & 0x000000F8) + 4;

		memcpy(addr + 3, buf + (i * SPI_BURST_SIZE), SPI_BURST_SIZE);
		spi_write_then_read(spi_device, addr, SPI_BURST_SIZE + 3, NULL, 0);
		addrbsb += (SPI_BURST_SIZE << 8);
	}

	if(r > 0)
	{
		addr[0] = (addrbsb & 0x00FF0000) >> 16;
		addr[1] = (addrbsb & 0x0000FF00) >> 8;
		addr[2] = (addrbsb & 0x000000F8) + 4;

		memcpy(addr + 3, buf + (i * SPI_BURST_SIZE), r);
		spi_write_then_read(spi_device, addr, r + 3, NULL, 0);
	}

	//spin_unlock_irqrestore(&spi_lock, irqflags);
	iinchip_irq_unlock();

	return len;
}

u16 w5500_read_buf(u32 addrbsb, u8 *buf, u16 len)
{
	u8 addr[3];
	unsigned int i, l, r;
	//unsigned long irqflags;

	l = len / SPI_BURST_SIZE;
	r = len % SPI_BURST_SIZE;

	iinchip_irq_lock();
	//spin_lock_irqsave(&spi_lock, irqflags);

	for(i = 0 ; i < l; i++)
	{
		addr[0] = (addrbsb & 0x00FF0000) >> 16 ;
		addr[1] = (addrbsb & 0x0000FF00) >> 8;
		addr[2] = (addrbsb & 0x000000F8);

		spi_write_then_read(spi_device, addr, 3, buf + (i * SPI_BURST_SIZE), SPI_BURST_SIZE);
		addrbsb += (SPI_BURST_SIZE << 8);
	}

	if(r > 0)
	{
		addr[0] = (addrbsb & 0x00FF0000) >> 16 ;
		addr[1] = (addrbsb & 0x0000FF00) >> 8;
		addr[2] = (addrbsb & 0x000000F8);
		spi_write_then_read(spi_device, addr, 3, buf + (i * SPI_BURST_SIZE), r);
	}

	//spin_unlock_irqrestore(&spi_lock, irqflags);
	iinchip_irq_unlock();

	return len;
}

int iinchip_w5500_write_buf(int s, unsigned char *buf, int len)
{
	struct net_local *lp = &iinchip_local_p;
	u32 addrbsb;
	u16 tx_ptr;
	int bufsize;
	u16 send_succ;

	DPRINTK("%s: s(%d), tx_len(%d)\n", __FUNCTION__, s, len);

	/* check buffer */
	bufsize = iinchip_get_txsize(s);
	if (!bufsize || len > bufsize) {
		printk("s(%d): tx buffer(%d) is not enough for pkt(%d)\n", s, bufsize, len);
		return -1;
	}

	/* get write offset address */
	tx_ptr = iinchip_ins(TX_WR_PTR(s));
	addrbsb = (u32)(tx_ptr << 8) + (s << 5) + 0x10;

	/* write to buffer */
	lp->w5x00_write_buf(addrbsb, buf, len);

	/* update write offset address */
	tx_ptr += len;
	iinchip_txwrptr_update(s, tx_ptr);

	/* command send */
	send_succ = iinchip_socket_send(s,0);
    if(send_succ== 0)
		len = -1;

#ifdef DEBUG_PKT
	iinchip_print_hexbuf("Tx", buf, len);
#endif

	return len;
}

void iinchip_w5500_read_buf(struct net_local *lp, int s, u8 *buf, int len)
{
	u32 rptr, addrbsb;

	/* read from ASIC's buffer */
	rptr = lp->rx_ptr[s];

	addrbsb = (u32)(rptr << 8) + (s << 5) + 0x18;

	/* read from buffer */
	lp->w5x00_read_buf(addrbsb, buf, len);

#ifdef DEBUG_PKT
	iinchip_print_hexbuf("Rx", buf, len);
#endif
}

void w5500_init(void) {
	struct net_local *lp = &iinchip_local_p;
	struct w5x00_regs regs = {
		.REG_TMODE = 0x000000,
		.REG_IP_GATEWAY = 0x000100,
		.REG_IP_SUBNET = 0x000500,
		.REG_MAC_SRC = 0x000900,
		.REG_IP_SRC = 0x000F00,

		.REG_INT_LL_TIMER0 = 0x001300,
		.REG_INT_LL_TIMER1 = 0x001400,
		.REG_INT_ST = 0x001500,
		.REG_INT_MASK = 0x001600,

		.REG_SIR = 0x001700,
		.REG_SIMR = 0x001800,
		.REG_RTRY_TIMEOUT = 0x001900,
		.REG_RTRY_COUNT = 0x001B00,

		.REG_PTIMER = 0x001C00,
		.REG_PMAGIC = 0x001D00,
		.REG_PPP_MAC_DST = 0x001E00, // Not available in w5200

		.REG_PSID = 0x002400, // Not available in w5200
		.REG_PMR = 0x002600, // Not available in w5200
		.REG_UIPR = 0x002800, // Not available in w5200
		.REG_UPORT = 0x002C00, // Not available in w5200
		.REG_PHYCFGR = 0x002E00, // Not available in w5200
		.REG_VERSIONR = 0x003900,

		.CH_BASE = 0x000008,
		.CH_OFFSET_SHIFT = 5
	};

	lp->w5x00_write = w5500_write;
	lp->w5x00_read = w5500_read;
	lp->w5x00_write_buf = w5500_write_buf;
	lp->w5x00_read_buf = w5500_read_buf;
	lp->iinchip_w5x00_write_buf = iinchip_w5500_write_buf;
	lp->iinchip_w5x00_read_buf = iinchip_w5500_read_buf;

	lp->regs = regs;

	lp->w5x00_type = W5X00_VERSION_W5500;
}



/************************************************************************
 *
 * Wiznet Socket Management Routines.
 *
 ***********************************************************************/
int iinchip_netif_create(struct net_device *dev)
{
	struct net_local *lp = &iinchip_local_p;
	struct wiz_private *wp = netdev_priv(dev);

	if (lp->dev) {
		return -EBUSY;
	}

	lp->dev = dev;
	iinchip_socket_interrupt_enable(wp->s);

	return 0;
}

int iinchip_netif_delete(struct net_device *dev)
{
	struct net_local *lp = &iinchip_local_p;
	struct wiz_private *wp = netdev_priv(dev);

	if (lp->dev != dev) {
		return -EFAULT;
	}

	iinchip_socket_interrupt_disable(wp->s);
	iinchip_socket_tasklet_kill(wp->s);
	lp->dev = NULL;

	return 0;
}

int iinchip_socket_tasklet_init(int s, void (*func)(unsigned long), unsigned long data)
{
	struct net_local *lp=&iinchip_local_p;

	if (s < 0 || s >= MAX_SOCK_NUM)
		return -1;

	tasklet_init(&lp->rx_tasklet[s], func, data);

	return 0;
}

int iinchip_socket_tasklet_kill(int s)
{
	struct net_local *lp=&iinchip_local_p;

	if (s < 0 || s >= MAX_SOCK_NUM)
		return -1;

	tasklet_kill(&lp->rx_tasklet[s]);

	return 0;
}

int iinchip_socket_tasklet_enable(int s)
{
	struct net_local *lp=&iinchip_local_p;

	if (s < 0 || s >= MAX_SOCK_NUM)
		return -1;

	tasklet_enable(&lp->rx_tasklet[s]);

	return 0;
}

int iinchip_socket_tasklet_disble(int s)
{
	struct net_local *lp=&iinchip_local_p;

	if (s < 0 || s >= MAX_SOCK_NUM)
		return -1;

	tasklet_disable(&lp->rx_tasklet[s]);

	return 0;
}

int iinchip_socket_interrupt_enable(int s)
{
	struct net_local *lp = &iinchip_local_p;
	unsigned char mask;

	if (s < 0 || s >= MAX_SOCK_NUM)
		return -1;

	mask = iinchip_inb(lp->regs.REG_INT_MASK);
	mask |= (0x01 << s);
	iinchip_outb(lp->regs.REG_INT_MASK, mask);

	return 0;
}

int iinchip_socket_interrupt_disable(int s)
{
	struct net_local *lp = &iinchip_local_p;
	unsigned char mask;

	if (s < 0 || s >= MAX_SOCK_NUM)
		return -1;

	mask = iinchip_inb(lp->regs.REG_INT_MASK);
	mask &= ~(0x01 << s);
	iinchip_outb(lp->regs.REG_INT_MASK, mask);

	return 0;
}

int iinchip_socket_status(int s)
{
	if (s < 0 || s >= MAX_SOCK_NUM)
		return -1;

	return iinchip_inb(SOCK_STATUS(s));
}

/************************************************************************
 *
 * Interrupt related routines.
 *
 ***********************************************************************/
static inline int
iinchip_socket_get_mtu(int type)
{
	if (type == SOCK_STREAM)
		//return 1450;
		return 1460;

	return 1480;
}

static void iinchip_mac_rx_tasklet(unsigned long data)
{
	struct net_local *lp = &iinchip_local_p;
	struct net_device *dev = (struct net_device *) data;
	struct wiz_private *wp = netdev_priv(dev);
	struct sk_buff *skb;
	int s, len, maxlen;

	s = wp->s;

	/* Get Rx Buffer Size */
	len = iinchip_get_rxsize(s);
	if (len == 0) {
		return;
	}

	maxlen = RSIZE[s];
	if (len > maxlen) {
		//DPRINTK
		printk("%s: length(%d) is invalid, reset socket.\n", dev->name, len);
		wp->stats.rx_errors++;
		iinchip_close(s);
		mdelay(10);
		iinchip_open(s, WSOCK_MACL_RAWM, 0);
		return;
	}

	/* Get Rx Buffer Pointer */
	iinchip_get_rxbuffer(lp, s);

	while (len > 0) {
		u8 t[4];

		int pktlen;

		lp->iinchip_w5x00_read_buf(lp, s, t, 2);
		iinchip_update_rx_bufptr(lp, s, 2);

		pktlen = (t[0] << 8) + t[1] - 2;
		if(pktlen > 1514)
		{
			printk("Packet Size Error 1514>> %d\n", pktlen);
			wp->stats.rx_errors++;
			iinchip_close(s);
			mdelay(10);
			iinchip_open(s, WSOCK_MACL_RAWM, 0);
			return;
		}

#if 0	// 2014.02.27 sskim
		if (pktlen < 60) {
			printk("%s: Invalid pktlen(%d), dropping packet.\n", dev->name, pktlen);
			wp->stats.rx_dropped++;
			/* update buffer pointer */
			iinchip_update_rx_bufptr(lp, s, len-2);
			iinchip_rxrdptr_update(s, lp->rx_ptr[s]);
			/* command recv */
			iinchip_socket_recv(s);
			return;
		}
#endif

		/* allocate socket buffer */
		skb = dev_alloc_skb(pktlen + 2);
		if (!skb) {
			printk("%s: Memory squeeze, dropping packet.\n", dev->name);
			wp->stats.rx_dropped++;
			/* update buffer pointer */
			iinchip_update_rx_bufptr(lp, s, len-2);
			iinchip_rxrdptr_update(s, lp->rx_ptr[s]);
			/* command recv */
			iinchip_socket_recv(s);
			return;
		}
		skb->dev = dev;
		skb_reserve(skb, 2);
		skb_put(skb, pktlen);

		/* read data */
		lp->iinchip_w5x00_read_buf(lp, s, skb->data, pktlen);
		iinchip_update_rx_bufptr(lp, s, pktlen);

		/* Send the packet to the upper layers */
		skb->protocol = eth_type_trans(skb, dev);
		netif_rx(skb);

		/* update counter */
		wp->stats.rx_bytes += pktlen;
		wp->stats.rx_packets++;

		/* update buffer pointer */
		iinchip_rxrdptr_update(s, lp->rx_ptr[s]);

		/* command recv */
		iinchip_socket_recv(s);

		len = iinchip_get_rxsize(s);
		if (len == 0) {
			return;
		}
	}
}

static void
iinchip_irq_event(struct net_local *lp, int s)
{
	struct sock *sk = lp->gSocket[s];

	if (sk) {
		lp->gStatus[s] = iinchip_inb(SOCK_STATUS(s));
		DPRINTK("%s: SOCK Status(0x%x)\n", DRV_NAME, lp->gStatus[s]);

		//if (lp->gStatus[s] & SOCK_ESTABLISHED) {
		if (lp->gStatus[s] == SOCK_ESTABLISHED) {
			sk->sk_state = TCP_ESTABLISHED;
			wake_up_interruptible(sk_sleep(sk));
		//} else if (lp->gStatus[s] & SOCK_CLOSED) {
		} else if (lp->gStatus[s] == SOCK_CLOSED) {
			sk->sk_state = TCP_CLOSE;
			wake_up_interruptible(sk_sleep(sk));
		}
	}
}

static void w5x00_rx_irq_work(struct work_struct *work)
{
	struct net_local *lp=&iinchip_local_p;
	int s;
	u8 isr, ssr;

	isr = iinchip_inb(lp->regs.REG_SIR);

	if (!isr) {
		iinchip_outb(lp->regs.REG_SIR, isr);
		enable_irq(lp->irq);
		return;
	}

	/* clear global interrupt */
	iinchip_outb(lp->regs.REG_SIR, isr);

	/* socket interrupt */
	s = 0;
	if (isr & (1<<s)) {
		ssr = iinchip_inb(INT_STATUS(s));
		DPRINTK("%s: socket(%d) ssr(0x%x)\n", DRV_NAME, s, ssr);
		/* clear socket interrupt */

		if (s > 0 && (ssr & ISR_CON)) {
			DPRINTK("%s: socket(%d) ISR_CON\n", DRV_NAME, s);
			iinchip_irq_event(lp, s);
		}
		if (s > 0 && (ssr & ISR_DISCON)) {
			DPRINTK("%s: socket(%d) ISR_DISCON\n", DRV_NAME, s);
			iinchip_irq_event(lp, s);
		}
		if (s > 0 && (ssr & ISR_TIMEOUT)) {
			DPRINTK("%s: socket(%d) ISR_TIMEOUT\n", DRV_NAME, s);
			iinchip_irq_event(lp, s);
		}
		if (ssr & ISR_RECV) {
			iinchip_mac_rx_tasklet((unsigned long)lp->dev);
		}

		iinchip_outb(INT_STATUS(s), ssr&0x0f);
	}

	enable_irq(lp->irq);
}

static irqreturn_t
iinchip_interrupt(int irq, void *dev_id)
{
	wiz_t *wz = (wiz_t *)dev_id;

	disable_irq_nosync(wz->irq);
	queue_work(w5x00_wq, &(wz->rx_work));
	return IRQ_HANDLED;
}

/************************************************************************
 *
 * Socket related routines.
 *
 ***********************************************************************/
int iinchip_open(int s, int type, int ipproto)
{
	struct net_local *lp=&iinchip_local_p;

	// Socket protocol.
	switch (type) {
	case WSOCK_MACL_RAWM:
		if (s != 0) {
			printk("%s: Not Supported\n", DRV_NAME);
			return -EFAULT;
		}

		// UCASTB not present in w5x00
		if(lp->w5x00_type == W5X00_VERSION_W5200) {
			iinchip_outb(OPT_PROTOCOL(s), WSOCKOPT_MULTI | WSOCK_MACL_RAWM);
		} else if(lp->w5x00_type == W5X00_VERSION_W5500) {
			iinchip_outb(OPT_PROTOCOL(s), WSOCKOPT_MULTI | WSOCKOPT_UCASTB | WSOCK_MACL_RAWM);
		} else {
			printk("------> Unkown type(%d)\n", lp->w5x00_type);
		}
		iinchip_outb(lp->regs.REG_SIMR, 0x01);
		iinchip_outb(INT_MASK(0), 0x0f);
		break;
	default:
		printk("W5X00: Unknown socket type (%d)\n", type);
		return -EFAULT;
	}

	// Initialize Rx Buffer Pointer.
	lp->rx_ptr[s] = RBASE[s];

	// Initialize Tx Buffer Pointer.
	lp->tx_ptr[s] = SBASE[s];

	// Send command.
	lp->gStatus[s] = 0;
	iinchip_outb(COMMAND(s), CSOCKINIT);
	while(iinchip_inb(COMMAND(s)) & CSOCKINIT);

	DPRINTK("sock:%d SOCK_STATUS = 0x%x , Protocol = 0x%x\n", s, iinchip_inb(SOCK_STATUS(s)), iinchip_inb(OPT_PROTOCOL(s)));
	return 0;
}

int iinchip_close(int s)
{
	struct net_local *lp=&iinchip_local_p;
	unsigned long flags;

	if (s < 0 || s >= MAX_SOCK_NUM)
		return -1;

	local_irq_save(flags);			// for test sskim TODO
	iinchip_get_rxbuffer(lp, s);
	iinchip_get_txbuffer(lp, s);
	local_irq_restore(flags);		// for test sskim TODO

	/* Re-set Tx-pointer. */
	iinchip_txwrptr_update(s, lp->tx_ptr[s]);

	// Send command.
	iinchip_outb(COMMAND(s), CCLOSE);
	while(iinchip_inb(COMMAND(s)) & CCLOSE);

	return 0;
}

int iinchip_listen(int s)
{
	struct net_local *lp=&iinchip_local_p;

	if (s < 0 || s >= MAX_SOCK_NUM)
		return -1;

	// Send command.
	lp->gStatus[s] = 0;
	iinchip_outb(COMMAND(s), CLISTEN);

	return 0;
}

int iinchip_connect(int s, u32 daddr, u16 dport)
{
	struct net_local *lp=&iinchip_local_p;

	if (s < 0 || s >= MAX_SOCK_NUM)
		return -1;

	if (dport != 0) {
		iinchip_socket_setdport(s, dport);
	} else {
		return -1;
	}
	iinchip_socket_setdipaddr(s, daddr);

	// Send command.
	lp->gStatus[s] = 0;
	iinchip_outb(COMMAND(s), CCONNECT);

	return 0;
}

int iinchip_disconnect(int s)
{
	if (s < 0 || s >= MAX_SOCK_NUM)
		return -1;

	// Send command.
	iinchip_outb(COMMAND(s), CDISCONNECT);

	return 0;
}

/************************************************************************
 *
 * Startup related routines.
 *
 ***********************************************************************/
void iinchip_sysinit(int version)
{
	int i, j, ssum=0, rsum=0;

	for (i = 0 ; i < MAX_SOCK_NUM; i++) {
		/*
		 * Sometimes the W5500 chip resets its buffer configuration to the defaults after some hours.
		 * This breaks network connectivity completely, as no packets can be sent anymore.
		 * The kernel log is then flooded with "kernel: socket_send(84000): free_buf_size 2048"
		 * messages as well as "----PHY RESET----":
		 * 
		 * The driver writes one packet to the socket buffer, then issues a send command
		 * and waits until the free buffer size is the expected 16384 bytes. But because of
		 * the reset, that the chip does for some reason, the buffer has now only 2048 bytes
		 * capacity, which results in an infinite loop in iinchip_socket_send.
		 * 
		 * Resetting the buffer configuration or other attempts to restore the ability
		 * to send packets (e.g. the PHY RESET) did not help.
		 * 
		 * As the reported MTU is hardcoded to < 1500 anyway, we can live with the standard
		 * buffer size of 2048 bytes.
		 * 
		 * To keep compatability with the W5200, we only skip the buffer configuration (and
		 * fake the 2kb per socket assignment) if the chip is a W5500.
		 */
		/* Set Buffer Size */       
		if(version != W5X00_VERSION_W5500) {
			iinchip_outb(TX_BUF_SIZE_PTR(i), txsize[i]);
			iinchip_outb(RX_BUF_SIZE_PTR(i), rxsize[i]);
		} else {
			txsize[i] = 2;
			rxsize[i] = 2;
			printk("%s: skipping socket buffer reconfiguration.", DRV_NAME);
		}
		

		SSIZE[i] = 0;
		RSIZE[i] = 0;
		SBASE[i] = TX_BASE;
		RBASE[i] = RX_BASE;

		if (ssum <= 16384) {
			switch (txsize[i]) {
			case 0:
				SSIZE[i] = 0;
				SMASK[i] = 0;
				break;
			case 2:
				SSIZE[i] = 2048;
				SMASK[i] = 0x7FF;
				break;
			case 4:
				SSIZE[i] = 4096;
				SMASK[i] = 0xFFF;
				break;
			case 8:
				SSIZE[i] = 8192;
				SMASK[i] = 0x1FFF;
				break;
			case 16:
				SSIZE[i] = 16384;
				SMASK[i] = 0x3FFF;
				break;
			default:
				SSIZE[i] = 2048;
				SMASK[i] = 0x7FF;
				break;
			}
		}
		for(j = 0; j < i; j++) {
			SBASE[j] += SSIZE[i];
		}

		if (rsum <= 16384) {
			switch (rxsize[i]) {
			case 0:
				SSIZE[i] = 0;
				SMASK[i] = 0;
				break;
			case 2:
				RSIZE[i] = 2048;
				RMASK[i] = 0x7FF;
				break;
			case 4:
				RSIZE[i] = 4096;
				RMASK[i] = 0xFFF;
				break;
			case 8:
				RSIZE[i] = 8192;
				RMASK[i] = 0x1FFF;
				break;
			case 16:
				RSIZE[i] = 16384;
				RMASK[i] = 0x3FFF;
				break;
			default:
				RSIZE[i] = 2048;
				RMASK[i] = 0x7FF;
				break;
			}
		}
		for(j = 0; j < i; j++) {
			RBASE[j] += RSIZE[i];
		}

		ssum += SSIZE[i];
		rsum += RSIZE[i];

		printk("%s: socket(%d) Tx(0x%x,0x%x,0x%x) Rx(0x%x,0x%x,0x%x)\n",
			DRV_NAME, i,
			SSIZE[i], SMASK[i], SBASE[i],
			RSIZE[i], RMASK[i], RBASE[i] );
	}
}

static u8 iinchip_macaddr[6];

/*
 */
void iinchip_hwreset(void)
{
	struct net_local *lp = &iinchip_local_p;

	gpio_request(lp->pin_reset, "w5x00_reset");
	gpio_direction_output(lp->pin_reset, 1);
	gpio_set_value(lp->pin_reset, 0);
	mdelay(1);
	gpio_set_value(lp->pin_reset, 1);
	mdelay(2);
	mdelay(1500);				// WIZ550IO 사용시 필요
}


int iinchip_reset(void)
{
	struct net_local *lp = &iinchip_local_p;
	unsigned char addr[8];
	int v;

	/* Initialize ASIC */

	iinchip_hwreset();

	v = iinchip_inb(lp->regs.REG_VERSIONR);    
	printk("Version : %02x\n",v);
	// TMODE_NOSIZECHK_RAW (0x04) is defined as "reserved" in w5500 as well as w5x00 datasheet! wtf?
	iinchip_outb(lp->regs.REG_TMODE, TMODE_PINGBLOCK /*| TMODE_NOSIZECHK_RAW*/);

	// HW address.
	iinchip_socket_sethwaddr(iinchip_macaddr);
	iinchip_copy_from(lp->regs.REG_MAC_SRC, addr, 6);
	printk("%s: MAC [%02x:%02x:%02x:%02x:%02x:%02x]\n", DRV_NAME,
		addr[0],addr[1],addr[2],addr[3],addr[4],addr[5] );

	iinchip_sysinit(v);

	// Interrupt.
	iinchip_outb(lp->regs.REG_INT_MASK, 0x00);

	return 0;
}


/*
 *	Initialize the WIZnet TCP/IP protocol family
 */
int wiz_dev_init(wiz_t *wz)
{
	struct net_local *lp = &iinchip_local_p;
	int v;

	spin_lock_init(&spi_lock);

	memset(lp, 0, sizeof(iinchip_local_p));

	w5x00_wq = create_workqueue("w5x00_workqueue");
	INIT_WORK(&(wz->rx_work), w5x00_rx_irq_work);
	INIT_WORK(&(wz->tx_work), w5x00_tx_irq_work);

	/* make room for the local structure containing stats etc */

	/* initialize parameter */
	memcpy(iinchip_macaddr, wz->macaddr, 6);
	lp->irq           = wz->irq;
	lp->pin_interrupt = wz->pin_interrupt;
	lp->pin_reset     = wz->pin_reset;

	/* Initialize channel */
	local_port = LOCAL_PORT;

	/* Find chip version (w5200 or w5500) */
	iinchip_hwreset();
	w5500_init();
	v = iinchip_inb(lp->regs.REG_VERSIONR);
	printk("Version test w5500 : %02x\n", v);

	if(v == W5X00_VERSION_W5500) {
		printk("Found W5500\n");
	} else {
		iinchip_hwreset();
		w5200_init();
		v = iinchip_inb(lp->regs.REG_VERSIONR);
		printk("Version test w5200 : %02x\n", v);

		if(v == W5X00_VERSION_W5200) {
			printk("Found W5200\n");
		} else {
			printk("Could not find any W5X00 IC\n");
			return -EAGAIN;
		}
	}

	/* Initialize ASIC */
	iinchip_reset();

	/* Initialize Interrupt GPIO */
	if(gpio_request(lp->pin_interrupt, "w5x00")) {
		printk("[%s] gpio_request w5x00 irq error\n", __func__);
		return -EAGAIN;
	}
	gpio_export(lp->pin_interrupt, 1);
	gpio_direction_input(lp->pin_interrupt);

	/* allocate the irq corresponding to the receiving */
	if (request_irq(wz->irq, iinchip_interrupt, (IRQF_SHARED | IRQF_DISABLED | IRQF_TRIGGER_LOW), "w5x00", (void *) wz)) {
		printk("errro request irq(%d)\n", wz->irq);
		return -EAGAIN;
	}

	return 0;
}

int wiz_dev_exit(wiz_t *wz)
{
	struct net_local *lp = &iinchip_local_p;
	destroy_workqueue(w5x00_wq);
	free_irq(wz->irq, (void *) wz);

	printk("gpio_free\n");
	gpio_free(lp->pin_interrupt);
	gpio_free(lp->pin_reset);

	return 0;
}



/****************************************************************************
 *
 * driver/module.c
 */

/*********************************************
 * Module support
 *********************************************/

static wiz_t gDrvInfo;

static int param_mac_size = 6;

struct spi_device *spi_device = NULL;

static int param_pin_interrupt = W5X00_DEFAULT_PIN_INTERRUPT;
static int param_pin_reset = W5X00_DEFAULT_PIN_RESET;
static int param_select = W5X00_DEFAULT_SELECT;
static unsigned char param_mac[6] = W5X00_DEFAULT_MAC;

module_param(param_pin_interrupt, int, 0);
MODULE_PARM_DESC(param_pin_interrupt, "Interrupt pin number");

module_param(param_pin_reset, int, 0);
MODULE_PARM_DESC(param_pin_reset, "Reset pin number");

module_param(param_select, int, 0);
MODULE_PARM_DESC(param_select, "SPI select number");

module_param_array(param_mac, byte, &param_mac_size, 0);
MODULE_PARM_DESC(param_mac, "MAC Address");

static int w5x00_probe(struct spi_device *spi)
{
	printk("w5x00 probe [int %d, rst %d, sel %d, mac %x:%x:%x:%x:%x:%x]\n",
	       param_pin_interrupt,
		   param_pin_reset,
		   param_select,
		   param_mac[0], param_mac[1], param_mac[2],
		   param_mac[3], param_mac[4], param_mac[5]);

	printk("chip select before: %d\n", spi->chip_select);

	spi->chip_select = param_select;
	spi_device = spi;

	/* Initial field */
	gDrvInfo.base = 0;
	gDrvInfo.pin_interrupt = param_pin_interrupt;
	gDrvInfo.pin_reset = param_pin_reset;
	gDrvInfo.irq = gpio_to_irq(param_pin_interrupt);

	/* mac address */
	memcpy(gDrvInfo.macaddr, param_mac, 6);

	/* initialize device */
	if (wiz_dev_init(&gDrvInfo) < 0) {
		return -EFAULT;
	}

	/* create network interface */
	gDrvInfo.dev = wiznet_drv_create(&gDrvInfo);

	return 0;
}

static int w5x00_remove(struct spi_device *spi)
{
	printk("w5x00 remove\n");

	/* de-initialize device */
	if (gDrvInfo.dev) {
		wiznet_drv_delete(gDrvInfo.dev);
		gDrvInfo.dev = NULL;
	}

	/* free irq */
	wiz_dev_exit(&gDrvInfo);

	spi_device = NULL;
	return 0;
}

static struct spi_driver w5x00_driver = {
	.driver = {
		.name = "w5x00",
		.bus = &spi_bus_type,
		.owner = THIS_MODULE,
	},
	.probe = w5x00_probe,
	.remove = w5x00_remove,
};


static int __init
wiz_module_init(void)
{
	int ret;

	printk(KERN_INFO "%s: %s\n", DRV_NAME, DRV_VERSION);

	ret = spi_register_driver(&w5x00_driver);
	if(ret < 0)
	{
		printk("w5x00 spi_register_driver failed\n");
		return ret;
	}
	else
		printk("w5x00 spi register succeed\n");

	return 0;
}

static void __exit
wiz_module_exit(void)
{
	spi_unregister_driver(&w5x00_driver);
}

module_init(wiz_module_init);
module_exit(wiz_module_exit);

MODULE_AUTHOR("WIZnet");
MODULE_AUTHOR("Olaf Lüke <olaf@tinkerforge.com>");
MODULE_AUTHOR("Ishraq Ibne Ashraf <ishraq@tinkerforge.com>");
MODULE_DESCRIPTION("Support for WIZnet w5x00-based MACRAW Mode.");
MODULE_SUPPORTED_DEVICE("WIZnet W5X00 Chip");
MODULE_LICENSE("GPL");
