/*
 * f_brick.c -- USB gadget RED Brick driver
 *
 * Copyright (C) 2014 Matthias Bolte (matthias@tinkerforge.com)
 * Copyright (C) 2017 Ishraq Ibne Ashraf (ishraq@tinkerforge.com)
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/* #define DEBUG */
/* #define VERBOSE_DEBUG */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/types.h>
#include <linux/file.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/usb.h>
#include <linux/usb_usual.h>
#include <linux/usb/ch9.h>
#include <linux/export.h>

#include "f_brick.h"

#define F_BRICK_BULK_BUFFER_SIZE 80

#define F_BRICK_STRING_INTERFACE_IDX 0
#define F_BRICK_STRING_MICROSOFT_OS_IDX 1

#define F_BRICK_STATE_USB_DISCONNECTED 0
#define F_BRICK_STATE_USB_CONNECTED 1

#define F_BRICK_TX_REQ_COUNT 10
#define F_BRICK_RX_REQ_COUNT 10

struct f_brick_packet_header {
	u32 uid;
	u8 length;
	u8 function_id;
	u8 sequence_number_and_options;
	u8 error_code_and_future_use;
} __attribute__((packed));

struct f_brick_packet {
	struct f_brick_packet_header header;
	u8 payload[64];
	u8 optional_data[8];
} __attribute__((packed));

struct f_brick_ctx {
	struct usb_composite_dev *cdev;
	struct usb_function func;
	struct usb_ep *ep_in;
	struct usb_ep *ep_out;

	u8 state_file_is_open; /* /proc/g_red_brick_state */
	u8 state;
	u8 state_changed;
	wait_queue_head_t state_wait;

	u8 data_file_is_open; /* /dev/g_red_brick_data */

	spinlock_t lock;
	struct mutex fops_lock;

	struct usb_request *tx_probe;

	/* buffer to accumulate a packet to be send to the host. a single USB
	 * request has to contain exactly one packet */
	struct usb_request *tx_partial_req;
	u8 *tx_partial_buf;
	unsigned tx_partial_buf_len;

	/* buffer to store the remaining part of a packet received from the host,
	 * that has not yet been fully read by brickd */
	struct usb_request *rx_partial_req;
	u8 *rx_partial_buf;
	unsigned rx_partial_buf_len;

	/* all TX requests start in tx_idle. if tx_partial contains a full packet
	 * then its data is to be send to the host. a TX request is removed from
	 * tx_idle, enqueued to the endpoint and added to the tx_active list. once
	 * the request completes it is added back to the tx_idle list */
	struct list_head tx_reqs_idle;
	struct list_head tx_reqs_active;

	/* all RX request start enqueued to the endpoint in rx_active. if data
	 * is received from the host then the RX request is removed from rx_active
	 * and added to rx_data. if brickd wants to read data then first rx_partial
	 * is checked to see if there is a partially packet left from the last read.
	 * if there is this data it is send to brickd first. after that rx_data is
	 * check for RX transfers. if there is one, then its data is send to brickd
	 * and potentially remaining data is stored in rx_partial. once the data of
	 * a RX request has been handled it is removed from rx_data, enqueued to
	 * the endpoint and added to the rx_active list. rx_idle should be empty,
	 * it'll contain request that could not be enqueued to the endpoint */
	struct list_head rx_reqs_idle;
	struct list_head rx_reqs_active;
	struct list_head rx_reqs_complete;

	/* indcates that data can be written by brickd. this means that the state
	 * is connected and that tx_reqs_idle is not empty */
	wait_queue_head_t tx_wait;

	/* inidcate that data can be read by brickd. this means that either
	 * rx_partial_buf_len is not zero or that rx_reqs_complete is not empty */
	wait_queue_head_t rx_wait;
};

struct f_brick_ctx *_f_brick_ctx;

static struct usb_interface_descriptor f_brick_interface_desc = {
	.bLength                = USB_DT_INTERFACE_SIZE,
	.bDescriptorType        = USB_DT_INTERFACE,
	.bInterfaceNumber       = 0,
	.bNumEndpoints          = 2,
	.bInterfaceClass        = USB_CLASS_VENDOR_SPEC,
	.bInterfaceSubClass     = USB_SUBCLASS_VENDOR_SPEC,
	.bInterfaceProtocol     = 0,
};

static struct usb_endpoint_descriptor f_brick_hs_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(512),
};

static struct usb_endpoint_descriptor f_brick_hs_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(512),
};

static struct usb_endpoint_descriptor f_brick_fs_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(64),
};

static struct usb_endpoint_descriptor f_brick_fs_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(64),
};

static struct usb_descriptor_header *f_brick_fs_descs[] = {
	(struct usb_descriptor_header *) &f_brick_interface_desc,
	(struct usb_descriptor_header *) &f_brick_fs_in_desc,
	(struct usb_descriptor_header *) &f_brick_fs_out_desc,
	NULL,
};

static struct usb_descriptor_header *f_brick_hs_descs[] = {
	(struct usb_descriptor_header *) &f_brick_interface_desc,
	(struct usb_descriptor_header *) &f_brick_hs_in_desc,
	(struct usb_descriptor_header *) &f_brick_hs_out_desc,
	NULL,
};

static struct usb_string f_brick_string_defs[] = {
	[F_BRICK_STRING_INTERFACE_IDX].s     = "Brick API",
	[F_BRICK_STRING_MICROSOFT_OS_IDX].s  = "MSFT100*", /* <"MSFT100"> + <vendor code == 42 == '*'> */
	{ }, /* end of list */
};

static struct usb_gadget_strings f_brick_string_table = {
	.language = 0x0409, /* en-US */
	.strings  = f_brick_string_defs,
};

static struct usb_gadget_strings *f_brick_strings[] = {
	&f_brick_string_table,
	NULL,
};

/* Microsoft Extended Compat ID Descriptor Header Section */
struct ms_compat_id_desc_header {
	__le32 dwLength;
	__le16 bcdVersion;
	__le16 wIndex;
	u8 bCount;
	u8 reserved[7];
} __attribute__((packed));

/* Microsoft Extended Compat ID Descriptor Function Section */
struct ms_compat_id_desc_function {
	u8 bFirstInterfaceNumber;
	u8 reserved1;
	u8 compatibleID[8];
	u8 subCompatibleID[8];
	u8 reserved2[6];
} __attribute__((packed));

/* Microsoft Extended Compat ID Descriptor */
struct {
	struct ms_compat_id_desc_header header;
	struct ms_compat_id_desc_function function;
} __attribute__((packed)) ms_compat_id_desc = {
	.header = {
		.dwLength              = __constant_cpu_to_le32(sizeof(ms_compat_id_desc)),
		.bcdVersion            = __constant_cpu_to_le16(0x0100),
		.wIndex                = __constant_cpu_to_le16(4),
		.bCount                = 1,
		.reserved              = { 0, 0, 0, 0, 0, 0, 0 },
	},
	.function = {
		.bFirstInterfaceNumber = 0,
		.reserved1             = 1,
		.compatibleID          = { 'W', 'I', 'N', 'U', 'S', 'B', 0, 0 },
		.subCompatibleID       = { 0, 0, 0, 0, 0, 0, 0, 0 },
		.reserved2             = { 0, 0, 0, 0, 0, 0 },
	}
};

/* Microsoft Extended Properties Descriptor Header Section */
struct ms_properties_desc_header {
	__le32 dwLength;
	__le16 bcdVersion;
	__le16 wIndex;
	__le16 bCount;
} __attribute__((packed));

/* Microsoft Extended Properties Descriptor Property Section */
struct ms_properties_desc_property {
	__le32 dwSize;
	__le32 dwPropertyDataType;
	__le16 wPropertyNameLength;
	u8 bPropertyName[42]; /* strlen("DeviceInterfaceGUIDs") * 2 + 2 */
	__le32 dwPropertyDataLength;
	u8 bPropertyData[80]; /* strlen("{9536B3B1-6077-4A3B-9BAC-7C2CFA8A2BF3}") * 2 + 4 */
} __attribute__((packed));

/* Microsoft Extended Properties Descriptor */
struct {
	struct ms_properties_desc_header header;
	struct ms_properties_desc_property property;
} __attribute__((packed)) ms_properties_desc = {
	.header = {
		.dwLength              = __constant_cpu_to_le32(sizeof(ms_properties_desc)),
		.bcdVersion            = __constant_cpu_to_le16(0x0100),
		.wIndex                = __constant_cpu_to_le16(5),
		.bCount                = __constant_cpu_to_le16(1),
	},
	.property = {
		.dwSize                = __constant_cpu_to_le32(sizeof(ms_properties_desc.property)),
		.dwPropertyDataType    = __constant_cpu_to_le32(7), /* REG_MULTI_SZ */
		.wPropertyNameLength   = __constant_cpu_to_le16(sizeof(ms_properties_desc.property.bPropertyName)),
		.bPropertyName         = { 'D', 0, 'e', 0, 'v', 0, 'i', 0, 'c', 0, 'e', 0, 'I', 0, 'n', 0, 't', 0, 'e', 0, 'r', 0, 'f', 0, 'a', 0, 'c', 0, 'e', 0, 'G', 0, 'U', 0, 'I', 0, 'D', 0, 's', 0, 0, 0 },
		.dwPropertyDataLength  = __constant_cpu_to_le32(sizeof(ms_properties_desc.property.bPropertyData)),
		.bPropertyData         = { '{', 0, '9', 0, '5', 0, '3', 0, '6', 0, 'B', 0, '3', 0, 'B', 0, '1', 0, '-', 0, '6', 0, '0', 0, '7', 0, '7', 0, '-', 0, '4', 0, 'A', 0, '3', 0, 'B', 0, '-', 0, '9', 0, 'B', 0, 'A', 0, 'C', 0, '-', 0, '7', 0, 'C', 0, '2', 0, 'C', 0, 'F', 0, 'A', 0, '8', 0, 'A', 0, '2', 0, 'B', 0, 'F', 0, '3', 0, '}', 0, 0, 0, 0, 0 },
	}
};

/* NOTE: assumes ctx->lock is locked */
static void f_brick_set_state(u8 state)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;

	if (ctx->state != state) {
		ctx->state = state;
		ctx->state_changed = 1;

		if (ctx->state == F_BRICK_STATE_USB_CONNECTED && !list_empty(&ctx->tx_reqs_idle)) {
			wake_up(&ctx->tx_wait);
		}

		wake_up(&ctx->state_wait);
	}
}

static struct usb_request *f_brick_request_new(struct usb_ep *ep, int buf_len)
{
	struct usb_request *req;

	/* allocate request */
	req = usb_ep_alloc_request(ep, GFP_KERNEL);

	if (!req) {
		return NULL;
	}

	/* allocate buffer for the request */
	req->buf = kmalloc(buf_len, GFP_KERNEL);

	if (!req->buf) {
		usb_ep_free_request(ep, req);

		return NULL;
	}

	req->length = buf_len;

	return req;
}

static void f_brick_request_free(struct usb_request *req, struct usb_ep *ep)
{
	if (req) {
		kfree(req->buf);
		usb_ep_free_request(ep, req);
	}
}

static void f_brick_complete_probe(struct usb_ep *ep, struct usb_request *req)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	unsigned long flags;

//	printk(">>>>>>>>>>>>>>>>>> enter f_brick_complete_probe: req->buf %p, status %d\n", req->buf, req->status);

	spin_lock_irqsave(&ctx->lock, flags);

	ctx->tx_probe = req;

	if (req->status == 0) {
		f_brick_set_state(F_BRICK_STATE_USB_CONNECTED);
	}

	spin_unlock_irqrestore(&ctx->lock, flags);

//	printk(">>>>>>>>>>>>>>>>>> leave f_brick_complete_probe: req->buf %p\n", req->buf);
}

static void f_brick_complete_in(struct usb_ep *ep, struct usb_request *req)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	unsigned long flags;

//	printk(">>>>>>>>>>>>>>>>>> enter f_brick_complete_in: req->buf %p, status %d\n", req->buf, req->status);

	spin_lock_irqsave(&ctx->lock, flags);

	list_del_init(&req->list); /* remove from tx_reqs_active, if it's in there */
	list_add(&req->list, &ctx->tx_reqs_idle);

	if (ctx->state == F_BRICK_STATE_USB_CONNECTED) {
		wake_up(&ctx->tx_wait);
	}

	spin_unlock_irqrestore(&ctx->lock, flags);

//	printk(">>>>>>>>>>>>>>>>>> leave f_brick_complete_in: req->buf %p\n", req->buf);
}

static void f_brick_complete_out(struct usb_ep *ep, struct usb_request *req)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	unsigned long flags;

//	printk(">>>>>>>>>>>>>>>>>> enter f_brick_complete_out: req->buf %p, status %d, actual %d\n", req->buf, req->status, req->actual);

	spin_lock_irqsave(&ctx->lock, flags);

	list_del_init(&req->list); /* remove from rx_reqs_active, if it's in there */

	if (req->status == 0 && req->actual > 0 && ctx->data_file_is_open) {
		/* successful RX request containing data */
		list_add_tail(&req->list, &ctx->rx_reqs_complete);

		wake_up(&ctx->rx_wait);
	} else {
		list_add(&req->list, &ctx->rx_reqs_idle);
	}

	spin_unlock_irqrestore(&ctx->lock, flags);

//	printk(">>>>>>>>>>>>>>>>>> leave f_brick_complete_out: req->buf %p\n", req->buf);
}

static void f_brick_enqueue_rx_idle(void)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	unsigned long flags;
	struct usb_request *req;
	int ret;

	spin_lock_irqsave(&ctx->lock, flags);

	while (!list_empty(&ctx->rx_reqs_idle)) {
		req = list_first_entry(&ctx->rx_reqs_idle, struct usb_request, list);

		list_del_init(&req->list); /* remove from rx_reqs_idle */
		list_add(&req->list, &ctx->rx_reqs_active);

		spin_unlock_irqrestore(&ctx->lock, flags);

		ret = usb_ep_queue(ctx->ep_out, req, GFP_ATOMIC);

		spin_lock_irqsave(&ctx->lock, flags);

		if (ret < 0) {
			printk("PPPHHH: f_brick_enqueue_rx_idle rx submit --> %d\n", ret);

			list_del_init(&req->list); /* remove from rx_reqs_active */
			list_add(&req->list, &ctx->rx_reqs_idle);

			break;
		}
	}

	spin_unlock_irqrestore(&ctx->lock, flags);
}

/* NOTE: assumes ctx->lock is locked */
static void f_brick_reset_requests(void)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	struct usb_request *req;

	/* move all complete RX requests back to idle */
	while (!list_empty(&ctx->rx_reqs_complete)) {
		req = list_first_entry(&ctx->rx_reqs_complete, struct usb_request, list);

		list_del_init(&req->list);
		list_add(&req->list, &ctx->rx_reqs_idle);
	}

	/* move partial requests back to idle */
	if (ctx->rx_partial_req) {
		list_add(&ctx->rx_partial_req->list, &ctx->rx_reqs_idle);

		ctx->rx_partial_req = NULL;
		ctx->rx_partial_buf = NULL;
		ctx->rx_partial_buf_len = 0;
	}

	if (ctx->tx_partial_req) {
		list_add(&ctx->tx_partial_req->list, &ctx->tx_reqs_idle);

		ctx->tx_partial_req = NULL;
		ctx->tx_partial_buf = NULL;
		ctx->tx_partial_buf_len = 0;
	}
}

static int f_brick_func_setup(struct usb_function *f, const struct usb_ctrlrequest *ctrl)
{
	struct usb_composite_dev *cdev = f->config->cdev;
	int value = -EOPNOTSUPP;
	int rc;
	u16 w_index = le16_to_cpu(ctrl->wIndex);
	u16 w_length = le16_to_cpu(ctrl->wLength);

	if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_VENDOR) {
		if (ctrl->bRequest == 42 && (ctrl->bRequestType & USB_DIR_IN) && (w_index == 4)) {
			value = (w_length < sizeof(ms_compat_id_desc) ?
			         w_length : sizeof(ms_compat_id_desc));

			memcpy(cdev->req->buf, &ms_compat_id_desc, value);
		} else if (ctrl->bRequest == 42 && (ctrl->bRequestType & USB_DIR_IN) && (w_index == 5)) {
			value = (w_length < sizeof(ms_properties_desc) ?
			         w_length : sizeof(ms_properties_desc));

			memcpy(cdev->req->buf, &ms_properties_desc, value);
		}
	}

	/* respond with data transfer or status phase? */
	if (value >= 0) {
		cdev->req->zero = value < w_length;
		cdev->req->length = value;

		rc = usb_ep_queue(cdev->gadget->ep0, cdev->req, GFP_ATOMIC);

		if (rc < 0) {
			printk("PPPHHH: %s: response queue error\n", __func__);
		}
	}

	return value;
}

static int f_brick_func_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	struct usb_composite_dev *cdev = ctx->cdev;
	int ret;
	struct usb_request *req;
	int i;

	ctx->cdev = c->cdev; // FIXME: is this necessary? already done in f_brick_bind_config

	/* allocate interface ID */
	ret = usb_interface_id(c, f);

	if (ret < 0) {
		return ret;
	}

	f_brick_interface_desc.bInterfaceNumber = ret;

	/* allocate in endpoint */
	ctx->ep_in = usb_ep_autoconfig(cdev->gadget, &f_brick_fs_in_desc);

	if (!ctx->ep_in) {
		return -ENODEV;
	}

	ctx->ep_in->driver_data = ctx; /* claim the endpoint */

	/* allocate out endpoint */
	ctx->ep_out = usb_ep_autoconfig(cdev->gadget, &f_brick_fs_out_desc);

	if (!ctx->ep_out) {
		return -ENODEV;
	}

	ctx->ep_out->driver_data = ctx; /* claim the endpoint */

	/* allocate requests */
	ctx->tx_probe = f_brick_request_new(ctx->ep_in, 1);

	if (!ctx->tx_probe) {
		return -ENOMEM;
	}

	ctx->tx_probe->complete = f_brick_complete_probe;

	for (i = 0; i < F_BRICK_TX_REQ_COUNT; i++) {
		req = f_brick_request_new(ctx->ep_in, F_BRICK_BULK_BUFFER_SIZE);

		if (!req) {
			return -ENOMEM;
		}

		req->complete = f_brick_complete_in;

		list_add(&req->list, &ctx->tx_reqs_idle);
	}

	for (i = 0; i < F_BRICK_RX_REQ_COUNT; i++) {
		req = f_brick_request_new(ctx->ep_out, F_BRICK_BULK_BUFFER_SIZE);

		if (!req) {
			return -ENOMEM;
		}

		req->complete = f_brick_complete_out;

		list_add(&req->list, &ctx->rx_reqs_idle);
	}

	/* support high speed hardware */
	if (gadget_is_dualspeed(c->cdev->gadget)) {
		f_brick_hs_in_desc.bEndpointAddress = f_brick_fs_in_desc.bEndpointAddress;
		f_brick_hs_out_desc.bEndpointAddress = f_brick_fs_out_desc.bEndpointAddress;
	}

	printk("PPPHHH: %s speed %s: IN/%s, OUT/%s\n",
			gadget_is_dualspeed(c->cdev->gadget) ? "dual" : "full",
			f->name, ctx->ep_in->name, ctx->ep_out->name);

	return 0;
}

static void f_brick_func_unbind(struct usb_configuration *c, struct usb_function *f)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	struct usb_request *req;

	while (!list_empty(&ctx->rx_reqs_idle)) {
		req = list_first_entry(&ctx->rx_reqs_idle, struct usb_request, list);
		list_del(&req->list);

		f_brick_request_free(req, ctx->ep_out);
	}

	while (!list_empty(&ctx->rx_reqs_complete)) {
		req = list_first_entry(&ctx->rx_reqs_complete, struct usb_request, list);
		list_del(&req->list);

		f_brick_request_free(req, ctx->ep_out);
	}

	while (!list_empty(&ctx->tx_reqs_idle)) {
		req = list_first_entry(&ctx->tx_reqs_idle, struct usb_request, list);
		list_del(&req->list);

		f_brick_request_free(req, ctx->ep_in);
	}

	if (ctx->tx_probe) {
		f_brick_request_free(ctx->tx_probe, ctx->ep_in);

		ctx->tx_probe = NULL;
	}
}

static int f_brick_enable_endpoint(struct usb_ep *ep, struct usb_function *f)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	struct usb_composite_dev *cdev = f->config->cdev;
	int ret;

	/* first disable endpoint, if it is already enabled */
	if (ep->driver_data) {
		usb_ep_disable(ep);
	} else {
		ret = config_ep_by_speed(cdev->gadget, f, ep);

		if (ret < 0) {
			return ret;
		}
	}

	/* enable endpoint */
	ret = usb_ep_enable(ep);

	if (ret < 0) {
		return ret;
	}

	/* mark endpoint as enabled */
	ep->driver_data = ctx;

	return ret;
}

static void f_brick_disable_endpoint(struct usb_ep *ep)
{
	int ret;

	if (ep->driver_data) {
		/* disable endpoint */
		ret = usb_ep_disable(ep);

		if (ret < 0) {
			printk(">>>>>>>>>>>>>>>>>> usb_ep_disable failed %d\n", ret);
		}

		/* mark endpoint as disabled */
		ep->driver_data = NULL;
	}
}

static int f_brick_func_set_alt(struct usb_function *f, unsigned intf, unsigned alt)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	int ret;
	unsigned long flags;
	struct usb_request *tx_probe;

	/* enable in endpoint */
	ret = f_brick_enable_endpoint(ctx->ep_in, f);

	if (ret < 0) {
		return ret;
	}

	/* enable out endpoint */
	ret = f_brick_enable_endpoint(ctx->ep_out, f);

	if (ret < 0) {
		f_brick_disable_endpoint(ctx->ep_in);

		return ret;
	}

	spin_lock_irqsave(&ctx->lock, flags);

	f_brick_reset_requests();

	/* queue probe request to figure out when the USB host is ready to receive
	 * data. this is a workaround for the problem with the first request being
	 * mangled. typically the first request send to the USB host is the 34 byte
	 * enumerate callback for the RED Brick itself. the first 12 bytes of this
	 * request get overwritten by [A1 20 00 00 01 00 02 00 03 00 02 00] if they
	 * are queued to the endpoint too early. directly before the data is written
	 * to the endpoint FIFO it is still correct, but the USB host receives it
	 * mangled. this doesn't seem to be a host side problem as it happens with
	 * Linux and Windows hosts.
	 *
	 * the callstack is:
	 *
	 * usb_ep_queue
	 * sw_udc_queue
	 * sw_udc_write_fifo
	 * pio_write_fifo
	 * sw_udc_write_packet
	 * USBC_WritePacket
	 *
	 * to workaround this send a 1 byte request. it doesn't matter if this one
	 * gets mangled because it contains no relevant data. brickd on the USB
	 * host side can filter it out by its length alone. */
	tx_probe = ctx->tx_probe;
	ctx->tx_probe = NULL;

	spin_unlock_irqrestore(&ctx->lock, flags);

	if (tx_probe) {
		*(uint8_t *)tx_probe->buf = 170; // 0b10101010
		tx_probe->length = 1;

		ret = usb_ep_queue(ctx->ep_in, tx_probe, GFP_ATOMIC);

		if (ret < 0) {
			ctx->tx_probe = tx_probe;

			printk("f_brick_func_set_alt: tx_probe usb_ep_queue failed: %d\n", ret);
		}
	}

	return 0;
}

static void f_brick_func_disable(struct usb_function *f)
{
	unsigned long flags;
	struct f_brick_ctx *ctx = _f_brick_ctx;

	/*
	 * According to, https://groups.google.com/forum/#!topic/linux.kernel/bhJe9qN_twI
	 * (Felipe Balbi's post of 14-10-2016) usb_ep_disable() should not be called with
	 * locks held.
	 *
	 * With our older 3.4 kernel this was not a problem but with the latest mainline
	 * kernel, doing so caused the whole system to totally hang. So as a fix we disable
	 * the end points before acquiring the ctx->lock lock.
	 */

	f_brick_disable_endpoint(ctx->ep_in);
	f_brick_disable_endpoint(ctx->ep_out);

	spin_lock_irqsave(&ctx->lock, flags);

	f_brick_set_state(F_BRICK_STATE_USB_DISCONNECTED);

	/* unblock waiting reader, as there is currently nothing to read */
	wake_up(&ctx->rx_wait);

	spin_unlock_irqrestore(&ctx->lock, flags);
}

int f_brick_bind_config(struct usb_configuration *c)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	int ret;

	if (f_brick_string_defs[F_BRICK_STRING_INTERFACE_IDX].id == 0) {
		ret = usb_string_id(c->cdev);

		if (ret < 0) {
			return ret;
		}

		f_brick_string_defs[F_BRICK_STRING_INTERFACE_IDX].id = ret;
	}

	f_brick_string_defs[F_BRICK_STRING_MICROSOFT_OS_IDX].id = 0xEE;

	ctx->cdev                = c->cdev;
	ctx->func.name           = "brick";
	ctx->func.strings        = f_brick_strings;
	ctx->func.fs_descriptors = f_brick_fs_descs;
	ctx->func.hs_descriptors = f_brick_hs_descs;
	ctx->func.bind           = f_brick_func_bind;
	ctx->func.unbind         = f_brick_func_unbind;
	ctx->func.set_alt        = f_brick_func_set_alt;
	ctx->func.setup          = f_brick_func_setup;
	ctx->func.disable        = f_brick_func_disable;

	return usb_add_function(c, &ctx->func);
}
EXPORT_SYMBOL_GPL(f_brick_bind_config);

static int f_brick_data_fop_open(struct inode *ip, struct file *fp)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	unsigned long flags;

	if (ctx->data_file_is_open) {
		return -EBUSY;
	}

	ctx->data_file_is_open = 1;

	spin_lock_irqsave(&ctx->lock, flags);

	f_brick_reset_requests();

	spin_unlock_irqrestore(&ctx->lock, flags);

	return 0;
}

static int f_brick_data_fop_release(struct inode *ip, struct file *fp)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;

	ctx->data_file_is_open = 0;

	return 0;
}

static ssize_t f_brick_data_fop_read(struct file *fp, char __user *buf,
                                     size_t buf_len, loff_t *pos)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	unsigned long flags;
	struct usb_request *rx_partial_req;
	u8 *rx_partial_buf;
	unsigned rx_partial_buf_len;
	struct usb_request *req;
	size_t copy_len;
	size_t total_len = 0;

	if (buf_len == 0) {
		return 0;
	}

	if (!access_ok(buf, buf_len)) {
		return -EFAULT;
	}

	f_brick_enqueue_rx_idle();

	mutex_lock(&ctx->fops_lock);
	spin_lock_irqsave(&ctx->lock, flags);

	rx_partial_req = ctx->rx_partial_req;
	rx_partial_buf = ctx->rx_partial_buf;
	rx_partial_buf_len = ctx->rx_partial_buf_len;
	ctx->rx_partial_req = NULL;
	ctx->rx_partial_buf = NULL;
	ctx->rx_partial_buf_len = 0;

	/* if no (partial) complete RX request is available then wait for one */
	if (!rx_partial_req && list_empty(&ctx->rx_reqs_complete)) {
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (fp->f_flags & (O_NONBLOCK | O_NDELAY)) {
			mutex_unlock(&ctx->fops_lock);

			return -EAGAIN;
		}

		/* wait until a RX request completes */
		if (wait_event_interruptible(ctx->rx_wait, !list_empty(&ctx->rx_reqs_complete)) < 0) {
			mutex_unlock(&ctx->fops_lock);

			return -ERESTARTSYS;
		}

		spin_lock_irqsave(&ctx->lock, flags);
	}

	/* copy available data to the user buffer */
	while (buf_len > 0 && (rx_partial_req || !list_empty(&ctx->rx_reqs_complete))) {
		if (!rx_partial_req) {
			req = list_first_entry(&ctx->rx_reqs_complete, struct usb_request, list);
			list_del_init(&req->list);

			rx_partial_req = req;
			rx_partial_buf = req->buf;
			rx_partial_buf_len = req->actual;
		}

		if (buf_len > rx_partial_buf_len) {
			copy_len = rx_partial_buf_len;
		} else {
			copy_len = buf_len;
		}

		spin_unlock_irqrestore(&ctx->lock, flags);

		// FIXME: if copy_len gets 0 then this can become and endless loop
		copy_len -= copy_to_user(buf, rx_partial_buf, copy_len);

		spin_lock_irqsave(&ctx->lock, flags);

		buf += copy_len;
		buf_len -= copy_len;

		rx_partial_buf += copy_len;
		rx_partial_buf_len -= copy_len;

		total_len += copy_len;

		if (rx_partial_buf_len == 0) {
			list_add(&rx_partial_req->list, &ctx->rx_reqs_idle);

			rx_partial_req = NULL;
			rx_partial_buf = NULL;
		}
	}

	ctx->rx_partial_req = rx_partial_req;
	ctx->rx_partial_buf = rx_partial_buf;
	ctx->rx_partial_buf_len = rx_partial_buf_len;

	spin_unlock_irqrestore(&ctx->lock, flags);
	mutex_unlock(&ctx->fops_lock);

	if (total_len == 0) {
		return -EAGAIN;
	}

	return total_len;
}

static ssize_t f_brick_data_fop_write(struct file *fp, const char __user *buf,
                                      size_t buf_len, loff_t *pos)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	unsigned long flags;
	struct usb_request *req;
	size_t packet_len; /* from packet header */
	size_t copy_len;
	size_t total_len = 0;
	int ret;

	if (buf_len == 0) {
		return 0;
	}

	if (!access_ok(buf, buf_len)) {
		return -EFAULT;
	}

	mutex_lock(&ctx->fops_lock);
	spin_lock_irqsave(&ctx->lock, flags);

	/* if no TX requests are available wait for some */
	if (ctx->state != F_BRICK_STATE_USB_CONNECTED || list_empty(&ctx->tx_reqs_idle)) {
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (fp->f_flags & (O_NONBLOCK | O_NDELAY)) {
			mutex_unlock(&ctx->fops_lock);

			return -EAGAIN;
		}

		if (wait_event_interruptible(ctx->tx_wait, ctx->state == F_BRICK_STATE_USB_CONNECTED && !list_empty(&ctx->tx_reqs_idle)) < 0) {
			mutex_unlock(&ctx->fops_lock);

			return -ERESTARTSYS;
		}

		spin_lock_irqsave(&ctx->lock, flags);
	}

	/* copy available data from the user buffer */
	while (buf_len > 0 && ctx->state == F_BRICK_STATE_USB_CONNECTED && (ctx->tx_partial_req || !list_empty(&ctx->tx_reqs_idle))) {
		if (!ctx->tx_partial_req) {
			req = list_first_entry(&ctx->tx_reqs_idle, struct usb_request, list);
			list_del_init(&req->list);

			ctx->tx_partial_req = req;
			ctx->tx_partial_buf = req->buf;
			ctx->tx_partial_buf_len = 0;
		}

		if (ctx->tx_partial_buf_len < sizeof(struct f_brick_packet_header)) {
			/* copy header */
			copy_len = sizeof(struct f_brick_packet_header) - ctx->tx_partial_buf_len;
		} else {
			/* copy payload */
			packet_len = ((struct f_brick_packet_header *)ctx->tx_partial_buf)->length; // FIXME: use union instead of cast

			if (packet_len > sizeof(struct f_brick_packet)) {
				packet_len = sizeof(struct f_brick_packet);
			}

			copy_len = packet_len - ctx->tx_partial_buf_len;
		}

		if (copy_len > buf_len) {
			copy_len = buf_len;
		}

		spin_unlock_irqrestore(&ctx->lock, flags);

		// FIXME: if copy_len gets 0 then this can become an endless loop
		copy_len -= copy_from_user(ctx->tx_partial_buf + ctx->tx_partial_buf_len, buf, copy_len);

		spin_lock_irqsave(&ctx->lock, flags);

		buf += copy_len;
		buf_len -= copy_len;

		ctx->tx_partial_buf_len += copy_len;

		total_len += copy_len;

		if (ctx->tx_partial_buf_len >= sizeof(struct f_brick_packet_header) &&
		    ctx->tx_partial_buf_len == ((struct f_brick_packet_header *)ctx->tx_partial_buf)->length) {
			ctx->tx_partial_req->zero = (ctx->tx_partial_buf_len % ctx->ep_in->maxpacket) == 0;
			ctx->tx_partial_req->length = ctx->tx_partial_buf_len;

			list_add(&ctx->tx_partial_req->list, &ctx->tx_reqs_active);

			spin_unlock_irqrestore(&ctx->lock, flags);

			ret = usb_ep_queue(ctx->ep_in, ctx->tx_partial_req, GFP_ATOMIC);

			spin_lock_irqsave(&ctx->lock, flags);

			if (ret < 0) {
				list_del_init(&ctx->tx_partial_req->list); /* remove from tx_reqs_active */
				list_add(&ctx->tx_partial_req->list, &ctx->tx_reqs_idle);
			}

			ctx->tx_partial_req = NULL;
			ctx->tx_partial_buf = NULL;
			ctx->tx_partial_buf_len = 0;
		}
	}

	spin_unlock_irqrestore(&ctx->lock, flags);
	mutex_unlock(&ctx->fops_lock);

	if (total_len == 0) {
		return -EAGAIN;
	}

	return total_len;
}

static unsigned int f_brick_data_fop_poll(struct file *fp, poll_table *wait)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	unsigned long flags;
	unsigned int status = 0;

	f_brick_enqueue_rx_idle();

	poll_wait(fp, &ctx->tx_wait, wait);
	poll_wait(fp, &ctx->rx_wait, wait);

	spin_lock_irqsave(&ctx->lock, flags);

	if (ctx->state == F_BRICK_STATE_USB_CONNECTED && !list_empty(&ctx->tx_reqs_idle)) {
		status |= POLLOUT | POLLWRNORM;
	}

	if (ctx->rx_partial_buf_len > 0 || !list_empty(&ctx->rx_reqs_complete)) {
		status |= POLLIN | POLLRDNORM;
	}

	spin_unlock_irqrestore(&ctx->lock, flags);

	return status;
}

static const struct file_operations f_brick_data_fops = {
	.owner   = THIS_MODULE,
	.open    = f_brick_data_fop_open,
	.release = f_brick_data_fop_release,
	.read    = f_brick_data_fop_read,
	.write   = f_brick_data_fop_write,
	.poll    = f_brick_data_fop_poll,
};

static struct miscdevice f_brick_data_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "g_red_brick_data",
	.fops  = &f_brick_data_fops,
};

static int f_brick_state_fop_open(struct inode *ip, struct file *fp)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;

	if (ctx->state_file_is_open) {
		return -EBUSY;
	}

	ctx->state_file_is_open = 1;

	return 0;
}

static int f_brick_state_fop_release(struct inode *ip, struct file *fp)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;

	ctx->state_file_is_open = 0;

	return 0;
}

static ssize_t f_brick_state_fop_read(struct file *fp, char __user *buf,
                                      size_t buf_len, loff_t *pos)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	unsigned long flags;
	u8 state;
	size_t copy_len;
	size_t total_len = 0;

	if (buf_len == 0) {
		return 0;
	}

	if (*pos >= sizeof(state)) {
		return 0;
	}

	copy_len = sizeof(state) - *pos;

	if (!access_ok(buf, buf_len)) {
		return -EFAULT;
	}

	spin_lock_irqsave(&ctx->lock, flags);

	state = ctx->state;
	ctx->state_changed = 0;

	spin_unlock_irqrestore(&ctx->lock, flags);

	copy_len -= copy_to_user(buf, &state, copy_len);

	total_len += copy_len;

	if (total_len == 0) {
		spin_lock_irqsave(&ctx->lock, flags);

		ctx->state_changed = 1;

		spin_unlock_irqrestore(&ctx->lock, flags);

		return -EAGAIN;
	}

	*pos += total_len;

	return total_len;
}

static unsigned int f_brick_state_fop_poll(struct file *fp, poll_table *wait)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	unsigned long flags;
	unsigned int status = 0;

	poll_wait(fp, &ctx->state_wait, wait);

	spin_lock_irqsave(&ctx->lock, flags);

	if (ctx->state_changed) {
		status |= POLLIN | POLLRDNORM;
	}

	spin_unlock_irqrestore(&ctx->lock, flags);

	return status;
}

static loff_t f_brick_state_fop_llseek(struct file *fp, loff_t offset, int origin)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;
	unsigned long flags;
	loff_t ret;

	spin_lock_irqsave(&ctx->lock, flags);

	switch (origin) {
	case SEEK_END:
		offset += sizeof(ctx->state);

		break;

	case SEEK_CUR:
		offset += fp->f_pos;

		break;
	}

	ret = -EINVAL;

	if (offset >= 0) {
		if (offset != fp->f_pos) {
			fp->f_pos = offset;
			fp->f_version = 0;
		}

		ret = offset;
	}

	spin_unlock_irqrestore(&ctx->lock, flags);

	return ret;
}

static const struct file_operations f_brick_state_fops = {
	.owner   = THIS_MODULE,
	.open    = f_brick_state_fop_open,
	.release = f_brick_state_fop_release,
	.read    = f_brick_state_fop_read,
	.poll    = f_brick_state_fop_poll,
	.llseek  = f_brick_state_fop_llseek,
};

int f_brick_setup(void)
{
	struct f_brick_ctx *ctx;
	int ret;

	/* allocate and initialize f_brick_ctx */
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);

	if (!ctx) {
		return -ENOMEM;
	}

	ctx->ep_in = NULL;
	ctx->ep_out = NULL;

	ctx->state_file_is_open = 0;
	ctx->state = F_BRICK_STATE_USB_DISCONNECTED;
	ctx->state_changed = 0;

	init_waitqueue_head(&ctx->state_wait);

	ctx->data_file_is_open = 0;

	spin_lock_init(&ctx->lock);
	mutex_init(&ctx->fops_lock);

	ctx->tx_partial_req = NULL;
	ctx->tx_partial_buf = NULL;
	ctx->tx_partial_buf_len = 0;

	ctx->rx_partial_req = NULL;
	ctx->rx_partial_buf = NULL;
	ctx->rx_partial_buf_len = 0;

	INIT_LIST_HEAD(&ctx->tx_reqs_idle);
	INIT_LIST_HEAD(&ctx->tx_reqs_active);
	INIT_LIST_HEAD(&ctx->rx_reqs_idle);

	INIT_LIST_HEAD(&ctx->rx_reqs_active);
	INIT_LIST_HEAD(&ctx->rx_reqs_complete);

	init_waitqueue_head(&ctx->tx_wait);
	init_waitqueue_head(&ctx->rx_wait);

	_f_brick_ctx = ctx;

	/* register /dev/g_red_brick_data */
	ret = misc_register(&f_brick_data_dev);

	if (ret < 0) {
		_f_brick_ctx = NULL;

		kfree(ctx);

		printk(KERN_ERR "could not register /dev/g_red_brick_data\n");

		return ret;
	}

	/* create /proc/g_red_brick_state */
	if (!proc_create("g_red_brick_state", 0, NULL, &f_brick_state_fops)) {
		misc_deregister(&f_brick_data_dev);

		_f_brick_ctx = NULL;

		kfree(ctx);

		printk(KERN_ERR "could not register /proc/g_red_brick_state\n");

		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(f_brick_setup);

void f_brick_cleanup(void)
{
	struct f_brick_ctx *ctx = _f_brick_ctx;

	if (!ctx) {
		return;
	}

	remove_proc_entry("g_red_brick_state", NULL);
	misc_deregister(&f_brick_data_dev);

	_f_brick_ctx = NULL;

	kfree(ctx);
}
EXPORT_SYMBOL_GPL(f_brick_cleanup);

MODULE_AUTHOR("Matthias Bolte");
MODULE_AUTHOR("Ishraq Ibne Ashraf");
MODULE_LICENSE("GPL");
