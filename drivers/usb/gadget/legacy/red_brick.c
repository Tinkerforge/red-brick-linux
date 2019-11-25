/*
 * red_brick.c -- USB gadget RED Brick driver
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

#include <linux/fs.h>
#include <linux/tty.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/tty_flip.h>
#include <linux/byteorder/generic.h>

#include "f_brick.h"
#include "u_serial.h"

USB_GADGET_COMPOSITE_OPTIONS();

#define VENDOR_ID  0x16D0
#define PRODUCT_ID 0x09E5
#define BASE58_MAX_LENGTH 8
#define LONG_NAME "RED Brick"

// Function prototypes.
static int red_brick_bind(struct usb_composite_dev *cdev);
static int red_brick_unbind(struct usb_composite_dev *cdev);

static unsigned n_ports = 1;
static char serial_number[BASE58_MAX_LENGTH] = "";
static struct usb_function *f_serial[MAX_U_SERIAL_PORTS];
static const char *_base58_alphabet =
	"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
static struct usb_function_instance *fi_serial[MAX_U_SERIAL_PORTS];

static struct usb_string strings_dev[] = {
	[USB_GADGET_MANUFACTURER_IDX].s = "Tinkerforge GmbH",
	[USB_GADGET_PRODUCT_IDX].s      = LONG_NAME,
	[USB_GADGET_SERIAL_IDX].s       = serial_number,
	{}
};

static struct usb_gadget_strings stringtab_dev = {
	.language	= 0x0409,	// en-US.
	.strings	= strings_dev,
};

static struct usb_gadget_strings *dev_strings[] = {
	&stringtab_dev,
	NULL,
};

static struct usb_device_descriptor device_desc = {
	.bLength            = sizeof(device_desc),
	.bDescriptorType    = USB_DT_DEVICE,
	.bcdUSB             = __constant_cpu_to_le16(0x0200),
	.bDeviceClass       = USB_CLASS_PER_INTERFACE,
	.idVendor           = __constant_cpu_to_le16(VENDOR_ID),
	.idProduct          = __constant_cpu_to_le16(PRODUCT_ID),
	.bcdDevice          = __constant_cpu_to_le16(0x0110),
	.bNumConfigurations = 1,
};

static const struct usb_descriptor_header *otg_desc[2];

static struct usb_composite_driver red_brick_composite_driver = {
	.name      = "RED Brick Composite Device",
	.dev       = &device_desc,
	.strings   = dev_strings,
	.max_speed = USB_SPEED_SUPER,
	.bind      = red_brick_bind,
	.unbind    = red_brick_unbind,
};

// Convert from host endian to little endian.
uint32_t uint32_to_le(uint32_t native) {
	union {
		uint8_t bytes[4];
		uint32_t little;
	} c;

	c.bytes[0] = (native >>  0) & 0xFF;
	c.bytes[1] = (native >>  8) & 0xFF;
	c.bytes[2] = (native >> 16) & 0xFF;
	c.bytes[3] = (native >> 24) & 0xFF;

	return c.little;
}

int red_brick_uid(uint32_t *uid /* Always little endian. */) {
	int i;
	int rc;

	struct file *fp;
	mm_segment_t fs;

	uint8_t uid_u8_0;
	uint8_t uid_u8_1;
	uint8_t uid_u8_2;
	uint8_t uid_u8_3;
	uint16_t sid_u16[8];

	memset(sid_u16, 0, sizeof(sid_u16));

	fp = filp_open("/sys/bus/nvmem/devices/sunxi-sid0/nvmem", O_RDONLY, 0);

	if (fp == NULL) {
		return -1;
	}

	// Get current segment descriptor.
	fs = get_fs();

	// Set segment descriptor associated to kernel space.
	set_fs(KERNEL_DS);

	// Read the file.
	rc = fp->f_op->read(fp, (char *)sid_u16, sizeof(sid_u16), &fp->f_pos);

	// Restore segment descriptor.
	set_fs(fs);

	filp_close(fp, NULL);

	if (rc != sizeof(sid_u16)) {
		return -1;
	}

	for(i = 0; i < sizeof(sid_u16) / 2; i++) {
		sid_u16[i] = ntohs(sid_u16[i]);
	}

	uid_u8_0 = ((uint8_t *)&sid_u16[1])[0];
	uid_u8_1 = ((uint8_t *)&sid_u16[6])[0];
	uid_u8_2 = ((uint8_t *)&sid_u16[7])[1];
	uid_u8_3 = ((uint8_t *)&sid_u16[7])[0];

	*uid = (uid_u8_0 << 24) | (uid_u8_1 << 16) | (uid_u8_2 << 8) | uid_u8_3;

	/*
	 * Avoid collisions with other Brick UIDs by clearing the 31th bit,
	 * as other Brick UIDs should have the 31th bit set always.
	 *
	 * Avoid collisions with Bricklet UIDs by setting the 30th bit to
	 * get a high UID, as Bricklets have a low UID.
	 */
	*uid = (*uid & ~(1 << 31)) | (1 << 30);

	*uid = uint32_to_le(*uid);

	return 0;
}

void base58_encode(char *base58, uint32_t value) {
	int i = 0;
	int k = 0;
	uint32_t digit;
	char reverse[BASE58_MAX_LENGTH];

	while (value >= 58) {
		digit = value % 58;
		reverse[i] = _base58_alphabet[digit];
		value = value / 58;
		++i;
	}

	reverse[i] = _base58_alphabet[value];

	for (k = 0; k <= i; ++k) {
		base58[k] = reverse[i - k];
	}

	for (; k < BASE58_MAX_LENGTH; ++k) {
		base58[k] = '\0';
	}
}

int red_brick_get_uid_str(char *serial_number) {
	int ret = 0;
	uint32_t uid = 0;

	ret = red_brick_uid(&uid);

	if(ret < 0) {
		return ret;
	}

	base58_encode(serial_number, uid);

	return 0;
}

static int red_brick_config_setup(struct usb_configuration *c,
                                  const struct usb_ctrlrequest *ctrl) {
	struct usb_function *f = NULL;

	f = c->interface[0];

	if (f && f->setup) {
		return f->setup(f, ctrl);
	}

	return -EOPNOTSUPP;
}

static struct usb_configuration red_brick_config = {
	.label               = "RED Brick",
	.bConfigurationValue = 1,
	.bmAttributes        = USB_CONFIG_ATT_ONE,
	.MaxPower            = 500, // 500 mA.
	.setup               = red_brick_config_setup,
};

static int red_brick_serial_bind_config(struct usb_configuration *c) {
	int i;
	int ret;

	for (i = 0; i < n_ports; i++) {
		fi_serial[i] = usb_get_function_instance("acm");

		if (IS_ERR(fi_serial[i])) {
			ret = PTR_ERR(fi_serial[i]);
			goto fail;
		}

		f_serial[i] = usb_get_function(fi_serial[i]);

		if (IS_ERR(f_serial[i])) {
			ret = PTR_ERR(f_serial[i]);
			goto err_get_func;
		}

		ret = usb_add_function(c, f_serial[i]);

		if (ret) {
			goto err_add_func;
		}
	}

	return 0;

err_add_func:
	usb_put_function(f_serial[i]);

err_get_func:
	usb_put_function_instance(fi_serial[i]);

fail:
	i--;
	while (i >= 0) {
		usb_remove_function(c, f_serial[i]);
		usb_put_function(f_serial[i]);
		usb_put_function_instance(fi_serial[i]);

		i--;
	}

	return ret;
}

static int red_brick_bind_config(struct usb_configuration *c) {
	int ret;

	// Add RED Brick configuration.
	ret = f_brick_bind_config(c);

	if (ret < 0) {
		return ret;
	}

	// Add RED Brick Serial configuration.
	ret = red_brick_serial_bind_config(c);

	if (ret < 0) {
		return ret;
	}

	return 0;
}

static int red_brick_bind(struct usb_composite_dev *cdev) {
	int ret;

	ret = usb_string_id(cdev);

	if (ret < 0) {
		goto fail;
	}

	strings_dev[USB_GADGET_MANUFACTURER_IDX].id = ret;
	device_desc.iManufacturer = ret;

	ret = usb_string_id(cdev);

	if (ret < 0) {
		goto fail;
	}

	strings_dev[USB_GADGET_PRODUCT_IDX].id = ret;
	device_desc.iProduct = ret;

	// Set serial number from UID.
	ret = red_brick_get_uid_str(serial_number);

	if (ret < 0) {
		goto fail;
	}

	ret = usb_string_id(cdev);

	if (ret < 0) {
		goto fail;
	}

	strings_dev[USB_GADGET_SERIAL_IDX].id = ret;
	device_desc.iSerialNumber = ret;

	if (gadget_is_otg(cdev->gadget)) {
		red_brick_config.descriptors = otg_desc;
		red_brick_config.bmAttributes |= USB_CONFIG_ATT_WAKEUP;
	}

	// Register RED Brick configuration.
	ret = usb_add_config(cdev, &red_brick_config, red_brick_bind_config);

	if (ret < 0) {
		goto fail;
	}

	return 0;

fail:
	kfree(otg_desc[0]);
	otg_desc[0] = NULL;

	return ret;
}

static int red_brick_unbind(struct usb_composite_dev *cdev) {
	int i;

	for (i = 0; i < n_ports; i++) {
		usb_put_function(f_serial[i]);
		usb_put_function_instance(fi_serial[i]);
	}

	kfree(otg_desc[0]);
	otg_desc[0] = NULL;

	return 0;
}

static int __init init(void) {
	int ret = 0;

	ret = f_brick_setup();

	if (ret < 0) {
		return ret;
	}

	ret = usb_composite_probe(&red_brick_composite_driver);

	if (ret < 0) {
		f_brick_cleanup();

		return ret;
	}

	return 0;
}

static void __exit cleanup(void) {
	usb_composite_unregister(&red_brick_composite_driver);
	f_brick_cleanup();
}

module_init(init);
module_exit(cleanup);

MODULE_DESCRIPTION(LONG_NAME);
MODULE_AUTHOR("Matthias Bolte");
MODULE_AUTHOR("Ishraq Ibne Ashraf");
MODULE_LICENSE("GPL");
