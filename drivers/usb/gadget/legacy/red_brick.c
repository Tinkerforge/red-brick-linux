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

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>

#include "f_brick.h"
#include "u_serial.h"

USB_GADGET_COMPOSITE_OPTIONS();

#define LONG_NAME "RED Brick"

#define VENDOR_ID  0x16D0
#define PRODUCT_ID 0x09E5

// String IDs are assigned dynamically.
#define STRING_DESCRIPTION_IDX USB_GADGET_FIRST_AVAIL_IDX

// Function prototypes.
static int gs_bind(struct usb_composite_dev *cdev);
static int gs_unbind(struct usb_composite_dev *cdev);

static unsigned n_ports = 1;

static struct usb_string strings_dev[] = {
	[USB_GADGET_MANUFACTURER_IDX].s = "Tinkerforge GmbH",
	[USB_GADGET_PRODUCT_IDX].s      = LONG_NAME,
	[USB_GADGET_SERIAL_IDX].s       = "DUMMY1234", // TODO: Generate UID from chip ID.
	[STRING_DESCRIPTION_IDX].s      = NULL,
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
	.bLength            = USB_DT_DEVICE_SIZE,
	.bDescriptorType    = USB_DT_DEVICE,
	.bDeviceSubClass    = 0,
	.bDeviceProtocol    = 0,
	.idVendor           = cpu_to_le16(VENDOR_ID),
	.bNumConfigurations = 1,
};

static const struct usb_descriptor_header *otg_desc[2];

static struct usb_composite_driver gserial_driver = {
	.name      = "RED Brick",
	.dev       = &device_desc,
	.strings   = dev_strings,
	.max_speed = USB_SPEED_SUPER,
	.bind      = gs_bind,
	.unbind    = gs_unbind,
};

static struct usb_configuration serial_config_driver = {
	.bmAttributes	= USB_CONFIG_ATT_SELFPOWER,
};

static struct usb_function *f_serial[MAX_U_SERIAL_PORTS];
static struct usb_function_instance *fi_serial[MAX_U_SERIAL_PORTS];

static int serial_register_ports(struct usb_composite_dev *cdev,
                                 struct usb_configuration *c,
                                 const char *f_name) {
	int i;
	int ret;

	ret = usb_add_config_only(cdev, c);

	if (ret) {
		goto out;
	}

	for (i = 0; i < n_ports; i++) {
		fi_serial[i] = usb_get_function_instance(f_name);

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

	ret = f_brick_bind_config(c);

	if (ret < 0) {
		printk(KERN_DEBUG "could not bind Brick config\n");

		return ret;
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

out:
	return ret;
}

static int gs_bind(struct usb_composite_dev *cdev) {
	int status;

	/*
	 * Allocate string descriptor numbers. Note that string
	 * contents can be overridden by the composite_dev glue.
	 */
	status = usb_string_ids_tab(cdev, strings_dev);

	if (status < 0) {
		goto fail;
	}

	device_desc.iManufacturer = strings_dev[USB_GADGET_MANUFACTURER_IDX].id;
	device_desc.iProduct = strings_dev[USB_GADGET_PRODUCT_IDX].id;
	status = strings_dev[STRING_DESCRIPTION_IDX].id;
	serial_config_driver.iConfiguration = status;

	if (gadget_is_otg(cdev->gadget)) {
		if (!otg_desc[0]) {
			struct usb_descriptor_header *usb_desc;

			usb_desc = usb_otg_descriptor_alloc(cdev->gadget);

			if (!usb_desc) {
				status = -ENOMEM;
				goto fail;
			}

			usb_otg_descriptor_init(cdev->gadget, usb_desc);
			otg_desc[0] = usb_desc;
			otg_desc[1] = NULL;
		}

		serial_config_driver.descriptors = otg_desc;
		serial_config_driver.bmAttributes |= USB_CONFIG_ATT_WAKEUP;
	}

	// Register our configuration.
	status = serial_register_ports(cdev,
                                 &serial_config_driver,
                                 "acm");

	usb_ep_autoconfig_reset(cdev->gadget);

	if (status < 0) {
		goto fail1;
	}

	usb_composite_overwrite_options(cdev, &coverwrite);

	return 0;

fail1:
	kfree(otg_desc[0]);
	otg_desc[0] = NULL;

fail:
	return status;
}

static int gs_unbind(struct usb_composite_dev *cdev) {
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
	serial_config_driver.label = "CDC ACM config";
	serial_config_driver.bConfigurationValue = 2;
	device_desc.bDeviceClass = USB_CLASS_COMM;
	device_desc.idProduct = cpu_to_le16(PRODUCT_ID);
	strings_dev[STRING_DESCRIPTION_IDX].s = serial_config_driver.label;

	ret = f_brick_setup();

	if (ret < 0) {
		return ret;
	}

	ret = usb_composite_probe(&gserial_driver);

	if (ret < 0) {
		f_brick_cleanup();

		return ret;
	}

	return 0;
}

static void __exit cleanup(void) {
	usb_composite_unregister(&gserial_driver);
	f_brick_cleanup();
}

module_init(init);
module_exit(cleanup);

MODULE_DESCRIPTION(LONG_NAME);
MODULE_AUTHOR("Matthias Bolte");
MODULE_AUTHOR("Ishraq Ibne Ashraf");
MODULE_LICENSE("GPL");
