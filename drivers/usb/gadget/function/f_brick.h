/*
 * f_brick.h -- USB gadget RED Brick driver
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

#ifndef F_BRICK_H
#define F_BRICK_H

#include <linux/usb/composite.h>

int f_brick_setup(void);
void f_brick_cleanup(void);
int f_brick_bind_config(struct usb_configuration *c);

#endif // F_BRICK_H
