/*
 * Copyright (C) 2012 - 2014 Allwinner Tech
 * Pan Nan <pannan@allwinnertech.com>
 *
 * Copyright (C) 2014 Maxime Ripard
 * Maxime Ripard <maxime.ripard@free-electrons.com>
 *
 * Copyright (C) 2017 Ishraq Ibne Ashraf
 * Ishraq Ibne Ashraf <ishraq@tinkerforge.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/spi/spi.h>

#ifdef CONFIG_RED_BRICK
	#include <linux/workqueue.h>
#endif

#define SUN4I_FIFO_DEPTH 64
#define SUN4I_RXDATA_REG 0x00
#define SUN4I_TXDATA_REG 0x04

#define SUN4I_CTL_REG 0x08
#define SUN4I_CTL_ENABLE BIT(0)
#define SUN4I_CTL_MASTER BIT(1)
#define SUN4I_CTL_CPHA BIT(2)
#define SUN4I_CTL_CPOL BIT(3)
#define SUN4I_CTL_CS_ACTIVE_LOW BIT(4)
#define SUN4I_CTL_LMTF BIT(6)
#define SUN4I_CTL_TF_RST BIT(8)
#define SUN4I_CTL_RF_RST BIT(9)
#define SUN4I_CTL_XCH BIT(10)
#define SUN4I_CTL_CS_MASK 0x3000
#define SUN4I_CTL_CS(cs) (((cs) << 12) & SUN4I_CTL_CS_MASK)
#define SUN4I_CTL_DHB BIT(15)
#define SUN4I_CTL_CS_MANUAL BIT(16)
#define SUN4I_CTL_CS_LEVEL BIT(17)
#define SUN4I_CTL_TP BIT(18)

#define SUN4I_INT_CTL_REG 0x0c
#define SUN4I_INT_CTL_RF_F34 BIT(4)
#define SUN4I_INT_CTL_TF_E34 BIT(12)
#define SUN4I_INT_CTL_TC BIT(16)

#define SUN4I_INT_STA_REG 0x10
#define SUN4I_DMA_CTL_REG 0x14
#define SUN4I_WAIT_REG 0x18

#define SUN4I_CLK_CTL_REG 0x1c
#define SUN4I_CLK_CTL_CDR2_MASK 0xff
#define SUN4I_CLK_CTL_CDR2(div) ((div) & SUN4I_CLK_CTL_CDR2_MASK)
#define SUN4I_CLK_CTL_CDR1_MASK 0xf
#define SUN4I_CLK_CTL_CDR1(div) (((div) & SUN4I_CLK_CTL_CDR1_MASK) << 8)
#define SUN4I_CLK_CTL_DRS BIT(12)

#define SUN4I_MAX_XFER_SIZE 0xffffff

#define SUN4I_BURST_CNT_REG 0x20
#define SUN4I_BURST_CNT(cnt) ((cnt) & SUN4I_MAX_XFER_SIZE)

#define SUN4I_XMIT_CNT_REG 0x24
#define SUN4I_XMIT_CNT(cnt) ((cnt) & SUN4I_MAX_XFER_SIZE)

#define SUN4I_FIFO_STA_REG 0x28
#define SUN4I_FIFO_STA_RF_CNT_MASK 0x7f
#define SUN4I_FIFO_STA_RF_CNT_BITS 0
#define SUN4I_FIFO_STA_TF_CNT_MASK 0x7f
#define SUN4I_FIFO_STA_TF_CNT_BITS 16

struct sun4i_spi {
	int len;
	u8 *rx_buf;
	struct clk *hclk;
	struct clk *mclk;
	const u8 *tx_buf;
	struct completion done;
	void __iomem *base_addr;
	struct spi_master *master;

	#ifdef CONFIG_RED_BRICK
		/*
		 * OK = 0, FAILED = -1.
		 *
		 * The value of "result" is updated from the IRQ handler to indicate
		 * outcome of the SPI transfer to the work queue function.
		 */
		int result;
		spinlock_t lock;
		/*
		* Queue for SPI messages which are handled serially in the
		* workqueue function.
		*/
		struct list_head queue;
		struct work_struct work;
		struct workqueue_struct *workqueue;
	#endif
};

static inline u32 sun4i_spi_read(struct sun4i_spi *sspi, u32 reg)
{
	return readl(sspi->base_addr + reg);
}

static inline void sun4i_spi_write(struct sun4i_spi *sspi, u32 reg, u32 value)
{
	writel(value, sspi->base_addr + reg);
}

static inline u32 sun4i_spi_get_tx_fifo_count(struct sun4i_spi *sspi)
{
	u32 reg = sun4i_spi_read(sspi, SUN4I_FIFO_STA_REG);

	reg >>= SUN4I_FIFO_STA_TF_CNT_BITS;

	return reg & SUN4I_FIFO_STA_TF_CNT_MASK;
}

static inline void sun4i_spi_enable_interrupt(struct sun4i_spi *sspi, u32 mask)
{
	u32 reg = sun4i_spi_read(sspi, SUN4I_INT_CTL_REG);

	reg |= mask;
	sun4i_spi_write(sspi, SUN4I_INT_CTL_REG, reg);
}

static inline void sun4i_spi_disable_interrupt(struct sun4i_spi *sspi, u32 mask)
{
	u32 reg = sun4i_spi_read(sspi, SUN4I_INT_CTL_REG);

	reg &= ~mask;
	sun4i_spi_write(sspi, SUN4I_INT_CTL_REG, reg);
}

static inline void sun4i_spi_drain_fifo(struct sun4i_spi *sspi, int len)
{
	u32 reg, cnt;
	u8 byte;

	/* See how much data is available */
	reg = sun4i_spi_read(sspi, SUN4I_FIFO_STA_REG);
	reg &= SUN4I_FIFO_STA_RF_CNT_MASK;
	cnt = reg >> SUN4I_FIFO_STA_RF_CNT_BITS;

	if (len > cnt)
		len = cnt;

	while (len--) {
		byte = readb(sspi->base_addr + SUN4I_RXDATA_REG);
		if (sspi->rx_buf)
			*sspi->rx_buf++ = byte;
	}
}

static inline void sun4i_spi_fill_fifo(struct sun4i_spi *sspi, int len)
{
	u32 cnt;
	u8 byte;

	/* See how much data we can fit */
	cnt = SUN4I_FIFO_DEPTH - sun4i_spi_get_tx_fifo_count(sspi);

	len = min3(len, (int)cnt, sspi->len);

	while (len--) {
		byte = sspi->tx_buf ? *sspi->tx_buf++ : 0;
		writeb(byte, sspi->base_addr + SUN4I_TXDATA_REG);
		sspi->len--;
	}
}

static void sun4i_spi_set_cs(struct spi_device *spi, bool enable)
{
	struct sun4i_spi *sspi = spi_master_get_devdata(spi->master);
	u32 reg;

	reg = sun4i_spi_read(sspi, SUN4I_CTL_REG);

	reg &= ~SUN4I_CTL_CS_MASK;
	reg |= SUN4I_CTL_CS(spi->chip_select);

	/* We want to control the chip select manually */
	reg |= SUN4I_CTL_CS_MANUAL;

	if (enable)
		reg |= SUN4I_CTL_CS_LEVEL;
	else
		reg &= ~SUN4I_CTL_CS_LEVEL;

	/*
	 * Even though this looks irrelevant since we are supposed to
	 * be controlling the chip select manually, this bit also
	 * controls the levels of the chip select for inactive
	 * devices.
	 *
	 * If we don't set it, the chip select level will go low by
	 * default when the device is idle, which is not really
	 * expected in the common case where the chip select is active
	 * low.
	 */
	if (spi->mode & SPI_CS_HIGH)
		reg &= ~SUN4I_CTL_CS_ACTIVE_LOW;
	else
		reg |= SUN4I_CTL_CS_ACTIVE_LOW;

	sun4i_spi_write(sspi, SUN4I_CTL_REG, reg);
}

static size_t sun4i_spi_max_transfer_size(struct spi_device *spi)
{
	return SUN4I_FIFO_DEPTH - 1;
}

#ifdef CONFIG_RED_BRICK
	static int sun4i_spi_work_do_red_brick(struct spi_master *master,
	                                       struct spi_device *spi,
	                                       struct spi_transfer *tfr)
	{
		u32 reg;
		unsigned int tx_len = 0;
		unsigned int mclk_rate, div, start, end, tx_time, timeout;
		struct sun4i_spi *sspi = spi_master_get_devdata(master);

		// We don't support transfer larger than the FIFO.
		if (tfr->len > SUN4I_MAX_XFER_SIZE)
			return -EMSGSIZE;

		if (tfr->tx_buf && tfr->len >= SUN4I_MAX_XFER_SIZE)
			return -EMSGSIZE;

		reinit_completion(&sspi->done);

		sspi->tx_buf = tfr->tx_buf;
		sspi->rx_buf = tfr->rx_buf;
		sspi->len = tfr->len;

		// Clear pending interrupts.
		sun4i_spi_write(sspi, SUN4I_INT_STA_REG, ~0);

		// Reset FIFOs.
		reg = sun4i_spi_read(sspi, SUN4I_CTL_REG);

		sun4i_spi_write(sspi,
		                SUN4I_CTL_REG,
		                reg | SUN4I_CTL_RF_RST | SUN4I_CTL_TF_RST);

		/*
		 * Setup the transfer control register:
		 *
		 * Chip Select, polarities, etc.
		 */
		reg = sun4i_spi_read(sspi, SUN4I_CTL_REG);

		if (spi->mode & SPI_CPOL)
			reg |= SUN4I_CTL_CPOL;
		else
			reg &= ~SUN4I_CTL_CPOL;

		if (spi->mode & SPI_CPHA)
			reg |= SUN4I_CTL_CPHA;
		else
			reg &= ~SUN4I_CTL_CPHA;

		if (spi->mode & SPI_LSB_FIRST)
			reg |= SUN4I_CTL_LMTF;
		else
			reg &= ~SUN4I_CTL_LMTF;

		/*
		 * If it's a TX only transfer, we don't want to fill the RX
		 * FIFO with bogus data.
		 */
		if (sspi->rx_buf)
			reg &= ~SUN4I_CTL_DHB;
		else
			reg |= SUN4I_CTL_DHB;

		sun4i_spi_write(sspi, SUN4I_CTL_REG, reg);

		// Ensure that we have a parent clock fast enough.
		mclk_rate = clk_get_rate(sspi->mclk);

		if (mclk_rate < (2 * tfr->speed_hz)) {
			clk_set_rate(sspi->mclk, 2 * tfr->speed_hz);

			mclk_rate = clk_get_rate(sspi->mclk);
		}

		/*
		 * Setup clock divider.
		 *
		 * We have two choices there. Either we can use the clock
		 * divide rate 1, which is calculated thanks to this formula:
		 * SPI_CLK = MOD_CLK / (2 ^ (cdr + 1))
		 * Or we can use CDR2, which is calculated with the formula:
		 * SPI_CLK = MOD_CLK / (2 * (cdr + 1))
		 * Wether we use the former or the latter is set through the
		 * DRS bit.
		 *
		 * First try CDR2, and if we can't reach the expected
		 * frequency, fall back to CDR1.
		 */
		reg = sun4i_spi_read(sspi, SUN4I_CTL_REG);

		div = mclk_rate / (2 * tfr->speed_hz);

		if (div <= (SUN4I_CLK_CTL_CDR2_MASK + 1)) {
			if (div > 0)
				div--;

			reg = SUN4I_CLK_CTL_CDR2(div) | SUN4I_CLK_CTL_DRS;
		} else {
			div = ilog2(mclk_rate) - ilog2(tfr->speed_hz);
			reg = SUN4I_CLK_CTL_CDR1(div);
		}

		sun4i_spi_write(sspi, SUN4I_CLK_CTL_REG, reg);

		// Setup the transfer.
		if (sspi->tx_buf)
			tx_len = tfr->len;

		// Setup the counters.
		sun4i_spi_write(sspi, SUN4I_BURST_CNT_REG, SUN4I_BURST_CNT(tfr->len));
		sun4i_spi_write(sspi, SUN4I_XMIT_CNT_REG, SUN4I_XMIT_CNT(tx_len));

		/*
		 * Fill the TX FIFO
		 * Filling the FIFO fully causes timeout for some reason
		 * at least on spi2 on A10s
		 */
		sun4i_spi_fill_fifo(sspi, SUN4I_FIFO_DEPTH - 1);

		// Enable the interrupts.
		sun4i_spi_enable_interrupt(sspi, SUN4I_INT_CTL_TC | SUN4I_INT_CTL_RF_F34);

		// Only enable Tx FIFO interrupt if we really need it.
		if (tx_len > SUN4I_FIFO_DEPTH)
			sun4i_spi_enable_interrupt(sspi, SUN4I_INT_CTL_TF_E34);

		// Start the transfer.
		reg = sun4i_spi_read(sspi, SUN4I_CTL_REG);

		sun4i_spi_write(sspi, SUN4I_CTL_REG, reg | SUN4I_CTL_XCH);

		/*
		 * The transfer complete will be set from the IRQ handler when SPI hardware
		 * signals transfer complete with interrupt or a timeout must occur, which
		 * ever happens happens first.
		 */
		tx_time = max(tfr->len * 8 * 2 / (tfr->speed_hz / 1000), 100U);
		start = jiffies;
		timeout = wait_for_completion_interruptible_timeout(&sspi->done,
		                                                    msecs_to_jiffies(tx_time));
		end = jiffies;

		if (!timeout) {
			dev_warn(&sspi->master->dev,
			         "%s: timeout transferring %u bytes@%iHz for %i(%i)ms",
			         dev_name(&spi->dev),
			         tfr->len,
			         tfr->speed_hz,
			         jiffies_to_msecs(end - start),
			         tx_time);

			sspi->result = -ETIMEDOUT;
		}

		// Get return code which is updated in the interrupt handler.
		if(sspi->result != 0)
			dev_warn(&sspi->master->dev, "SPI transfer failed\n");

		return sspi->result;
	}

	static void sun4i_spi_work_red_brick(struct work_struct *work)
	{
		int status;
		struct spi_message *msg = NULL;
		struct spi_device  *spi = NULL;
		struct spi_transfer *t  = NULL;
		struct sun4i_spi *sspi = container_of(work, struct sun4i_spi, work);

		while (!list_empty(&sspi->queue)) {
			spin_lock_irq(&sspi->lock);

			// Get message from message queue.
			msg = container_of(sspi->queue.next, struct spi_message, queue);
			// Remove the message from the queue.
			list_del_init(&msg->queue);

			spin_unlock_irq(&sspi->lock);

			status = -1;
			spi = msg->spi;

			// Search for the SPI transfer in this message and deal with it.
			list_for_each_entry(t, &msg->transfers, transfer_list) {
				// Power-up the subsystem.
				pm_runtime_get_sync(sspi->master->dev.parent);

				// Do the transfer.
				mutex_lock(&sspi->master->io_mutex);
				status = sun4i_spi_work_do_red_brick(sspi->master, spi, t);
				mutex_unlock(&sspi->master->io_mutex);

				// Power-down the subsystem.
				pm_runtime_put_sync(sspi->master->dev.parent);

				if (status != 0)
					break; // Failed.

				// Accmulate the value in the message.
				msg->actual_length += t->len;
			}

			msg->status = status;

			if (status != 0)
				break;
		}

		/*
		 * Sleep a fixed amount of time before waking up the calling process.
		 * The idea is to have a sleep long enough that will cause a reschedule
		 * of the current process.
		 *
		 * This approach seems to improve system performance for single core CPUs.
		 *
		 * How long is good enough and what are the effects?
		 *
		 * Also checkout, https://www.kernel.org/doc/Documentation/timers/timers-howto.txt
		 */
		usleep_range(400, 500);

		// Wake up the caller.
		msg->complete(msg->context);
	}

	static int sun4i_spi_transfer_red_brick(struct spi_device *spi, struct spi_message *msg)
	{
		unsigned long flags = 0;
		struct sun4i_spi *sspi = spi_master_get_devdata(spi->master);
		msg->actual_length = 0;
		msg->status = -EINPROGRESS;
		sspi = spi_master_get_devdata(spi->master);

		spin_lock_irqsave(&sspi->lock, flags);

		// Enqueue SPI message.
		list_add_tail(&msg->queue, &sspi->queue);
		// Add work to the work queue.
		queue_work(sspi->workqueue, &sspi->work);

		spin_unlock_irqrestore(&sspi->lock, flags);

		return 0;
	}
#endif

static int sun4i_spi_transfer_one(struct spi_master *master,
                                  struct spi_device *spi,
                                  struct spi_transfer *tfr)
{
	u32 reg;
	int ret = 0;
	unsigned int start, end, tx_time, mclk_rate, div, timeout;

	unsigned int tx_len = 0;
	struct sun4i_spi *sspi = spi_master_get_devdata(master);

	// We don't support transfer larger than the FIFO.
	if (tfr->len > SUN4I_MAX_XFER_SIZE)
		return -EMSGSIZE;

	if (tfr->tx_buf && tfr->len >= SUN4I_MAX_XFER_SIZE)
		return -EMSGSIZE;

	reinit_completion(&sspi->done);
	sspi->tx_buf = tfr->tx_buf;
	sspi->rx_buf = tfr->rx_buf;
	sspi->len = tfr->len;

	// Clear pending interrupts.
	sun4i_spi_write(sspi, SUN4I_INT_STA_REG, ~0);

	reg = sun4i_spi_read(sspi, SUN4I_CTL_REG);

	// Reset FIFOs.
	sun4i_spi_write(sspi,
	                SUN4I_CTL_REG,
	                reg | SUN4I_CTL_RF_RST | SUN4I_CTL_TF_RST);

	/*
	 * Setup the transfer control register: Chip Select,
	 * polarities, etc.
	 */
	if (spi->mode & SPI_CPOL)
		reg |= SUN4I_CTL_CPOL;
	else
		reg &= ~SUN4I_CTL_CPOL;

	if (spi->mode & SPI_CPHA)
		reg |= SUN4I_CTL_CPHA;
	else
		reg &= ~SUN4I_CTL_CPHA;

	if (spi->mode & SPI_LSB_FIRST)
		reg |= SUN4I_CTL_LMTF;
	else
		reg &= ~SUN4I_CTL_LMTF;

	/*
	 * If it's a TX only transfer, we don't want to fill the RX
	 * FIFO with bogus data
	 */
	if (sspi->rx_buf)
		reg &= ~SUN4I_CTL_DHB;
	else
		reg |= SUN4I_CTL_DHB;

	sun4i_spi_write(sspi, SUN4I_CTL_REG, reg);

	// Ensure that we have a parent clock fast enough.
	mclk_rate = clk_get_rate(sspi->mclk);

	if (mclk_rate < (2 * tfr->speed_hz)) {
		clk_set_rate(sspi->mclk, 2 * tfr->speed_hz);
		mclk_rate = clk_get_rate(sspi->mclk);
	}

	/*
	 * Setup clock divider.
	 *
	 * We have two choices there. Either we can use the clock
	 * divide rate 1, which is calculated thanks to this formula:
	 * SPI_CLK = MOD_CLK / (2 ^ (cdr + 1))
	 * Or we can use CDR2, which is calculated with the formula:
	 * SPI_CLK = MOD_CLK / (2 * (cdr + 1))
	 * Wether we use the former or the latter is set through the
	 * DRS bit.
	 *
	 * First try CDR2, and if we can't reach the expected
	 * frequency, fall back to CDR1.
	 */
	div = mclk_rate / (2 * tfr->speed_hz);

	if (div <= (SUN4I_CLK_CTL_CDR2_MASK + 1)) {
		if (div > 0)
			div--;

		reg = SUN4I_CLK_CTL_CDR2(div) | SUN4I_CLK_CTL_DRS;
	} else {
		div = ilog2(mclk_rate) - ilog2(tfr->speed_hz);
		reg = SUN4I_CLK_CTL_CDR1(div);
	}

	sun4i_spi_write(sspi, SUN4I_CLK_CTL_REG, reg);

	// Setup the transfer now.
	if (sspi->tx_buf)
		tx_len = tfr->len;

	// Setup the counters.
	sun4i_spi_write(sspi, SUN4I_BURST_CNT_REG, SUN4I_BURST_CNT(tfr->len));
	sun4i_spi_write(sspi, SUN4I_XMIT_CNT_REG, SUN4I_XMIT_CNT(tx_len));

	/*
	 * Fill the TX FIFO
	 * Filling the FIFO fully causes timeout for some reason
	 * at least on spi2 on A10s
	 */
	sun4i_spi_fill_fifo(sspi, SUN4I_FIFO_DEPTH - 1);

	// Enable the interrupts.
	sun4i_spi_enable_interrupt(sspi,
	                           SUN4I_INT_CTL_TC | SUN4I_INT_CTL_RF_F34);

	// Only enable Tx FIFO interrupt if we really need it.
	if (tx_len > SUN4I_FIFO_DEPTH)
		sun4i_spi_enable_interrupt(sspi, SUN4I_INT_CTL_TF_E34);

	// Start the transfer.
	reg = sun4i_spi_read(sspi, SUN4I_CTL_REG);
	sun4i_spi_write(sspi, SUN4I_CTL_REG, reg | SUN4I_CTL_XCH);

	tx_time = max(tfr->len * 8 * 2 / (tfr->speed_hz / 1000), 100U);
	start = jiffies;
	timeout = wait_for_completion_timeout(&sspi->done,
	                                      msecs_to_jiffies(tx_time));
	end = jiffies;

	if (!timeout) {
		dev_warn(&master->dev,
		         "%s: timeout transferring %u bytes@%iHz for %i(%i)ms",
		         dev_name(&spi->dev),
		         tfr->len,
		         tfr->speed_hz,
		         jiffies_to_msecs(end - start),
		         tx_time);

		ret = -ETIMEDOUT;

		goto out;
	}

out:
	sun4i_spi_write(sspi, SUN4I_INT_CTL_REG, 0);

	return ret;
}

static irqreturn_t sun4i_spi_handler(int irq, void *dev_id)
{
	struct sun4i_spi *sspi = dev_id;
	u32 status = sun4i_spi_read(sspi, SUN4I_INT_STA_REG);

	#ifdef CONFIG_RED_BRICK
		sspi->result = -1;
	#endif

	/* Transfer complete */
	if (status & SUN4I_INT_CTL_TC) {
		sun4i_spi_write(sspi, SUN4I_INT_STA_REG, SUN4I_INT_CTL_TC);
		sun4i_spi_drain_fifo(sspi, SUN4I_FIFO_DEPTH);

		#ifdef CONFIG_RED_BRICK
			sspi->result = 0;
		#endif

		complete(&sspi->done);

		return IRQ_HANDLED;
	}

	/* Receive FIFO 3/4 full */
	if (status & SUN4I_INT_CTL_RF_F34) {
		sun4i_spi_drain_fifo(sspi, SUN4I_FIFO_DEPTH);
		/* Only clear the interrupt _after_ draining the FIFO */
		sun4i_spi_write(sspi, SUN4I_INT_STA_REG, SUN4I_INT_CTL_RF_F34);
		return IRQ_HANDLED;
	}

	/* Transmit FIFO 3/4 empty */
	if (status & SUN4I_INT_CTL_TF_E34) {
		sun4i_spi_fill_fifo(sspi, SUN4I_FIFO_DEPTH);

		if (!sspi->len)
			/* nothing left to transmit */
			sun4i_spi_disable_interrupt(sspi, SUN4I_INT_CTL_TF_E34);

		/* Only clear the interrupt _after_ re-seeding the FIFO */
		sun4i_spi_write(sspi, SUN4I_INT_STA_REG, SUN4I_INT_CTL_TF_E34);

		return IRQ_HANDLED;
	}

	return IRQ_NONE;
}

static int sun4i_spi_runtime_resume(struct device *dev)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct sun4i_spi *sspi = spi_master_get_devdata(master);
	int ret;

	ret = clk_prepare_enable(sspi->hclk);
	if (ret) {
		dev_err(dev, "Couldn't enable AHB clock\n");
		goto out;
	}

	ret = clk_prepare_enable(sspi->mclk);
	if (ret) {
		dev_err(dev, "Couldn't enable module clock\n");
		goto err;
	}

	sun4i_spi_write(sspi, SUN4I_CTL_REG,
			SUN4I_CTL_ENABLE | SUN4I_CTL_MASTER | SUN4I_CTL_TP);

	return 0;

err:
	clk_disable_unprepare(sspi->hclk);
out:
	return ret;
}

static int sun4i_spi_runtime_suspend(struct device *dev)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct sun4i_spi *sspi = spi_master_get_devdata(master);

	clk_disable_unprepare(sspi->mclk);
	clk_disable_unprepare(sspi->hclk);

	return 0;
}

static int sun4i_spi_probe(struct platform_device *pdev)
{
	struct spi_master *master;
	struct sun4i_spi *sspi;
	struct resource	*res;
	int ret = 0, irq;

	master = spi_alloc_master(&pdev->dev, sizeof(struct sun4i_spi));
	if (!master) {
		dev_err(&pdev->dev, "Unable to allocate SPI Master\n");
		return -ENOMEM;
	}

	platform_set_drvdata(pdev, master);
	sspi = spi_master_get_devdata(master);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);

	sspi->base_addr = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(sspi->base_addr)) {
		ret = PTR_ERR(sspi->base_addr);
		goto err_free_master;
	}

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_err(&pdev->dev, "No SPI IRQ specified\n");
		ret = -ENXIO;
		goto err_free_master;
	}

	ret = devm_request_irq(&pdev->dev, irq, sun4i_spi_handler, 0, "sun4i-spi", sspi);
	if (ret) {
		dev_err(&pdev->dev, "Cannot request IRQ\n");
		goto err_free_master;
	}

	sspi->master = master;
	master->min_speed_hz = 3 * 1000;
	master->set_cs = sun4i_spi_set_cs;
	master->max_speed_hz = 100 * 1000 * 1000;

	#ifdef CONFIG_RED_BRICK
		master->transfer_red_brick = sun4i_spi_transfer_red_brick;
	#endif

	master->transfer_one = sun4i_spi_transfer_one;
	master->num_chipselect = 4;
	master->mode_bits = SPI_CPOL | SPI_CPHA | SPI_CS_HIGH | SPI_LSB_FIRST;
	master->bits_per_word_mask = SPI_BPW_MASK(8);
	master->dev.of_node = pdev->dev.of_node;
	master->auto_runtime_pm = true;
	master->max_transfer_size = sun4i_spi_max_transfer_size;

	sspi->hclk = devm_clk_get(&pdev->dev, "ahb");
	if (IS_ERR(sspi->hclk)) {
		dev_err(&pdev->dev, "Unable to acquire AHB clock\n");
		ret = PTR_ERR(sspi->hclk);
		goto err_free_master;
	}

	sspi->mclk = devm_clk_get(&pdev->dev, "mod");
	if (IS_ERR(sspi->mclk)) {
		dev_err(&pdev->dev, "Unable to acquire module clock\n");
		ret = PTR_ERR(sspi->mclk);
		goto err_free_master;
	}

	init_completion(&sspi->done);

	/*
	 * This wake-up/shutdown pattern is to be able to have the
	 * device woken up, even if runtime_pm is disabled
	 */
	ret = sun4i_spi_runtime_resume(&pdev->dev);
	if (ret) {
		dev_err(&pdev->dev, "Couldn't resume the device\n");
		goto err_free_master;
	}

	pm_runtime_set_active(&pdev->dev);
	pm_runtime_enable(&pdev->dev);
	pm_runtime_idle(&pdev->dev);

	#ifdef CONFIG_RED_BRICK
		sspi->workqueue = create_singlethread_workqueue(dev_name(master->dev.parent));
		if (sspi->workqueue == NULL) {
			dev_err(&pdev->dev, "Unable to create work queue\n");
			ret = -ENOMEM;
			goto err_pm_disable;
		}

		spin_lock_init(&sspi->lock);
		INIT_WORK(&sspi->work, sun4i_spi_work_red_brick);
		INIT_LIST_HEAD(&sspi->queue);
	#endif

	ret = devm_spi_register_master(&pdev->dev, master);
	if (ret) {
		dev_err(&pdev->dev, "Can't register SPI master\n");
		goto err_pm_disable;
	}

	return 0;

err_pm_disable:
	pm_runtime_disable(&pdev->dev);
	sun4i_spi_runtime_suspend(&pdev->dev);
err_free_master:
	spi_master_put(master);
	return ret;
}

static int sun4i_spi_remove(struct platform_device *pdev)
{
	pm_runtime_disable(&pdev->dev);

	return 0;
}

static const struct of_device_id sun4i_spi_match[] = {
	{ .compatible = "allwinner,sun4i-a10-spi", },
	{}
};
MODULE_DEVICE_TABLE(of, sun4i_spi_match);

static const struct dev_pm_ops sun4i_spi_pm_ops = {
	.runtime_resume		= sun4i_spi_runtime_resume,
	.runtime_suspend	= sun4i_spi_runtime_suspend,
};

static struct platform_driver sun4i_spi_driver = {
	.probe	= sun4i_spi_probe,
	.remove	= sun4i_spi_remove,
	.driver	= {
		.name		= "sun4i-spi",
		.of_match_table	= sun4i_spi_match,
		.pm		= &sun4i_spi_pm_ops,
	},
};
module_platform_driver(sun4i_spi_driver);

MODULE_AUTHOR("Pan Nan <pannan@allwinnertech.com>");
MODULE_AUTHOR("Maxime Ripard <maxime.ripard@free-electrons.com>");
MODULE_AUTHOR("Ishraq Ibne Ashraf <ishraq@tinkerforge.com>");
MODULE_DESCRIPTION("Allwinner A1X/A20 SPI controller driver");
MODULE_LICENSE("GPL");
