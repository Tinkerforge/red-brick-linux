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
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/reset.h>
#include <linux/of.h>
#include <linux/spi/spi.h>

#define SUN4I_FIFO_DEPTH		64
#define SUN6I_FIFO_DEPTH		128

#define SUN4I_COMPATIBLE "allwinner,sun4i-a10-spi"
#define SUN6I_COMPATIBLE "allwinner,sun6i-a31-spi"

#define SUNXI_TFR_CTL_CS(bitmap, cs)	(((cs) << \
					  (bitmap)[SUNXI_TFR_CTL_CS_SHIFT]) \
					 & (bitmap)[SUNXI_TFR_CTL_CS_MASK])

#define SUNXI_CNT_MASK			0xffffff
#define SUNXI_XMIT_CNT(cnt)		((cnt) & SUNXI_CNT_MASK)
#define SUNXI_BURST_CNT(cnt)		((cnt) & SUNXI_CNT_MASK)
#define SUNXI_BURST_CTL_CNT_STC(cnt)	((cnt) & SUNXI_CNT_MASK)

#define SUNXI_CLK_CTL_DRS		BIT(12)
#define SUNXI_CLK_CTL_CDR2_MASK		0xff
#define SUNXI_CLK_CTL_CDR2(div)		(((div) & SUNXI_CLK_CTL_CDR2_MASK) << 0)
#define SUNXI_CLK_CTL_CDR1_MASK		0xf
#define SUNXI_CLK_CTL_CDR1(div)		(((div) & SUNXI_CLK_CTL_CDR1_MASK) << 8)

#define SUNXI_FIFO_STA_RF_CNT_MASK	0x7f
#define SUNXI_FIFO_STA_RF_CNT_BITS	0
#define SUNXI_FIFO_STA_TF_CNT_MASK	0x7f
#define SUNXI_FIFO_STA_TF_CNT_BITS	16

static int wait_for_dma = 1;
module_param(wait_for_dma, int, 0644);
MODULE_PARM_DESC(wait_for_dma,
		 "When acquiring a DMA channel returns EDEFER return and let kernel defer spi master probe.\n"
		 "Non-DMA operation is used otherwise (defaults to wait for DMA driver to load).");

enum SPI_SUNXI_TYPE {
	SPI_SUN4I = 1,
	SPI_SUN6I,
};

enum SUNXI_REG_ENUM {
	SUNXI_RXDATA_REG,
	SUNXI_TXDATA_REG,
	SUNXI_TFR_CTL_REG,
	SUNXI_INT_CTL_REG,
	SUNXI_INT_STA_REG,
	SUNXI_DMA_CTL_REG,
	SUNXI_WAIT_REG,
	SUNXI_CLK_CTL_REG,
	SUNXI_BURST_CNT_REG,
	SUNXI_XMIT_CNT_REG,
	SUNXI_FIFO_STA_REG,
	SUNXI_VERSION_REG,
	SUNXI_GBL_CTL_REG,
	SUNXI_FIFO_CTL_REG,
	SUNXI_BURST_CTL_CNT_REG,
	SUNXI_NUM_REGS
};

static int sun4i_regmap[SUNXI_NUM_REGS] = {
/* SUNXI_RXDATA_REG */			0x00,
/* SUNXI_TXDATA_REG */			0x04,
/* SUNXI_TFR_CTL_REG */			0x08,
/* SUNXI_INT_CTL_REG */			0x0c,
/* SUNXI_INT_STA_REG */			0x10,
/* SUNXI_DMA_CTL_REG */			0x14,
/* SUNXI_WAIT_REG */			0x18,
/* SUNXI_CLK_CTL_REG */			0x1c,
/* SUNXI_BURST_CNT_REG */		0x20,
/* SUNXI_XMIT_CNT_REG */		0x24,
/* SUNXI_FIFO_STA_REG */		0x28,
-1, -1, -1, -1
};

static int sun6i_regmap[SUNXI_NUM_REGS] = {
/* SUNXI_RXDATA_REG */			0x300,
/* SUNXI_TXDATA_REG */			0x200,
/* SUNXI_TFR_CTL_REG */			0x08,
/* SUNXI_INT_CTL_REG */			0x10,
/* SUNXI_INT_STA_REG */			0x14,
/* SUNXI_DMA_CTL_REG */			-1,
/* SUNXI_WAIT_REG */			0x20,
/* SUNXI_CLK_CTL_REG */			0x24,
/* SUNXI_BURST_CNT_REG */		0x30,
/* SUNXI_XMIT_CNT_REG */		0x34,
/* SUNXI_FIFO_STA_REG */		0x1c,
/* SUNXI_VERSION_REG */			0x00,
/* SUNXI_GBL_CTL_REG */			0x04,
/* SUNXI_FIFO_CTL_REG */		0x18,
/* SUNXI_BURST_CTL_CNT_REG */		0x38,
};

enum SUNXI_BITMAP_ENUM {
	SUNXI_CTL_ENABLE,
	SUNXI_CTL_MASTER,
	SUNXI_TFR_CTL_CPHA,
	SUNXI_TFR_CTL_CPOL,
	SUNXI_TFR_CTL_CS_ACTIVE_LOW,
	SUNXI_CTL_DMA_DEDICATED,
	SUNXI_TFR_CTL_FBS,
	SUNXI_CTL_TF_RST,
	SUNXI_CTL_RF_RST,
	SUNXI_TFR_CTL_XCH,
	SUNXI_TFR_CTL_CS_MASK,
	SUNXI_TFR_CTL_CS_SHIFT,
	SUNXI_TFR_CTL_DHB,
	SUNXI_TFR_CTL_CS_MANUAL,
	SUNXI_TFR_CTL_CS_LEVEL,
	SUNXI_CTL_TP,
	SUNXI_INT_CTL_TC,
	SUNXI_CTL_DMA_RF_READY,
	SUNXI_CTL_DMA_TF_NOT_FULL,
	SUNXI_CTL_DMA_TF_HALF,
	SUNXI_BITMAP_SIZE
};

static int sun4i_bitmap[SUNXI_BITMAP_SIZE] = {
/* SUNXI_CTL_ENABLE */			BIT(0),
/* SUNXI_CTL_MASTER */			BIT(1),
/* SUNXI_TFR_CTL_CPHA */		BIT(2),
/* SUNXI_TFR_CTL_CPOL */		BIT(3),
/* SUNXI_TFR_CTL_CS_ACTIVE_LOW */	BIT(4),
/* SUNXI_CTL_DMA_DEDICATED */		BIT(5),
/* SUNXI_TFR_CTL_FBS */			BIT(6),
/* SUNXI_CTL_TF_RST */			BIT(8),
/* SUNXI_CTL_RF_RST */			BIT(9),
/* SUNXI_TFR_CTL_XCH */			BIT(10),
/* SUNXI_TFR_CTL_CS_MASK */		0x3000,
/* SUNXI_TFR_CTL_CS_SHIFT */		12,
/* SUNXI_TFR_CTL_DHB */			BIT(15),
/* SUNXI_TFR_CTL_CS_MANUAL */		BIT(16),
/* SUNXI_TFR_CTL_CS_LEVEL */		BIT(17),
/* SUNXI_CTL_TP */			BIT(18),
/* SUNXI_INT_CTL_TC */			BIT(16),
/* SUNXI_CTL_DMA_RF_READY */		BIT(0),
/* SUNXI_CTL_DMA_TF_NOT_FULL */		BIT(10),
/* SUNXI_CTL_DMA_TF_HALF */		BIT(9),
};

static int sun6i_bitmap[SUNXI_BITMAP_SIZE] = {
/* SUNXI_CTL_ENABLE */			BIT(0),
/* SUNXI_CTL_MASTER */			BIT(1),
/* SUNXI_TFR_CTL_CPHA */		BIT(0),
/* SUNXI_TFR_CTL_CPOL */		BIT(1),
/* SUNXI_TFR_CTL_CS_ACTIVE_LOW */	BIT(2),
/*
 * Bit 9 is listed as dedicated dma control for rx.
 * There is no dedicated dma control bit listed for tx and bit 25
 * on the logical position is listed as unused.
 */
/* SUNXI_CTL_DMA_DEDICATED */		BIT(9)|BIT(25),
/* SUNXI_TFR_CTL_FBS */			BIT(12),
/* SUNXI_CTL_TF_RST */			BIT(31),
/* SUNXI_CTL_RF_RST */			BIT(15),
/* SUNXI_TFR_CTL_XCH */			BIT(31),
/* SUNXI_TFR_CTL_CS_MASK */		0x30,
/* SUNXI_TFR_CTL_CS_SHIFT */		4,
/* SUNXI_TFR_CTL_DHB */			BIT(8),
/* SUNXI_TFR_CTL_CS_MANUAL */		BIT(6),
/* SUNXI_TFR_CTL_CS_LEVEL */		BIT(7),
/* SUNXI_CTL_TP */			BIT(7),
/* SUNXI_INT_CTL_TC */			BIT(12),
/*
 * On sun4i there are separate bits enabling request on different fifo levels.
 * On sun6i there is a level field and enable bit which enables request on that
 * FIFO level. Only one level is ever used so just pack the relevant bits as
 * one constant.
 */
/* SUNXI_CTL_DMA_RF_READY */		BIT(0)|BIT(8),
/* SUNXI_CTL_DMA_TF_NOT_FULL */		(0x7f << 16)|BIT(24),
/* SUNXI_CTL_DMA_TF_HALF */		BIT(23)|BIT(24),
};

struct sunxi_spi {
	struct spi_master	*master;
	void __iomem		*base_addr;
	struct clk		*hclk;
	struct clk		*mclk;
	struct reset_control	*rstc;
	int			(*regmap)[SUNXI_NUM_REGS];
	int			(*bitmap)[SUNXI_BITMAP_SIZE];
	int			fifo_depth;
	int			type;

	struct completion	done;

	const u8		*tx_buf;
	u8			*rx_buf;
	int			len;
};

static inline u32 sspi_reg(struct sunxi_spi *sspi, enum SUNXI_REG_ENUM name)
{
	BUG_ON((name >= SUNXI_NUM_REGS) || (name < 0) ||
	       (*sspi->regmap)[name] < 0);
	return (*sspi->regmap)[name];
}

static inline u32 sunxi_spi_read(struct sunxi_spi *sspi,
				 enum SUNXI_REG_ENUM name)
{
	return readl(sspi->base_addr + sspi_reg(sspi, name));
}

static inline void sunxi_spi_write(struct sunxi_spi *sspi,
				   enum SUNXI_REG_ENUM name, u32 value)
{
	writel(value, sspi->base_addr + sspi_reg(sspi, name));
}

static inline u32 sspi_bits(struct sunxi_spi *sspi,
			    enum SUNXI_BITMAP_ENUM name)
{
	BUG_ON((name >= SUNXI_BITMAP_SIZE) || (name < 0) ||
	       (*sspi->bitmap)[name] <= 0);
	return (*sspi->bitmap)[name];
}

static inline void sunxi_spi_set(struct sunxi_spi *sspi, u32 reg, u32 value)
{
	u32 orig = sunxi_spi_read(sspi, reg);

	sunxi_spi_write(sspi, reg, orig | value);
}

static inline void sunxi_spi_unset(struct sunxi_spi *sspi, u32 reg, u32 value)
{
	u32 orig = sunxi_spi_read(sspi, reg);

	sunxi_spi_write(sspi, reg, orig & ~value);
}

static inline void sunxi_spi_drain_fifo(struct sunxi_spi *sspi, int len)
{
	u32 reg, cnt;
	u8 byte;

	/* See how much data is available */
	reg = sunxi_spi_read(sspi, SUNXI_FIFO_STA_REG);
	reg &= SUNXI_FIFO_STA_RF_CNT_MASK;
	cnt = reg >> SUNXI_FIFO_STA_RF_CNT_BITS;

	if (len > cnt)
		len = cnt;

	while (len--) {
		byte = readb(sspi->base_addr +
			     sspi_reg(sspi, SUNXI_RXDATA_REG));
		if (sspi->rx_buf)
			*sspi->rx_buf++ = byte;
	}
}

static inline void sunxi_spi_fill_fifo(struct sunxi_spi *sspi, int len)
{
	u8 byte;

	if (len > sspi->len)
		len = sspi->len;

	while (len--) {
		byte = sspi->tx_buf ? *sspi->tx_buf++ : 0;
		writeb(byte, sspi->base_addr +
		       sspi_reg(sspi, SUNXI_TXDATA_REG));
		sspi->len--;
	}
}

static bool sunxi_spi_can_dma(struct spi_master *master,
			      struct spi_device *spi,
			      struct spi_transfer *tfr)
{
	struct sunxi_spi *sspi = spi_master_get_devdata(master);

	return tfr->len >= sspi->fifo_depth;
}

static void sunxi_spi_set_cs(struct spi_device *spi, bool enable)
{
	struct sunxi_spi *sspi = spi_master_get_devdata(spi->master);
	u32 reg;

	reg = sunxi_spi_read(sspi, SUNXI_TFR_CTL_REG);
	reg &= ~sspi_bits(sspi, SUNXI_TFR_CTL_CS_MASK);
	reg |= SUNXI_TFR_CTL_CS(*sspi->bitmap, spi->chip_select);

	/* We want to control the chip select manually */
	reg |= sspi_bits(sspi, SUNXI_TFR_CTL_CS_MANUAL);

	if (enable)
		reg |= sspi_bits(sspi, SUNXI_TFR_CTL_CS_LEVEL);
	else
		reg &= ~sspi_bits(sspi, SUNXI_TFR_CTL_CS_LEVEL);

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
		reg &= ~sspi_bits(sspi, SUNXI_TFR_CTL_CS_ACTIVE_LOW);
	else
		reg |= sspi_bits(sspi, SUNXI_TFR_CTL_CS_ACTIVE_LOW);

	sunxi_spi_write(sspi, SUNXI_TFR_CTL_REG, reg);
}

static size_t sunxi_spi_max_transfer_size(struct spi_device *spi)
{
	struct spi_master *master = spi->master;
	struct sunxi_spi *sspi = spi_master_get_devdata(master);

	if (master->can_dma)
		return SUNXI_CNT_MASK;
	return sspi->fifo_depth - 1;
}

static int sunxi_spi_transfer_one(struct spi_master *master,
				  struct spi_device *spi,
				  struct spi_transfer *tfr)
{
	struct sunxi_spi *sspi = spi_master_get_devdata(master);
	struct dma_async_tx_descriptor *desc_tx = NULL, *desc_rx = NULL;
	unsigned int mclk_rate, div, timeout;
	unsigned int start, end, tx_time;
	unsigned int tx_len = 0;
	int ret = 0;
	u32 reg, trigger = 0;

	if (!master->can_dma) {
		/* We don't support transfer larger than the FIFO */
		if (tfr->len > sspi->fifo_depth)
			return -EMSGSIZE;
		/*
		 * Filling the FIFO fully causes timeout for some reason
		 * at least on spi2 on A10s
		 */
		if ((sspi->type == SPI_SUN4I) &&
		    tfr->tx_buf && tfr->len >= sspi->fifo_depth)
			return -EMSGSIZE;
	}

	if (tfr->len > SUNXI_CNT_MASK)
		return -EMSGSIZE;

	reinit_completion(&sspi->done);
	sspi->tx_buf = tfr->tx_buf;
	sspi->rx_buf = tfr->rx_buf;
	sspi->len = tfr->len;

	/* Clear pending interrupts */
	sunxi_spi_write(sspi, SUNXI_INT_STA_REG, ~0);

	reg = sunxi_spi_read(sspi, SUNXI_TFR_CTL_REG);

	/* Reset FIFOs */
	if (sspi->type == SPI_SUN4I)
		sunxi_spi_write(sspi, SUNXI_TFR_CTL_REG,
				reg | sspi_bits(sspi, SUNXI_CTL_RF_RST) |
				sspi_bits(sspi, SUNXI_CTL_TF_RST));
	else
		sunxi_spi_write(sspi, SUNXI_FIFO_CTL_REG,
				sspi_bits(sspi, SUNXI_CTL_RF_RST) |
				sspi_bits(sspi, SUNXI_CTL_TF_RST));

	/*
	 * Setup the transfer control register: Chip Select,
	 * polarities, etc.
	 */
	if (spi->mode & SPI_CPOL)
		reg |= sspi_bits(sspi, SUNXI_TFR_CTL_CPOL);
	else
		reg &= ~sspi_bits(sspi, SUNXI_TFR_CTL_CPOL);

	if (spi->mode & SPI_CPHA)
		reg |= sspi_bits(sspi, SUNXI_TFR_CTL_CPHA);
	else
		reg &= ~sspi_bits(sspi, SUNXI_TFR_CTL_CPHA);

	if (spi->mode & SPI_LSB_FIRST)
		reg |= sspi_bits(sspi, SUNXI_TFR_CTL_FBS);
	else
		reg &= ~sspi_bits(sspi, SUNXI_TFR_CTL_FBS);

	/*
	 * If it's a TX only transfer, we don't want to fill the RX
	 * FIFO with bogus data
	 */
	if (sspi->rx_buf)
		reg &= ~sspi_bits(sspi, SUNXI_TFR_CTL_DHB);
	else
		reg |= sspi_bits(sspi, SUNXI_TFR_CTL_DHB);

	sunxi_spi_write(sspi, SUNXI_TFR_CTL_REG, reg);

	/* Ensure that we have a parent clock fast enough */
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
	 * SPI_CLK = MOD_CLK / (2 ^ cdr)
	 * Or we can use CDR2, which is calculated with the formula:
	 * SPI_CLK = MOD_CLK / (2 * (cdr + 1))
	 * Wether we use the former or the latter is set through the
	 * DRS bit.
	 *
	 * First try CDR2, and if we can't reach the expected
	 * frequency, fall back to CDR1.
	 */
	div = mclk_rate / (2 * tfr->speed_hz);
	if (div <= (SUNXI_CLK_CTL_CDR2_MASK + 1)) {
		if (div > 0)
			div--;

		reg = SUNXI_CLK_CTL_CDR2(div) | SUNXI_CLK_CTL_DRS;
	} else {
		div = ilog2(mclk_rate) - ilog2(tfr->speed_hz);
		reg = SUNXI_CLK_CTL_CDR1(div);
	}

	sunxi_spi_write(sspi, SUNXI_CLK_CTL_REG, reg);

	/* Setup the transfer now... */
	if (sspi->tx_buf)
		tx_len = tfr->len;

	/* Setup the counters */
	sunxi_spi_write(sspi, SUNXI_BURST_CNT_REG, SUNXI_BURST_CNT(tfr->len));
	sunxi_spi_write(sspi, SUNXI_XMIT_CNT_REG, SUNXI_XMIT_CNT(tx_len));
	if (sspi->type == SPI_SUN6I)
		sunxi_spi_write(sspi, SUNXI_BURST_CTL_CNT_REG,
				SUNXI_BURST_CTL_CNT_STC(tx_len));

	/* Setup transfer buffers */
	if (sunxi_spi_can_dma(master, spi, tfr)) {
		dev_dbg(&sspi->master->dev, "Using DMA mode for transfer\n");

		if (sspi->tx_buf) {
			desc_tx = dmaengine_prep_slave_sg(master->dma_tx,
					tfr->tx_sg.sgl, tfr->tx_sg.nents,
					DMA_TO_DEVICE,
					DMA_PREP_INTERRUPT | DMA_CTRL_ACK);
			if (!desc_tx) {
				dev_err(&sspi->master->dev,
					"Couldn't prepare dma slave\n");
				ret = -EIO;
				goto out;
			}

			if (sspi->type == SPI_SUN4I)
				trigger |= sspi_bits(sspi, SUNXI_CTL_DMA_TF_NOT_FULL);
			else
				trigger |= sspi_bits(sspi, SUNXI_CTL_DMA_TF_HALF);

			dmaengine_submit(desc_tx);
			dma_async_issue_pending(master->dma_tx);
		}

		if (sspi->rx_buf) {
			desc_rx = dmaengine_prep_slave_sg(master->dma_rx,
					tfr->rx_sg.sgl, tfr->rx_sg.nents,
					DMA_FROM_DEVICE,
					DMA_PREP_INTERRUPT | DMA_CTRL_ACK);
			if (!desc_rx) {
				dev_err(&sspi->master->dev,
					"Couldn't prepare dma slave\n");
				ret = -EIO;
				goto out;
			}

			trigger |= sspi_bits(sspi, SUNXI_CTL_DMA_RF_READY);

			dmaengine_submit(desc_rx);
			dma_async_issue_pending(master->dma_rx);
		}

		/* Enable Dedicated DMA requests */
		if (sspi->type == SPI_SUN4I) {
			sunxi_spi_set(sspi, SUNXI_TFR_CTL_REG,
				      sspi_bits(sspi, SUNXI_CTL_DMA_DEDICATED));
			sunxi_spi_write(sspi, SUNXI_DMA_CTL_REG, trigger);
		} else {
			trigger |= sspi_bits(sspi, SUNXI_CTL_DMA_DEDICATED);
			sunxi_spi_write(sspi, SUNXI_FIFO_CTL_REG, trigger);
		}
	} else {
		dev_dbg(&sspi->master->dev, "Using PIO mode for transfer\n");

		/* Disable DMA requests */
		if (sspi->type == SPI_SUN4I) {
			sunxi_spi_unset(sspi, SUNXI_TFR_CTL_REG,
					sspi_bits(sspi, SUNXI_CTL_DMA_DEDICATED));
			sunxi_spi_write(sspi, SUNXI_DMA_CTL_REG, 0);
		} else {
			sunxi_spi_write(sspi, SUNXI_FIFO_CTL_REG, 0);
		}

		/* Fill the TX FIFO */
		sunxi_spi_fill_fifo(sspi, sspi->fifo_depth);
	}

	/* Enable the interrupts */
	sunxi_spi_write(sspi, SUNXI_INT_CTL_REG,
			sspi_bits(sspi, SUNXI_INT_CTL_TC));

	/* Start the transfer */
	sunxi_spi_set(sspi, SUNXI_TFR_CTL_REG,
			    sspi_bits(sspi, SUNXI_TFR_CTL_XCH));

	tx_time = max(tfr->len * 8 * 2 / (tfr->speed_hz / 1000), 100U);
	start = jiffies;
	timeout = wait_for_completion_timeout(&sspi->done,
					      msecs_to_jiffies(tx_time));
	end = jiffies;
	if (!timeout) {
		dev_warn(&master->dev,
			 "%s: timeout transferring %u bytes@%iHz for %i(%i)ms",
			 dev_name(&spi->dev), tfr->len, tfr->speed_hz,
			 jiffies_to_msecs(end - start), tx_time);
		ret = -ETIMEDOUT;
		goto out;
	}

out:
	if (ret < 0 && sunxi_spi_can_dma(master, spi, tfr)) {
		dev_dbg(&master->dev, "DMA channel teardown");
		if (sspi->tx_buf)
			dmaengine_terminate_sync(master->dma_tx);
		if (sspi->rx_buf)
			dmaengine_terminate_sync(master->dma_rx);
	}

	/*
	 * By this time either the transfer has ended and we have data in the
	 * FIFO buffer from a PIO RX transfer or the buffer is empty
	 * or something has failed.
	 * Empty the buffer either way to avoid leaving garbage around.
	 */
	sunxi_spi_drain_fifo(sspi, sspi->fifo_depth);

	sunxi_spi_write(sspi, SUNXI_INT_CTL_REG, 0);

	return ret;
}

static irqreturn_t sunxi_spi_handler(int irq, void *dev_id)
{
	struct sunxi_spi *sspi = dev_id;
	u32 status = sunxi_spi_read(sspi, SUNXI_INT_STA_REG);

	/* Transfer complete */
	if (status & sspi_bits(sspi, SUNXI_INT_CTL_TC)) {
		sunxi_spi_write(sspi, SUNXI_INT_STA_REG,
				sspi_bits(sspi, SUNXI_INT_CTL_TC));
		complete(&sspi->done);
		return IRQ_HANDLED;
	}

	return IRQ_NONE;
}

static int sunxi_spi_runtime_resume(struct device *dev)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct sunxi_spi *sspi = spi_master_get_devdata(master);
	int ret, reg;

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

	if (sspi->rstc) {
		ret = reset_control_deassert(sspi->rstc);
		if (ret) {
			dev_err(dev, "Couldn't deassert the device from reset\n");
			goto err2;
		}
	}

	if (sspi->type == SPI_SUN4I)
		reg = SUNXI_TFR_CTL_REG;
	else
		reg = SUNXI_GBL_CTL_REG;
	sunxi_spi_write(sspi, reg,
			sspi_bits(sspi, SUNXI_CTL_ENABLE) |
			sspi_bits(sspi, SUNXI_CTL_MASTER) |
			sspi_bits(sspi, SUNXI_CTL_TP));

	return 0;

err2:
	clk_disable_unprepare(sspi->mclk);
err:
	clk_disable_unprepare(sspi->hclk);
out:
	return ret;
}

static int sunxi_spi_runtime_suspend(struct device *dev)
{
	struct spi_master *master = dev_get_drvdata(dev);
	struct sunxi_spi *sspi = spi_master_get_devdata(master);

	if (sspi->rstc)
		reset_control_assert(sspi->rstc);
	clk_disable_unprepare(sspi->mclk);
	clk_disable_unprepare(sspi->hclk);

	return 0;
}

static int sunxi_spi_probe(struct platform_device *pdev)
{
	struct dma_slave_config dma_sconfig;
	struct spi_master *master;
	struct sunxi_spi *sspi;
	struct resource	*res;
	int ret = 0, irq;
	const char *desc = NULL;
	u32 version = 0;

	if (!pdev->dev.of_node) {
		dev_err(&pdev->dev, "No devicetree data.");
		return -EINVAL;
	}

	master = spi_alloc_master(&pdev->dev, sizeof(struct sunxi_spi));
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
		dev_err(&pdev->dev, "No spi IRQ specified\n");
		ret = -ENXIO;
		goto err_free_master;
	}

	ret = devm_request_irq(&pdev->dev, irq, sunxi_spi_handler,
			       0, "sunxi-spi", sspi);
	if (ret) {
		dev_err(&pdev->dev, "Cannot request IRQ\n");
		goto err_free_master;
	}

	sspi->master = master;
	if (of_device_is_compatible(pdev->dev.of_node, SUN4I_COMPATIBLE)) {
		sspi->fifo_depth = SUN4I_FIFO_DEPTH;
		sspi->type = SPI_SUN4I;
		sspi->regmap = &sun4i_regmap;
		sspi->bitmap = &sun4i_bitmap;
	} else if (of_device_is_compatible(pdev->dev.of_node,
					   SUN6I_COMPATIBLE)) {
		sspi->fifo_depth = SUN6I_FIFO_DEPTH;
		sspi->type = SPI_SUN6I;
		sspi->regmap = &sun6i_regmap;
		sspi->bitmap = &sun6i_bitmap;
	} else {
		const char *str = NULL;
		int i = 1;

		of_property_read_string(pdev->dev.of_node, "compatible", &str);
		dev_err(&pdev->dev, "Unknown device compatible %s", str);
		/* is there no sane way to print a string array property ? */
		if (of_property_count_strings(pdev->dev.of_node, "compatible")
		    > 1) {
			while (!of_property_read_string_index(pdev->dev.of_node,
							      "compatible", i,
							      &str)) {
				pr_err(", %s", str);
				i++;
			}
		}
		ret = -EINVAL;
		goto err_free_master;
	}

	master->max_speed_hz = 100 * 1000 * 1000;
	master->min_speed_hz =          3 * 1000;
	master->set_cs = sunxi_spi_set_cs;
	master->transfer_one = sunxi_spi_transfer_one;
	master->num_chipselect = 4;
	master->mode_bits = SPI_CPOL | SPI_CPHA | SPI_CS_HIGH | SPI_LSB_FIRST;
	master->bits_per_word_mask = SPI_BPW_MASK(8);
	master->dev.of_node = pdev->dev.of_node;
	master->auto_runtime_pm = true;
	master->max_transfer_size = sunxi_spi_max_transfer_size;

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

	if (sspi->type == SPI_SUN6I) {
		sspi->rstc = devm_reset_control_get(&pdev->dev, NULL);
		if (IS_ERR(sspi->rstc)) {
			dev_err(&pdev->dev, "Couldn't get reset controller\n");
			ret = PTR_ERR(sspi->rstc);
			goto err_free_master;
		}
	}

	master->dma_tx = dma_request_slave_channel_reason(&pdev->dev, "tx");
	if (IS_ERR(master->dma_tx)) {
		dev_err(&pdev->dev, "Unable to acquire DMA channel TX\n");
		ret = PTR_ERR(master->dma_tx);
		goto err_dma_chan;
	}

	dma_sconfig.direction = DMA_MEM_TO_DEV;
	dma_sconfig.src_addr_width = DMA_SLAVE_BUSWIDTH_1_BYTE;
	dma_sconfig.dst_addr_width = DMA_SLAVE_BUSWIDTH_1_BYTE;
	dma_sconfig.dst_addr = res->start + sspi_reg(sspi, SUNXI_TXDATA_REG);
	dma_sconfig.src_maxburst = 1;
	dma_sconfig.dst_maxburst = 1;

	ret = dmaengine_slave_config(master->dma_tx, &dma_sconfig);
	if (ret) {
		dev_err(&pdev->dev, "Unable to configure TX DMA slave\n");
		goto err_tx_dma_release;
	}

	master->dma_rx = dma_request_slave_channel_reason(&pdev->dev, "rx");
	if (IS_ERR(master->dma_rx)) {
		dev_err(&pdev->dev, "Unable to acquire DMA channel RX\n");
		ret = PTR_ERR(master->dma_rx);
		goto err_tx_dma_release;
	}

	dma_sconfig.direction = DMA_DEV_TO_MEM;
	dma_sconfig.src_addr_width = DMA_SLAVE_BUSWIDTH_1_BYTE;
	dma_sconfig.dst_addr_width = DMA_SLAVE_BUSWIDTH_1_BYTE;
	dma_sconfig.src_addr = res->start + sspi_reg(sspi, SUNXI_RXDATA_REG);
	dma_sconfig.src_maxburst = 1;
	dma_sconfig.dst_maxburst = 1;

	ret = dmaengine_slave_config(master->dma_rx, &dma_sconfig);
	if (ret) {
		dev_err(&pdev->dev, "Unable to configure RX DMA slave\n");
		goto err_rx_dma_release;
	}

	/*
	 * This is a bit dodgy. If you set can_dma then map_msg in spi.c
	 * apparently dereferences your dma channels if non-NULL even if your
	 * can_dma never returns true (and crashes if the channel is an error
	 * pointer). So just don't set can_dma unless both channels are valid.
	 */
	master->can_dma = sunxi_spi_can_dma;
wakeup:
	/*
	 * This wake-up/shutdown pattern is to be able to have the
	 * device woken up, even if runtime_pm is disabled
	 */
	ret = sunxi_spi_runtime_resume(&pdev->dev);
	if (ret) {
		dev_err(&pdev->dev, "Couldn't resume the device\n");
		goto err_free_master;
	}

	pm_runtime_set_active(&pdev->dev);
	pm_runtime_enable(&pdev->dev);
	pm_runtime_idle(&pdev->dev);

	ret = devm_spi_register_master(&pdev->dev, master);
	if (ret) {
		dev_err(&pdev->dev, "cannot register SPI master\n");
		goto err_pm_disable;
	}

	switch (sspi->type) {
	case SPI_SUN4I:
		desc = "sun4i";
		break;
	case SPI_SUN6I:
		desc = "sun6i";
		break;
	}
	dev_notice(&pdev->dev,
		   "%s SPI controller at 0x%08x, IRQ %i, %i bytes FIFO",
		   desc, res->start, irq, sspi->fifo_depth);
	if (sspi->type != SPI_SUN4I) {
		version = sunxi_spi_read(sspi, SUNXI_VERSION_REG);
		dev_notice(&pdev->dev, "HW revision %x.%x",
			   version >> 16,
			   version && 0xff);
	}

	return 0;

err_rx_dma_release:
	dma_release_channel(master->dma_rx);
err_tx_dma_release:
	dma_release_channel(master->dma_tx);
err_dma_chan:
	master->dma_tx = NULL;
	master->dma_rx = NULL;
	if ((ret == -EPROBE_DEFER) && wait_for_dma)
		goto err_free_master;
	goto wakeup;

err_pm_disable:
	pm_runtime_disable(&pdev->dev);
	sunxi_spi_runtime_suspend(&pdev->dev);
err_free_master:
	if (master->can_dma) {
		dma_release_channel(master->dma_rx);
		dma_release_channel(master->dma_tx);
	}
	spi_master_put(master);
	return ret;
}

static int sunxi_spi_remove(struct platform_device *pdev)
{
	struct spi_master *master = platform_get_drvdata(pdev);

	pm_runtime_disable(&pdev->dev);

	if (master->can_dma) {
		dma_release_channel(master->dma_rx);
		dma_release_channel(master->dma_tx);
	}

	return 0;
}

static const struct of_device_id sunxi_spi_match[] = {
	{ .compatible = SUN4I_COMPATIBLE, },
	{ .compatible = SUN6I_COMPATIBLE, },
	{}
};
MODULE_DEVICE_TABLE(of, sunxi_spi_match);

static const struct dev_pm_ops sunxi_spi_pm_ops = {
	.runtime_resume		= sunxi_spi_runtime_resume,
	.runtime_suspend	= sunxi_spi_runtime_suspend,
};

static struct platform_driver sunxi_spi_driver = {
	.probe	= sunxi_spi_probe,
	.remove	= sunxi_spi_remove,
	.driver	= {
		.name		= "sunxi-spi",
		.of_match_table	= sunxi_spi_match,
		.pm		= &sunxi_spi_pm_ops,
	},
};
module_platform_driver(sunxi_spi_driver);

MODULE_AUTHOR("Pan Nan <pannan@allwinnertech.com>");
MODULE_AUTHOR("Maxime Ripard <maxime.ripard@free-electrons.com>");
MODULE_DESCRIPTION("Allwinner A1X/A2X/A31 SPI controller driver");
MODULE_AUTHOR("Ishraq Ibne Ashraf <ishraq@tinkerforge.com>");
MODULE_LICENSE("GPL");
