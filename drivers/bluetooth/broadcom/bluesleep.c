/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * Copyright (c) 2014, BlackBerry Limited
 * Copyright (C) 2006-2007 - Motorola
 * Copyright (c) 2008-2010, The Linux Foundation. All rights reserved.
 * Copyright (c) 2013, LGE Inc.
 *
 * Date         Author           Comment
 * -----------  --------------   --------------------------------
 * 2006-Apr-28	Motorola	 The kernel module for running the Bluetooth(R)
 *                               Sleep-Mode Protocol from the Host side
 *  2006-Sep-08  Motorola        Added workqueue for handling sleep work.
 *  2007-Jan-24  Motorola        Added mbm_handle_ioi() call to ISR.
 *  2009-Aug-10  Motorola        Changed "add_timer" to "mod_timer" to solve
 *                               race when flurry of queued work comes in.
 */

#define pr_fmt(fmt)	"Bluetooth: %s: " fmt, __func__

#include <linux/module.h>	/* kernel module definitions */
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/notifier.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/platform_device.h>

#include <linux/irq.h>
#include <linux/ioport.h>
#include <linux/param.h>
#include <linux/bitops.h>
#include <linux/termios.h>
#include <linux/wakelock.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/serial_core.h>
#include <linux/platform_data/msm_serial_hs.h>

#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h> /* event notifications */
//#include "hci_uart.h"

#define BT_SLEEP_DBG
#ifndef BT_SLEEP_DBG
#define BT_DBG(fmt, arg...)
#endif
/*
 * Defines
 */

#define VERSION		"1.1"
#define PROC_DIR	"bluetooth/sleep"

#define POLARITY_LOW 0
#define POLARITY_HIGH 1

/* enable/disable wake-on-bluetooth */
#define BT_ENABLE_IRQ_WAKE 1

#define BT_BLUEDROID_SUPPORT 1

enum {
    DEBUG_USER_STATE = 1U << 0,
    DEBUG_SUSPEND = 1U << 1,
    DEBUG_BTWAKE = 1U << 2,
    DEBUG_VERBOSE = 1U << 3,
};

static int debug_mask = DEBUG_USER_STATE | DEBUG_SUSPEND | DEBUG_BTWAKE;
module_param_named(debug_mask, debug_mask, int, S_IRUGO | S_IWUSR | S_IWGRP);

struct bluesleep_info {
    unsigned host_wake;
    unsigned ext_wake;
    unsigned host_wake_irq;
    struct uart_port *uport;
    struct wake_lock wake_lock;
    int active_polarity;
    int has_ext_wake;
    int port_id;
    bool active;
};

/* work function */
static void bluesleep_sleep_work(struct work_struct *work);

/* work queue */
DECLARE_DELAYED_WORK(sleep_workqueue, bluesleep_sleep_work);

/* Macros for handling sleep work */
#define bluesleep_rx_busy()     schedule_delayed_work(&sleep_workqueue, 0)
#define bluesleep_tx_busy()     schedule_delayed_work(&sleep_workqueue, 0)
#define bluesleep_rx_idle()     schedule_delayed_work(&sleep_workqueue, 0)
#define bluesleep_tx_idle()     schedule_delayed_work(&sleep_workqueue, 0)

/* 5 second timeout */
#define TX_TIMER_INTERVAL  5

/* state variable names and bit positions */
#define BT_PROTO	0x01
#define BT_TXDATA	0x02
#define BT_ASLEEP	0x04
#define BT_EXT_WAKE	0x08
#define BT_SUSPEND	0x10

#if BT_BLUEDROID_SUPPORT
static bool has_lpm_enabled = false;
#else
/* global pointer to a single hci device. */
static struct hci_dev *bluesleep_hdev;
#endif

static struct platform_device *bluesleep_uart_dev;
static struct bluesleep_info *bsi;

/* module usage */
static atomic_t open_count = ATOMIC_INIT(1);

/* pinctrl variables */
#define PINCTRL_STATE_NO_PULL "host_wake_no_pull"
#define PINCTRL_STATE_PULL_DOWN "host_wake_pull_down"
static struct pinctrl *pinctrl;
static struct pinctrl_state *no_pull, *pull_down;

/*
 * Local function prototypes
 */
#if !BT_BLUEDROID_SUPPORT
static int bluesleep_hci_event(struct notifier_block *this,
        unsigned long event, void *data);
#endif
static int bluesleep_start(void);
static void bluesleep_stop(void);

/*
 * Global variables
 */

/** Global state flags */
static unsigned long flags;

/** Tasklet to respond to change in hostwake line */
static struct tasklet_struct hostwake_task;

/** Transmission timer */
static void bluesleep_tx_timer_expire(unsigned long data);
static DEFINE_TIMER(tx_timer, bluesleep_tx_timer_expire, 0, 0);

/** Lock for state transitions */
static spinlock_t rw_lock;

#if !BT_BLUEDROID_SUPPORT
/** Notifier block for HCI events */
struct notifier_block hci_event_nblock = {
    .notifier_call = bluesleep_hci_event,
};
#endif

struct proc_dir_entry *bluetooth_dir, *sleep_dir;

/*
 * Local functions
 */

static void hsuart_power(int on)
{
    if (test_bit(BT_SUSPEND, &flags))
        return;
    if (on) {
        msm_hs_request_clock_on(bsi->uport);
        msm_hs_set_mctrl(bsi->uport, TIOCM_RTS);
    } else {
        msm_hs_set_mctrl(bsi->uport, 0);
        msm_hs_request_clock_off(bsi->uport);
    }
}

/**
 * @return 1 if the Host can go to sleep, 0 otherwise.
 */
int bluesleep_can_sleep(void)
{
    if (debug_mask & DEBUG_SUSPEND)
        pr_info("host wake %d != %d, EXT_WAKE %d, !BT_TXDATA %d, uport %p\n",
                gpio_get_value(bsi->host_wake),
                bsi->active_polarity,
                test_bit(BT_EXT_WAKE, &flags),
                !test_bit(BT_TXDATA, &flags),
                bsi->uport);

    /* check if WAKE_BT_GPIO and BT_WAKE_GPIO are both deasserted.
     * ensure no Tx data is pending as well */
    return ((gpio_get_value(bsi->host_wake) != bsi->active_polarity) &&
            (test_bit(BT_EXT_WAKE, &flags)) &&
            (!test_bit(BT_TXDATA, &flags)) &&
            (bsi->uport != NULL));
}

void bluesleep_sleep_wakeup(void)
{
    if (test_bit(BT_ASLEEP, &flags) || test_bit(BT_EXT_WAKE, &flags)) {
        wake_lock(&bsi->wake_lock);
        /* Start the timer */
        mod_timer(&tx_timer, jiffies + (TX_TIMER_INTERVAL * HZ));
        if (debug_mask & DEBUG_BTWAKE)
            pr_info("BT WAKE: set to wake\n");
        if (bsi->has_ext_wake == 1) {
            if (debug_mask & DEBUG_BTWAKE)
                pr_info("BT WAKE: Assert\n");
            gpio_set_value(bsi->ext_wake, bsi->active_polarity ? 1 : 0); /* Assert External Wake */
        }
        clear_bit(BT_EXT_WAKE, &flags);
        if (test_bit(BT_ASLEEP, &flags)) {
            if (debug_mask & DEBUG_SUSPEND)
                pr_info("waking up...\n");
            clear_bit(BT_ASLEEP, &flags);
            /*Activating UART */
            hsuart_power(1);
        }
    }
}

/**
 * @brief@  main sleep work handling function which update the flags
 * and activate and deactivate UART ,check FIFO.
 */
static void bluesleep_sleep_work(struct work_struct *work)
{
    if ((debug_mask & DEBUG_SUSPEND) || (debug_mask & DEBUG_BTWAKE))
        pr_info("BT_WAKE set to ext_wake %d, host_wake %d, flags 0x%02x",
                gpio_get_value(bsi->ext_wake),
                gpio_get_value(bsi->host_wake),
                (unsigned int)flags);

    if (bluesleep_can_sleep()) {
        /* already asleep, this is an error case */
        if (test_bit(BT_ASLEEP, &flags)) {
            if (debug_mask & DEBUG_SUSPEND)
                pr_info("already asleep\n");
            return;
        }

        if (msm_hs_tx_empty(bsi->uport)) {
            if (debug_mask & DEBUG_SUSPEND)
                pr_info("going to sleep...\n");
            set_bit(BT_ASLEEP, &flags);
            /*Deactivating UART */
            hsuart_power(0);
            /* UART clk is not turned off immediately. Release
             * wakelock after 500 ms.
             */
            wake_lock_timeout(&bsi->wake_lock, HZ / 2);
        } else {

            mod_timer(&tx_timer, jiffies + (TX_TIMER_INTERVAL * HZ));
            return;
        }
    } else if (test_bit(BT_EXT_WAKE, &flags)
            && !test_bit(BT_ASLEEP, &flags)) {
        mod_timer(&tx_timer, jiffies + (TX_TIMER_INTERVAL * HZ));
        if (debug_mask & DEBUG_BTWAKE)
            pr_info("BT WAKE: set to wake\n");
        if (bsi->has_ext_wake == 1) {
            if (debug_mask & DEBUG_BTWAKE)
                pr_info("BT WAKE: Assert\n");
            gpio_set_value(bsi->ext_wake, bsi->active_polarity ? 1 : 0); /* Assert External Wake */
        }
        clear_bit(BT_EXT_WAKE, &flags);
    } else {
        bluesleep_sleep_wakeup();
    }
}

/**
 * A tasklet function that runs in tasklet context and reads the value
 * of the HOST_WAKE GPIO pin and further defer the work.
 * @param data Not used.
 */
static void bluesleep_hostwake_task(unsigned long data)
{
    if (debug_mask & DEBUG_SUSPEND)
        pr_info("hostwake line change %d\n", gpio_get_value(bsi->host_wake));

    spin_lock(&rw_lock);
    if ((gpio_get_value(bsi->host_wake) == bsi->active_polarity))
        bluesleep_rx_busy();
    else
        bluesleep_rx_idle();

    spin_unlock(&rw_lock);
}

/**
 * Handles proper timer action when outgoing data is delivered to the
 * HCI line discipline. Sets BT_TXDATA.
 */
static void bluesleep_outgoing_data(void)
{
    unsigned long irq_flags;

    spin_lock_irqsave(&rw_lock, irq_flags);

    /* log data passing by */
    set_bit(BT_TXDATA, &flags);

    spin_unlock_irqrestore(&rw_lock, irq_flags);

    /* if the tx side is sleeping... */
    if (test_bit(BT_EXT_WAKE, &flags)) {
        if (debug_mask & DEBUG_SUSPEND)
            pr_info("tx was sleeping\n");
        bluesleep_sleep_wakeup();
    }
}

#if BT_BLUEDROID_SUPPORT
static ssize_t bluesleep_read_proc_lpm(struct file *file, char *buf,
        size_t count, loff_t *data)
{
    char str[] = "Unsupported to read\n";

    if (count < sizeof(str)) {
        return -EINVAL;
    }

    if (copy_to_user( buf, str, sizeof(str) )) {
        return -EFAULT;
    }

    return sizeof(str);
}

static ssize_t bluesleep_write_proc_lpm(struct file *file, const char *buffer,
        size_t count, loff_t *data)
{
    char b;

    if (count < 1)
        return -EINVAL;

    if (copy_from_user(&b, buffer, 1))
        return -EFAULT;

    if (b == '0') {
        /* HCI_DEV_UNREG */
        bluesleep_stop();
        has_lpm_enabled = false;
        bsi->uport = NULL;
    } else {
        /* HCI_DEV_REG */
        if (!has_lpm_enabled) {
            has_lpm_enabled = true;
            bsi->uport = msm_hs_get_uart_port(bsi->port_id);
            /* if bluetooth started, start bluesleep*/
            bluesleep_start();
        }
    }

    return count;
}

static ssize_t bluesleep_read_proc_btwrite(struct file *file, char *buf,
        size_t count, loff_t *data)
{
    char str[] = "Unsupported to read\n";

    if (count < sizeof(str)) {
        return -EINVAL;
    }

    if (copy_to_user( buf, str, sizeof(str) )) {
        return -EFAULT;
    }

    return sizeof(str);
}

static ssize_t bluesleep_write_proc_btwrite(struct file *file, const char *buffer,
        size_t count, loff_t *data)
{
    char b;

    if (count < 1)
        return -EINVAL;

    if (copy_from_user(&b, buffer, 1))
        return -EFAULT;

    /* HCI_DEV_WRITE */
    if (b != '0')
        bluesleep_outgoing_data();

    return count;
}
#else
/**
 * Handles HCI device events.
 * @param this Not used.
 * @param event The event that occurred.
 * @param data The HCI device associated with the event.
 * @return <code>NOTIFY_DONE</code>.
 */
static int bluesleep_hci_event(struct notifier_block *this,
        unsigned long event, void *data)
{
    struct hci_dev *hdev = (struct hci_dev *) data;
    struct hci_uart *hu;
    struct uart_state *state;

    if (!hdev)
        return NOTIFY_DONE;

    switch (event) {
        case HCI_DEV_REG:
            if (!bluesleep_hdev) {
                bluesleep_hdev = hdev;
                hu  = (struct hci_uart *) hdev->driver_data;
                state = (struct uart_state *) hu->tty->driver_data;
                bsi->uport = state->uart_port;
                /* if bluetooth started, start bluesleep*/
                bluesleep_start();
            }
            break;
        case HCI_DEV_UNREG:
            bluesleep_stop();
            bluesleep_hdev = NULL;
            bsi->uport = NULL;
            /* if bluetooth stopped, stop bluesleep also */
            break;
        case HCI_DEV_WRITE:
            bluesleep_outgoing_data();
            break;
    }

    return NOTIFY_DONE;
}
#endif

/**
 * Handles transmission timer expiration.
 * @param data Not used.
 */
static void bluesleep_tx_timer_expire(unsigned long data)
{
    unsigned long irq_flags;

    if (debug_mask & DEBUG_VERBOSE)
        pr_info("Tx timer expired\n");

    spin_lock_irqsave(&rw_lock, irq_flags);

    /* were we silent during the last timeout? */
    if (!test_bit(BT_TXDATA, &flags)) {
        if (debug_mask & DEBUG_SUSPEND)
            pr_info("Tx has been idle\n");
        if (debug_mask & DEBUG_BTWAKE)
            pr_info("BT WAKE: set to sleep %d\n", bsi->has_ext_wake);
        if (bsi->has_ext_wake == 1) {
            if (debug_mask & DEBUG_BTWAKE)
                pr_info("BT WAKE: De-Assert\n");
            gpio_set_value(bsi->ext_wake, bsi->active_polarity ? 0 : 1); /* De-Assert External Wake */
        }
        set_bit(BT_EXT_WAKE, &flags);
        bluesleep_tx_idle();
    } else {
        if (debug_mask & DEBUG_SUSPEND)
            pr_info("Tx data during last period\n");
        mod_timer(&tx_timer, jiffies + (TX_TIMER_INTERVAL*HZ));
    }

    /* clear the incoming data flag */
    clear_bit(BT_TXDATA, &flags);

    spin_unlock_irqrestore(&rw_lock, irq_flags);
}

/**
 * Schedules a tasklet to run when receiving an interrupt on the
 * <code>HOST_WAKE</code> GPIO pin.
 * @param irq Not used.
 * @param dev_id Not used.
 */
static irqreturn_t bluesleep_hostwake_isr(int irq, void *dev_id)
{
    /* schedule a tasklet to handle the change in the host wake line */
    tasklet_schedule(&hostwake_task);
    return IRQ_HANDLED;
}

/**
 * Starts the Sleep-Mode Protocol on the Host.
 * @return On success, 0. On error, -1, and <code>errno</code> is set
 * appropriately.
 */
static int bluesleep_start(void)
{
    int retval;
    unsigned long irq_flags;

    spin_lock_irqsave(&rw_lock, irq_flags);

    if (test_bit(BT_PROTO, &flags)) {
        spin_unlock_irqrestore(&rw_lock, irq_flags);
        return 0;
    }

    spin_unlock_irqrestore(&rw_lock, irq_flags);

    if (!atomic_dec_and_test(&open_count)) {
        atomic_inc(&open_count);
        return -EBUSY;
    }

    /* start the timer */

    mod_timer(&tx_timer, jiffies + (TX_TIMER_INTERVAL*HZ));

    /* assert BT_WAKE */
    if (debug_mask & DEBUG_BTWAKE)
        pr_info("BT WAKE: set to wake\n");
    if (bsi->has_ext_wake == 1) {
        if (debug_mask & DEBUG_BTWAKE)
            pr_info("BT WAKE: Assert\n");
        gpio_set_value(bsi->ext_wake, bsi->active_polarity ? 1 : 0); /* Assert External Wake */
    }
    clear_bit(BT_EXT_WAKE, &flags);
#if BT_ENABLE_IRQ_WAKE
    retval = enable_irq_wake(bsi->host_wake_irq);
    if (retval < 0) {
        BT_ERR("Couldn't enable BT_HOST_WAKE as wakeup interrupt");
        goto fail;
    }
#endif
    set_bit(BT_PROTO, &flags);
    wake_lock(&bsi->wake_lock);
    return 0;
fail:
    del_timer(&tx_timer);
    atomic_inc(&open_count);

    return retval;
}

/**
 * Stops the Sleep-Mode Protocol on the Host.
 */
static void bluesleep_stop(void)
{
    unsigned long irq_flags;

    spin_lock_irqsave(&rw_lock, irq_flags);

    if (!test_bit(BT_PROTO, &flags)) {
        spin_unlock_irqrestore(&rw_lock, irq_flags);
        return;
    }

    /* assert BT_WAKE */
    if (debug_mask & DEBUG_BTWAKE)
        pr_info("BT WAKE: set to wake\n");
    if (bsi->has_ext_wake == 1) {
        if (debug_mask & DEBUG_BTWAKE)
            pr_info("BT WAKE: Assert\n");
        gpio_set_value(bsi->ext_wake, bsi->active_polarity ? 1 : 0); /* Assert External Wake */
    }
    clear_bit(BT_EXT_WAKE, &flags);
    del_timer(&tx_timer);
    clear_bit(BT_PROTO, &flags);

    if (test_bit(BT_ASLEEP, &flags)) {
        clear_bit(BT_ASLEEP, &flags);
        spin_unlock_irqrestore(&rw_lock, irq_flags);
        hsuart_power(1);
    } else {
        spin_unlock_irqrestore(&rw_lock, irq_flags);
    }

    atomic_inc(&open_count);

#if BT_ENABLE_IRQ_WAKE
    if (disable_irq_wake(bsi->host_wake_irq))
        BT_ERR("Couldn't disable hostwake IRQ wakeup mode");
#endif
    wake_lock_timeout(&bsi->wake_lock, HZ / 2);
}
/**
 * Read the <code>BT_WAKE</code> GPIO pin value via the proc interface.
 * When this function returns, <code>buf</code> will contain a 1 if the
 * pin is high, 0 otherwise.
 * @param file Not used.
 * @param buf Buffer for writing data.
 * @param count Not used.
 * @param data Not used.
 * @return The number of bytes written to buf.
 */
static ssize_t bluepower_read_proc_btwake(struct file *file, char *buf,
        size_t count, loff_t *data)
{
    char str[20];
    unsigned int len = snprintf(str, sizeof(str), "btwake:%u\n", test_bit(BT_EXT_WAKE, &flags));

    if ( len < 0 || len > sizeof(str) ) {
        BT_ERR("snprintf failed");
        return 0;
    }

    if (count < len+1) {
        return -EINVAL;
    }


    if (copy_to_user( buf, str, len+1 )) {
        return -EFAULT;
    }

    return len+1;
}

/**
 * Write the <code>BT_WAKE</code> GPIO pin value via the proc interface.
 * @param file Not used.
 * @param buffer The buffer to read from.
 * @param count The number of bytes to be written.
 * @param data Not used.
 * @return On success, the number of bytes written. On error, -1, and
 * <code>errno</code> is set appropriately.
 */
static ssize_t bluepower_write_proc_btwake(struct file *file, const char *buffer,
        size_t count, loff_t *data)
{
    char *buf;

    if (count < 1)
        return -EINVAL;

    buf = kmalloc(count, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    if (copy_from_user(buf, buffer, count)) {
        kfree(buf);
        return -EFAULT;
    }

    if (buf[0] == '0') {
        if (debug_mask & DEBUG_BTWAKE)
            pr_info("BT WAKE: set to wake\n");
        if (bsi->has_ext_wake == 1) {
            if (debug_mask & DEBUG_BTWAKE)
                pr_info("BT WAKE: Assert\n");
            gpio_set_value(bsi->ext_wake, bsi->active_polarity ? 1 : 0); /* Assert External Wake */
        }
        clear_bit(BT_EXT_WAKE, &flags);
    } else if (buf[0] == '1') {
        if (debug_mask & DEBUG_BTWAKE)
            pr_info("BT WAKE: set to sleep\n");
        if (bsi->has_ext_wake == 1) {
            if (debug_mask & DEBUG_BTWAKE)
                pr_info("BT WAKE: De-Assert\n");
            gpio_set_value(bsi->ext_wake, bsi->active_polarity ? 0 : 1); /* De-Assert External Wake */
        }
        set_bit(BT_EXT_WAKE, &flags);
    } else {
        kfree(buf);
        return -EINVAL;
    }

    kfree(buf);
    return count;
}

/**
 * Read the <code>BT_HOST_WAKE</code> GPIO pin value via the proc interface.
 * When this function returns, <code>page</code> will contain a 1 if the pin
 * is high, 0 otherwise.
 * @param file Not used.
 * @param buf Buffer for writing data.
 * @param count Not used.
 * @param data Not used.
 * @return The number of bytes written to buf.
 */
static ssize_t bluepower_read_proc_hostwake(struct file *file, char *buf,
        size_t count, loff_t *data)
{
    char str[20];
    unsigned int len = snprintf(str, sizeof(str), "hostwake:%u\n",
           gpio_get_value(bsi->host_wake));

    if( len < 0 || len > sizeof(str) ){
        BT_ERR("snprintf failed");
        return 0;
    }

    if (count < len+1) {
        return -EINVAL;
    }

    if (copy_to_user( buf, str, len+1 )) {
        return -EFAULT;
    }

    return len+1;
}

/**
 * Read the low-power status of the Host via the proc interface.
 * When this function returns, <code>page</code> contains a 1 if the Host
 * is asleep, 0 otherwise.
 * @param file Not used.
 * @param buf Buffer for writing data.
 * @param count Not used.
 * @param data Not used.
 * @return The number of bytes written to buf.
 */
static ssize_t bluesleep_read_proc_asleep(struct file *file, char *buf,
        size_t count, loff_t *data)
{
    char str[20];
    unsigned int len = snprintf(str, sizeof(str), "asleep:%u\n",
           test_bit(BT_ASLEEP, &flags) ? 1 : 0);

    if( len < 0 || len > sizeof(str) ){
        BT_ERR("snprintf failed");
        return 0;
    }

    if (count < len+1) {
        return -EINVAL;
    }

    if (copy_to_user( buf, str, len+1 )) {
        return -EFAULT;
    }

    return len+1;
}

/**
 * Read the low-power protocol being used by the Host via the proc interface.
 * When this function returns, <code>page</code> will contain a 1 if the Host
 * is using the Sleep Mode Protocol, 0 otherwise.
 * @param file Not used.
 * @param buf Buffer for writing data.
 * @param count Not used.
 * @param data Not used.
 * @return The number of bytes written to buf.
 */
static ssize_t bluesleep_read_proc_proto(struct file *file, char *buf,
        size_t count, loff_t *data)
{
    char str[20];
    unsigned int len = snprintf(str, sizeof(str), "proto:%u\n",
           test_bit(BT_PROTO, &flags) ? 1 : 0);

    if( len < 0 || len > sizeof(str) ){
        BT_ERR("snprintf failed");
        return 0;
    }

    if (count < len+1) {
        return -EINVAL;
    }

    if (copy_to_user( buf, str, len+1 ) ){
        return -EFAULT;
    }

    return len+1;
}

/**
 * Modify the low-power protocol used by the Host via the proc interface.
 * @param file Not used.
 * @param buffer The buffer to read from.
 * @param count The number of bytes to be written.
 * @param data Not used.
 * @return On success, the number of bytes written. On error, -1, and
 * <code>errno</code> is set appropriately.
 */
static ssize_t bluesleep_write_proc_proto(struct file *file, const char *buffer,
        size_t count, loff_t *data)
{
    char proto;

    if (count < 1)
        return -EINVAL;

    if (copy_from_user(&proto, buffer, 1))
        return -EFAULT;

    if (proto == '0')
        bluesleep_stop();
    else
        bluesleep_start();

    /* claim that we wrote everything */
    return count;
}

void bluesleep_setup_uart_port(struct platform_device *uart_dev)
{
    bluesleep_uart_dev = uart_dev;
}

static int bluesleep_populate_dt_pinfo(struct platform_device *pdev)
{
    struct device_node *np = pdev->dev.of_node;
    int tmp;

    tmp = of_get_named_gpio(np, "bt_host_wake", 0);
    if (tmp < 0) {
        BT_ERR("couldn't find host_wake gpio");
        return -ENODEV;
    }
    bsi->host_wake = tmp;

    tmp = of_get_named_gpio(np, "bt_ext_wake", 0);
    if (tmp < 0)
        bsi->has_ext_wake = 0;
    else
        bsi->has_ext_wake = 1;

    if (bsi->has_ext_wake)
        bsi->ext_wake = tmp;


    bsi->active_polarity = POLARITY_LOW;

    if ((!of_property_read_u32(np, "active_polarity", &tmp)) && (tmp > 0))
        bsi->active_polarity = POLARITY_HIGH;

    if ((!of_property_read_u32(np, "bt_port_id", &tmp)) && (tmp > 0))
        bsi->port_id = tmp;


    BT_INFO("bt_host_wake %d, bt_ext_wake %d, bt_port_id %d",
            bsi->host_wake,
            bsi->ext_wake,
            bsi->port_id);
    return 0;
}

static int bluesleep_populate_pinfo(struct platform_device *pdev)
{
    struct resource *res;

    res = platform_get_resource_byname(pdev, IORESOURCE_IO,
            "gpio_host_wake");
    if (!res) {
        BT_ERR("couldn't find host_wake gpio");
        return -ENODEV;
    }
    bsi->host_wake = res->start;

    res = platform_get_resource_byname(pdev, IORESOURCE_IO,
            "gpio_ext_wake");
    if (!res)
        bsi->has_ext_wake = 0;
    else
        bsi->has_ext_wake = 1;

    if (bsi->has_ext_wake)
        bsi->ext_wake = res->start;

    return 0;
}

static struct pinctrl_state *
gpio_get_state(const char *name)
{
    struct pinctrl_state *pin_state
        = pinctrl_lookup_state(pinctrl, name);

    if (IS_ERR_OR_NULL(pin_state)) {
        BT_ERR("note pinctrl_lookup_state(%s) err:%ld\n",
            name, PTR_ERR(pin_state));
    }

    return pin_state;
}

void bt_host_wake_set_pull_state(bool active){
    int ret;

    if( active ) {
        /* Remove pull on host wake */
        ret = pinctrl_select_state(pinctrl, no_pull);
    } else {
        /* Set pull down on host wake */
        ret = pinctrl_select_state(pinctrl, pull_down);
    }

    if (ret){
        BT_ERR("error: couldn't set pinctrl state");
    } else {
        BT_INFO("pinctrl state set: %s",
                active ? "no pull" : "pull down");
    }
}
EXPORT_SYMBOL(bt_host_wake_set_pull_state);

static int bluesleep_probe(struct platform_device *pdev)
{
    struct resource *res;
    int ret;

    bsi = kzalloc(sizeof(struct bluesleep_info), GFP_KERNEL);
    if (!bsi)
        return -ENOMEM;

    if (pdev->dev.of_node) {
        ret = bluesleep_populate_dt_pinfo(pdev);
        if (ret < 0) {
            BT_ERR("couldn't populate info from dt");
            return ret;
        }
    } else {
        ret = bluesleep_populate_pinfo(pdev);
        if (ret < 0) {
            BT_ERR("couldn't populate info");
            return ret;
        }
    }

    /* get pinctrl states for bt_host_wake */
    pinctrl = devm_pinctrl_get(&pdev->dev);
    if (IS_ERR_OR_NULL(pinctrl)) {
        BT_ERR("error devm_pinctrl_get() failed err:%ld\n",
        PTR_ERR(pinctrl));
        return PTR_ERR(pinctrl);
    }

    no_pull = gpio_get_state(PINCTRL_STATE_NO_PULL);

    pull_down = gpio_get_state(PINCTRL_STATE_PULL_DOWN);

    /* configure host_wake as input */
    ret = gpio_request_one(bsi->host_wake, GPIOF_IN, "bt_host_wake");
    if (ret < 0) {
        BT_ERR("failed to configure input"
                " direction for GPIO %d, error %d",
                bsi->host_wake, ret);
        goto free_bsi;
    }

    if (debug_mask & DEBUG_BTWAKE)
        pr_info("BT WAKE: set to wake\n");
    if (bsi->has_ext_wake) {
        /* configure ext_wake as output mode*/
        ret = gpio_request_one(bsi->ext_wake,
                GPIOF_OUT_INIT_LOW, "bt_ext_wake");
        if (ret < 0) {
            BT_ERR("failed to configure output"
                    " direction for GPIO %d, error %d",
                    bsi->ext_wake, ret);
            goto free_bt_host_wake;
        }
    }
    clear_bit(BT_EXT_WAKE, &flags);

    res = platform_get_resource_byname(pdev, IORESOURCE_IRQ,
            "host_wake");
    if (!res) {
        BT_ERR("couldn't find host_wake irq");
        ret = -ENODEV;
        goto free_bt_host_wake;
    }
    bsi->host_wake_irq = res->start;
    if (bsi->host_wake_irq < 0) {
        BT_ERR("couldn't find host_wake irq");
        ret = -ENODEV;
        goto free_bt_ext_wake;
    }


    wake_lock_init(&bsi->wake_lock, WAKE_LOCK_SUSPEND, "bluesleep");
    clear_bit(BT_SUSPEND, &flags);

    BT_INFO("host_wake_irq %d, polarity %d",
            bsi->host_wake_irq,
            bsi->active_polarity);

    ret = request_irq(bsi->host_wake_irq, bluesleep_hostwake_isr,
            IRQF_DISABLED | IRQF_TRIGGER_FALLING | IRQF_TRIGGER_RISING,
            "bluetooth hostwake", NULL);
    if (ret  < 0) {
        BT_ERR("Couldn't acquire BT_HOST_WAKE IRQ");
        goto free_bt_ext_wake;
    }

    return 0;

free_bt_ext_wake:
    gpio_free(bsi->ext_wake);
free_bt_host_wake:
    gpio_free(bsi->host_wake);
free_bsi:
    kfree(bsi);
    return ret;
}

static int bluesleep_remove(struct platform_device *pdev)
{
    free_irq(bsi->host_wake_irq, NULL);
    gpio_free(bsi->host_wake);
    gpio_free(bsi->ext_wake);
    wake_lock_destroy(&bsi->wake_lock);
    kfree(bsi);
    return 0;
}


static int bluesleep_resume(struct platform_device *pdev)
{
    if (test_bit(BT_SUSPEND, &flags)) {
        if (debug_mask & DEBUG_VERBOSE)
            pr_info("bluesleep resuming...\n");
        if ((bsi->uport != NULL) &&
                (gpio_get_value(bsi->host_wake) == bsi->active_polarity)) {
            if (debug_mask & DEBUG_SUSPEND)
                pr_info("bluesleep resume from BT event...\n");
            msm_hs_request_clock_on(bsi->uport);
            msm_hs_set_mctrl(bsi->uport, TIOCM_RTS);
        }
        clear_bit(BT_SUSPEND, &flags);
    }
    return 0;
}

static int bluesleep_suspend(struct platform_device *pdev, pm_message_t state)
{
    if (debug_mask & DEBUG_VERBOSE)
        pr_info("bluesleep suspending...\n");
    set_bit(BT_SUSPEND, &flags);
    return 0;
}

static struct of_device_id bluesleep_match_table[] = {
    { .compatible = "qcom,bluesleep" },
    {}
};

static struct platform_driver bluesleep_driver = {
    .probe = bluesleep_probe,
    .remove = bluesleep_remove,
    .suspend = bluesleep_suspend,
    .resume = bluesleep_resume,
    .driver = {
        .name = "bluesleep",
        .owner = THIS_MODULE,
        .of_match_table = bluesleep_match_table,
    },
};

static const struct file_operations proc_fops_btwake = {
    .owner = THIS_MODULE,
    .read  = bluepower_read_proc_btwake,
    .write = bluepower_write_proc_btwake,
};

static const struct file_operations proc_fops_hostwake = {
    .owner = THIS_MODULE,
    .read  = bluepower_read_proc_hostwake,
};

static const struct file_operations proc_fops_proto = {
    .owner = THIS_MODULE,
    .read  = bluesleep_read_proc_proto,
    .write = bluesleep_write_proc_proto,
};

static const struct file_operations proc_fops_asleep = {
    .owner = THIS_MODULE,
    .read  = bluesleep_read_proc_asleep,
};

static const struct file_operations proc_fops_lpm = {
    .owner = THIS_MODULE,
    .read  = bluesleep_read_proc_lpm,
    .write = bluesleep_write_proc_lpm,
};

static const struct file_operations proc_fops_btwrite = {
    .owner = THIS_MODULE,
    .read  = bluesleep_read_proc_btwrite,
    .write = bluesleep_write_proc_btwrite,
};

/**
 * Initializes the module.
 * @return On success, 0. On error, -1, and <code>errno</code> is set
 * appropriately.
 */
static int __init bluesleep_init(void)
{
    int retval;

    BT_INFO("BlueSleep Mode Driver Ver %s", VERSION);

    retval = platform_driver_register(&bluesleep_driver);
    if (retval)
        return retval;

    if (bsi == NULL)
        return 0;

#if !BT_BLUEDROID_SUPPORT
    bluesleep_hdev = NULL;
#endif

    bluetooth_dir = proc_mkdir("bluetooth", NULL);
    if (bluetooth_dir == NULL) {
        BT_ERR("Unable to create /proc/bluetooth directory");
        return -ENOMEM;
    }

    sleep_dir = proc_mkdir("sleep", bluetooth_dir);
    if (sleep_dir == NULL) {
        BT_ERR("Unable to create /proc/%s directory", PROC_DIR);
        return -ENOMEM;
    }

    /* Creating read/write "btwake" entry */
    if (proc_create("btwake", S_IRUGO | S_IWUSR | S_IWGRP, sleep_dir,
            &proc_fops_btwake) == NULL) {
        BT_ERR("Unable to create /proc/%s/btwake entry", PROC_DIR);
        retval = -ENOMEM;
        goto fail;
    }


    /* read only proc entries */
    if (proc_create("hostwake", S_IRUGO, sleep_dir,
            &proc_fops_hostwake) == NULL) {
        BT_ERR("Unable to create /proc/%s/hostwake entry", PROC_DIR);
        retval = -ENOMEM;
        goto fail;
    }

    /* read/write proc entries */
    if (proc_create("proto", S_IRUGO | S_IWUSR | S_IWGRP, sleep_dir,
            &proc_fops_proto) == NULL) {
        BT_ERR("Unable to create /proc/%s/proto entry", PROC_DIR);
        retval = -ENOMEM;
        goto fail;
    }

    /* read only proc entries */
    if (proc_create("asleep", S_IRUGO, sleep_dir,
            &proc_fops_asleep) == NULL) {
        BT_ERR("Unable to create /proc/%s/asleep entry", PROC_DIR);
        retval = -ENOMEM;
        goto fail;
    }

#if BT_BLUEDROID_SUPPORT
    /* read/write proc entries */
    if (proc_create("lpm", S_IRUGO | S_IWUSR | S_IWGRP, sleep_dir,
               &proc_fops_lpm) == NULL) {
        BT_ERR("Unable to create /proc/%s/lpm entry", PROC_DIR);
        retval = -ENOMEM;
        goto fail;
    }


    /* read/write proc entries */
    if (proc_create("btwrite", S_IRUGO | S_IWUSR | S_IWGRP, sleep_dir,
            &proc_fops_btwrite) == NULL) {
        BT_ERR("Unable to create /proc/%s/btwrite entry", PROC_DIR);
        retval = -ENOMEM;
        goto fail;
    }
#endif

    flags = 0; /* clear all status bits */

    /* Initialize spinlock. */
    spin_lock_init(&rw_lock);

    /* Initialize timer */
    init_timer(&tx_timer);
    tx_timer.function = bluesleep_tx_timer_expire;
    tx_timer.data = 0;

    /* initialize host wake tasklet */
    tasklet_init(&hostwake_task, bluesleep_hostwake_task, 0);

    /* assert bt wake */
    if (debug_mask & DEBUG_BTWAKE)
        pr_info("BT WAKE: set to wake\n");
    if (bsi->has_ext_wake == 1) {
        if (debug_mask & DEBUG_BTWAKE)
            pr_info("BT WAKE: Assert\n");
        gpio_set_value(bsi->ext_wake, bsi->active_polarity ? 1 : 0); /* Assert External Wake */
    }
    clear_bit(BT_EXT_WAKE, &flags);
#if !BT_BLUEDROID_SUPPORT
    hci_register_notifier(&hci_event_nblock);
#endif

    return 0;

fail:
#if BT_BLUEDROID_SUPPORT
    remove_proc_entry("btwrite", sleep_dir);
    remove_proc_entry("lpm", sleep_dir);
#endif
    remove_proc_entry("asleep", sleep_dir);
    remove_proc_entry("proto", sleep_dir);
    remove_proc_entry("hostwake", sleep_dir);
    remove_proc_entry("btwake", sleep_dir);
    remove_proc_entry("sleep", bluetooth_dir);
    remove_proc_entry("bluetooth", 0);
    return retval;
}

/**
 * Cleans up the module.
 */
static void __exit bluesleep_exit(void)
{
    if (bsi == NULL)
        return;

    /* assert bt wake */
    if (bsi->has_ext_wake == 1) {
        if (debug_mask & DEBUG_BTWAKE)
            pr_info("BT WAKE: Assert\n");
        gpio_set_value(bsi->ext_wake, bsi->active_polarity ? 1 : 0); /* Assert External Wake */
    }
    clear_bit(BT_EXT_WAKE, &flags);
    if (test_bit(BT_PROTO, &flags)) {
        if (disable_irq_wake(bsi->host_wake_irq))
            BT_ERR("Couldn't disable hostwake IRQ wakeup mode");
        free_irq(bsi->host_wake_irq, NULL);
        del_timer(&tx_timer);
        if (test_bit(BT_ASLEEP, &flags))
            hsuart_power(1);
    }

#if !BT_BLUEDROID_SUPPORT
    hci_unregister_notifier(&hci_event_nblock);
#endif
    platform_driver_unregister(&bluesleep_driver);

#if BT_BLUEDROID_SUPPORT
    remove_proc_entry("btwrite", sleep_dir);
    remove_proc_entry("lpm", sleep_dir);
#endif
    remove_proc_entry("asleep", sleep_dir);
    remove_proc_entry("proto", sleep_dir);
    remove_proc_entry("hostwake", sleep_dir);
    remove_proc_entry("btwake", sleep_dir);
    remove_proc_entry("sleep", bluetooth_dir);
    remove_proc_entry("bluetooth", 0);
}

module_init(bluesleep_init);
module_exit(bluesleep_exit);

MODULE_DESCRIPTION("Bluetooth Sleep Mode Driver ver %s " VERSION);
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif
