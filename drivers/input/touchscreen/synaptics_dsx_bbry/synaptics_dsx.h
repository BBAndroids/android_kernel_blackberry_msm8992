/*
 * Synaptics RMI4 touchscreen driver
 *
 * Copyright (C) 2014 BlackBerry Limited
 * Copyright (C) 2012 Synaptics Incorporated
 *
 * Copyright (C) 2012 Alexandra Chin <alexandra.chin@tw.synaptics.com>
 * Copyright (C) 2012 Scott Lin <scott.lin@tw.synaptics.com>
 * Copyright (c) 2013, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _SYNAPTICS_DSX_H_
#define _SYNAPTICS_DSX_H_

#define PLATFORM_DRIVER_NAME "synaptics_dsx"
#define I2C_DRIVER_NAME "synaptics_dsx_i2c"
#define SPI_DRIVER_NAME "synaptics_dsx_spi"
/*
 * struct synaptics_dsx_cap_button_map - 0d button map
 * @nbuttons: number of 0d buttons
 * @map: pointer to array of button types
 */
struct synaptics_dsx_cap_button_map {
	unsigned char nbuttons;
	unsigned char *map;
};

/*
 * struct synaptics_dsx_board_data - dsx board data
 * @x_flip: x flip flag
 * @y_flip: y flip flag
 * @restart_sys_fw_upgrade: restart system when firmware upgrade complete
 * @force_restart_sys_fw_upgrade: force restart system even firmware upgrade
 *  is not complete, this is used for special firmware which changes touch
 *  controller I2C slave address
 * @irq_gpio: attention interrupt gpio
 * @power_gpio: power switch gpio
 * @power_on_state: power switch active state
 * @reset_gpio: reset gpio
 * @reset_on_state: reset active state
 * @irq_flags: irq flags
 * @panel_x: x-axis resolution of display panel
 * @panel_y: y-axis resolution of display panel
 * @power_delay_ms: delay time to wait after power-on
 * @reset_delay_ms: delay time to wait after reset
 * @reset_active_ms: reset active time
 * @byte_delay_us: delay time between two bytes of SPI data
 * @block_delay_us: delay time between two SPI transfers
 * @regulator_name: pointer to name of regulator
 * @gpio_config: pointer to gpio configuration function
 * @cap_button_map: pointer to 0d button map
 * @fw_wake_swipe_distance:  Firmware wakeup length in millimetres
 *  The length of swipe require to get the controller to wakeup the CPU
 *  The longer the initial swipe the less often the CPU is
 *  woken up.  A longer minimum swipe also gives more consistent delta x & y
 *  values.
 *  -1 - use firmware defaults
 * @fw_wake_zone_top_left_x:
 * @fw_wake_zone_top_left_x1:
 *  Firmware wakeup zone top left point x
 *  -1 - use firmware defaults
 * @fw_wake_zone_top_left_y;
 *  Firmware wakeup zone top left point y
 * -1 - use firmware defaults
 * @fw_wake_zone_bottom_right_x;
 * @fw_wake_zone_bottom_right_x1;
 *  Firmware wakeup zone bottom right point x
 *  -1 - use firmware defaults
 * @fw_wake_zone_bottom_right_y;
 *  Firmware wakeup zone bottom right point y
 *  -1 - use firmware defaults
 * @large_object_detected;
 *  Track large touch objects
 *  The touch controller needs to change the  baseline relaxation algorithm when large objects touch are present.
 * @fw_wake_swipe_min_speed;
 *  Firmware wakeup swipe speed in millimetres per second
 *  -1 - use firmware defaults
 * @fw_wake_swipe_max_speed;
 *  Maximum swipe speed in unknown units
 *  -1 - use firmware defaults
 */

struct synaptics_dsx_board_data {
	bool x_flip;
	bool y_flip;
	bool swap_axes;
	bool reg_en;
	bool i2c_pull_up;
	bool pm_disabled;
	bool wg_no_ct;
	bool restart_sys_fw_upgrade;
	bool force_restart_sys_fw_upgrade;
	int irq_gpio;
	int irq_on_state;
	int power_gpio;
	int main_power_gpio;
	int power_on_state;
	int main_power_on_state;
	int reset_gpio;
	int reset_on_state;
	int max_y_for_2d;
	unsigned long irq_flags;
	unsigned int panel_x;
	unsigned int panel_y;
	unsigned int power_delay_ms;
	unsigned int reset_delay_ms;
	unsigned int reset_active_ms;
	unsigned int byte_delay_us;
	unsigned int block_delay_us;
	unsigned int resolution_x;
	unsigned int resolution_y;
	unsigned char watchdog_timeout_s;
	unsigned char *regulator_name;
	unsigned char lockup_poll_count;
	unsigned int lockup_poll_interval_ms;
	const char *bl_product_id;
	const char *product_id_major;
	int report_type;
	int disable_bc_bist;
	struct regulator *vcc;
	struct regulator *vcc_i2c;
	bool dis_in_slider;
	bool enable_abs_cancel;
	bool enable_abs_edge;
	int (*gpio_config)(int gpio, bool configure, int dir, int state);
	struct synaptics_dsx_cap_button_map *cap_button_map;
	int device_id;
	const char *input_dev_name;
	int large_object_detected;
	int tap_status_addr;
	int pos_buf_addr;
};

#endif
