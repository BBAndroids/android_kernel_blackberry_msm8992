/* Copyright (c) 2010-2015, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __HDMI_EDID_H__
#define __HDMI_EDID_H__

#include <linux/msm_hdmi.h>
#include "mdss_hdmi_util.h"

struct hdmi_edid_init_data {
	struct dss_io_data *io;
	struct mutex *mutex;
	struct kobject *sysfs_kobj;

	struct hdmi_tx_ddc_ctrl *ddc_ctrl;
	struct hdmi_util_ds_data *ds_data;
	int (**ds_read_edid_block) (int block, uint8_t *edid_buf);
};

int hdmi_edid_read(void *edid_ctrl);
u8 hdmi_edid_get_sink_scaninfo(void *edid_ctrl, u32 resolution);
u32 hdmi_edid_get_sink_mode(void *edid_ctrl);
int hdmi_edid_get_audio_blk(void *edid_ctrl,
	struct msm_hdmi_audio_edid_blk *blk);
void hdmi_edid_set_video_resolution(void *edid_ctrl, u32 resolution);
void hdmi_edid_deinit(void *edid_ctrl);
void *hdmi_edid_init(struct hdmi_edid_init_data *init_data);
bool hdmi_edid_is_s3d_mode_supported(void *input,
	u32 video_mode, u32 s3d_mode);

#endif /* __HDMI_EDID_H__ */
