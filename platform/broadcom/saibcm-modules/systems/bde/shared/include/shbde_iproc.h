/*
 * $Id: $
 * $Copyright: 2007-2023 Broadcom Inc. All rights reserved.
 * 
 * Permission is granted to use, copy, modify and/or distribute this
 * software under either one of the licenses below.
 * 
 * License Option 1: GPL
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation (the "GPL").
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 (GPLv2) for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * version 2 (GPLv2) along with this source code.
 * 
 * 
 * License Option 2: Broadcom Open Network Switch APIs (OpenNSA) license
 * 
 * This software is governed by the Broadcom Open Network Switch APIs license:
 * https://www.broadcom.com/products/ethernet-connectivity/software/opennsa $
 * 
 *
 */

#ifndef __SHBDE_IPROC_H__
#define __SHBDE_IPROC_H__

#include <shbde.h>

extern int
shbde_iproc_config_init(shbde_iproc_config_t *icfg,
                        unsigned int dev_id, unsigned int dev_rev);

extern int
shbde_iproc_paxb_init(shbde_hal_t *shbde, void *iproc_regs,
                      shbde_iproc_config_t *icfg);

extern unsigned int
shbde_iproc_pci_read(shbde_hal_t *shbde, void *iproc_regs,
                     unsigned int addr);

extern void
shbde_iproc_pci_write(shbde_hal_t *shbde, void *iproc_regs,
                      unsigned int addr, unsigned int data);

extern int
shbde_iproc_pcie_preemphasis_set(shbde_hal_t *shbde, void *iproc_regs,
                                 shbde_iproc_config_t *icfg, void *pci_dev);

#endif /* __SHBDE_IPROC_H__ */
