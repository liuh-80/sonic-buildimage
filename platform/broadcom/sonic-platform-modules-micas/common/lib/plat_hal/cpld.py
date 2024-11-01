#!/usr/bin/env python3
#
# Copyright (C) 2024 Micas Networks Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from plat_hal.devicebase import devicebase


class cpld(devicebase):
    __user_reg = None

    def __init__(self, conf=None):
        if conf is not None:
            self.name = conf.get('name', None)
            self.user_reg = conf.get('UserReg', None)
            self.console_reg = conf.get('ConsoleReg', None)
            self.console_reg_attrs = conf.get('ConsoleRegAttrs', None)
            self.version_file = conf.get('VersionFile', None)
            self.cpld_id = conf.get("cpld_id", None)
            self.desc = conf.get("desc", None)
            self.slot = conf.get("slot", None)
            self.format = conf.get("format", "big_endian")
            self.warm = conf.get("warm", None)
            self.type = conf.get("type", None)

    def get_user_reg(self):
        if self.user_reg is None:
            return False
        ret, val = self.get_value(self.user_reg)
        return val

    def set_user_reg(self, value):
        if self.user_reg is None:
            return False
        byte = value & 0xFF
        ret, val = self.set_value(self.user_reg, byte)
        return ret

    def set_console_owner(self, owner):
        ret = False

        if self.console_reg is None:
            return False
        tmpattr = self.console_reg_attrs.get(owner, None)
        if tmpattr is not None:
            ret, val = self.set_value(self.console_reg, tmpattr)
        return ret

    def get_version(self):
        ret, val = self.get_value(self.version_file)
        if ret is False:
            val = "N/A"
            return val
        if self.type == "str":
            return val.strip('\n')
        val = val.strip('\n').split(" ")
        if len(val) < 4:
            val = "N/A"
            return val
        if self.format == "little_endian":
            cpld_version = "%s%s%s%s" % (val[3], val[2], val[1], val[0])
        else:
            cpld_version = "%s%s%s%s" % (val[0], val[1], val[2], val[3])
        return cpld_version
