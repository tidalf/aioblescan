#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This file deal with Bbw200 formated message
#
# Copyright (c) 2017 François Wautier
# Copyright (c) 2018 Cyril Leclerc
#
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE

import aioblescan as aios
from base64 import b64decode
from math import sqrt
from struct import pack, unpack, calcsize


class Bbw200(object):
    """Class defining the content of an Bbw200 Tag advertisement.

    """

    def decode(self, packet):
        result = {}
        url = packet.retrieve("Payload for mfg_specific_data")
        if url:
            val = url[0].val
            # magic for beewi bbw200 device
            if val[0] == 0x0d and val[1] == 0x00 and val[2] == 0x05:
                # start after magic
                val = val[3:]
                bytes = ''.join('{:02x} '.format(x) for x in val).split(" ")
                temperature = int(bytes[2] + bytes[1], 16)
                if (temperature > 0x8000):
                    temperature = temperature - 0x10000

                result["mac address"] = packet.retrieve("peer")[0].val
                result["temperature"] = temperature / 10.0
                result["humidity"] = int(bytes[4], 16)
                result["battery"] = int(bytes[9], 16)

                return result
        else:
            return None
