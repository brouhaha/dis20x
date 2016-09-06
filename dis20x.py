#!/usr/bin/env python3

# Disassembler for Intel SBC 201/202 channel microcode (Intel 3001 and 3002 bitslice design)
# Copyright 2016 Eric Smith <spacewar@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only

# This program is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU General Public License
# as published by the Free Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re

ihre = re.compile('^:(([0-9a-fA-F]{2})+)$')


def decode_fields(fields, w):
    d = { }
    for name in fields:
        value = (w >> fields[name][0]) & ((1 << fields[name][1]) - 1)
        d[name] = value
    return d

def parse_intel_hex_line(l, data):
    m = ihre.match(l.strip())
    if not m:
        raise Exception("bad format")
    s = m.group(1)
    byte_count = int(s[0:2], 16)
    if byte_count != (len(s)//2) - 5:
        raise Exception("bad format")
    all_bytes = [int(s[i*2:i*2+2], 16) for i in range(byte_count + 5)]
    address = all_bytes[1] * 256 + all_bytes[2]
    rec_type = all_bytes[3]
    if rec_type == 0x01:
        return  # end of file
    if rec_type == 0x04:
        return  # extended linear address, ignore
    if rec_type != 0x00:
        raise Exception('unknown record type %02x' % rec_type)
    ldata = all_bytes[4:byte_count+4]
    checksum = 256 - sum(all_bytes[:-1])&0xff
    exp_checksum = all_bytes[byte_count+4]
    if checksum != exp_checksum:
        raise Exception('expected checksum %02x, computed %02x' % (exp_checksum, checksum))
    #print('%02x %04x %02x %s %02x' % (byte_count, address, rec_type, '.'.join(['%02x' % b for b in ldata]), exp_checksum))
    if address != len(data):
        raise Exception('discontiguous address %04x, expected %04x' % (address, len(data)))
    data.extend(ldata)
    
def read_intel_hex_file(fn):
    data = bytearray()
    with open(fn, 'r') as f:
        for l in f:
            parse_intel_hex_line(l, data)
    return data


prom_set = 'sbc202'

prom_fn = { 'sbc201': ['sbc201-a10-0236.hex',
                       'sbc201-a11-0237.hex',
                       'sbc201-a12-0238.hex',
                       'sbc201-a13-0239.hex'],
            'sbc202': ['sbc202-a10-0230.hex',
                       'sbc202-a11-0261.hex',
                       'sbc202-a12-0233.hex',
                       'sbc202-a13-0232.hex'],
            'mds740': ['mds740-a2-104567-002.hex',
                       'mds740-a3-104568-002.hex',
                       'mds740-a4-104569-002.hex',
                       'mds740-a5-104571-002.hex']}

raw_microcode = [(b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3] for b in zip(*[read_intel_hex_file(fn) for fn in prom_fn[prom_set]])]

fields = { 'ac':   (25, 7),
           'f':    (18, 7),
           'fc':   (16, 2),
           'in':   (13, 3),
           'out':  (10, 3),
           'slk':  ( 8, 2),
           'mask': ( 0, 8) }

microcode = [decode_fields(fields, w) for w in raw_microcode]

for addr in range(len(microcode)):
    ui = microcode[addr]
    jc = ui['ac']
    if jc & 0x60 == 0x00:
        jcs = 'JCC %03x' % (((jc & 0x01f) << 4) + (addr & 0x0f))
    elif jc & 0x70 == 0x20:
        jcs = 'JZR %03x' % (jc & 0x0f)
    elif jc & 0x70 == 0x30:
        jcs = 'JCR %03x' % ((addr & 0x1f0) + (jc & 0x0f))
    elif jc & 0x70 == 0x40:
        jcs = 'JFL'
    elif jc & 0x78 == 0x50:
        jcs = 'JCF'
    elif jc & 0x78 == 0x58:
        jcs = 'JCF'
    elif jc & 0x78 == 0x60:
        jcs = 'JPR'
    elif jc & 0x78 == 0x68:
        jcs = 'JLL'
    elif jc & 0x78 == 0x70:
        jcs = 'JCE'
    elif jc & 0x7c == 0x78:
        jcs = 'JPX'
    elif jc & 0x7c == 0x7c:
        jcs = 'JRL'
        
    print('%03x' % addr, jcs, microcode[addr])
