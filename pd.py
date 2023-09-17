##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2023 Jacky6 <Jacky6.Liu7@gmail.com>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##


import sigrokdecode as srd

# Dictionary of FUNCTION commands and their names.
commands_1977 = {
    0x0f: ['Write Scratchpad', 'WR Sc'],
    0xaa: ['Read Scratchpad', 'RD Sc'],
    0x99: ['Copy Scratchpad with Password', 'WR Mem'],
    0x69: ['Read Memory with Password', 'RD Mem'],
    0xc3: ['Verify Password', 'Verify Pwd'],
    0xcc: ['Read Version Command', 'RD Ver'],
}


# Calculate the CRC-16 checksum.
# Initial value: 0x0000, xor-in: 0x0000, polynom 0x8005, xor-out: 0xffff.
def crc16(byte_array):
    reverse = 0xa001  # Use the reverse polynom to make algo simpler.
    crc = 0x0000  # Initial value.
    # Reverse CRC calculation.
    for byte in byte_array:
        for bit in range(8):
            if (byte ^ crc) & 1:
                crc = (crc >> 1) ^ reverse
            else:
                crc >>= 1
            byte >>= 1
    crc ^= 0xffff  # Invert CRC.
    return crc


bin_mem, bin_read, bin_full = range(3)
ann_data, ann_reset, ann_rom, ann_cmd, ann_pwd, ann_addr, ann_end, ann_stat, ann_crc, ann_succ, ann_fail, ann_err = range(12)


class Decoder(srd.Decoder):
    api_version = 3
    id = 'ds1977'
    name = 'DS1977'
    longname = 'Dallas DS1977'
    desc = 'Dallas DS1977 iButton (1-Wire) protocol.'
    license = 'gplv2+'
    inputs = ['onewire_network']
    outputs = []
    tags = ['IC', 'EEPROM', 'iButton']
    annotations = (
        ('data', 'Data'),
        ('reset', 'Reset/Presence'),
        ('rom', 'ROM'),
        ('cmd', 'Command'),
        ('pwd', 'Password'),
        ('addr', 'Address'),
        ('ending', 'Ending Offset'),
        ('status', 'Data Status'),
        ('crc', 'CRC'),
        ('succ', 'Success'),
        ('fail', 'Fail'),
        ('err', 'Error'),
    )
    annotations_row = (
        ('bits', 'Bits', (ann_data, ann_reset, ann_rom, ann_cmd, ann_pwd, ann_addr, ann_crc, ann_succ, ann_fail)),
        ('err', 'Error', (ann_err)),
    )

    binary = (
        ('mem_read', 'Data read from memory'),
        ('read_pwd', 'Read Access Password'),
        ('full_pwd', 'Full Access Password'),
    )

    def __init__(self):
        self.reset()

    def reset(self):
        # Bytes for function command.
        self.bytes = []
        self.family_code = None
        self.family = 'DS1977'
        self.commands = commands_1977

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)
        self.out_binary = self.register(srd.OUTPUT_BINARY)

    def putx(self, data):
        self.put(self.ss, self.es, self.out_ann, data)

    def decode(self, ss, es, data):
        code, val = data

        if code == 'RESET/PRESENCE':
            self.ss, self.es = ss, es
            self.putx([ann_reset, ['Reset/Presence: %s'
                                   % ('true' if val else 'false')]])
            self.bytes = []
        elif code == 'ROM':
            self.ss, self.es = ss, es
            self.family_code = val & 0xff

            s = None
            if self.family_code == 0x37:
                s = 'is 0x%02x, %s detected' % (self.family_code, self.family)
            else:
                s = '0x%02x unknown' % (self.family_code)

            self.putx([ann_rom, ['ROM: 0x%016x (%s)' % (val, 'family code ' + s),
                                 'ROM: 0x%016x (%s)' % (val, self.family),
                                 'ROM: 0x%016x' % val]])
            self.bytes = []
        elif code == 'DATA':
            self.bytes.append(val)
            if 1 == len(self.bytes):
                self.ss, self.es = ss, es
                if val not in self.commands:
                    self.putx([ann_err, ['Unrecognized command: 0x%02x' % val]])
                else:
                    self.putx([ann_cmd, self.commands[val]])
            elif 0x0f == self.bytes[0]:  # Write scratchpad
                if 2 == len(self.bytes):
                    self.ss = ss
                elif 3 == len(self.bytes):
                    self.es = es
                    self.putx([ann_addr, ['Target address: 0x%04x'
                                          % ((self.bytes[2] << 8) + self.bytes[1])]])
                elif 4 == len(self.bytes):
                    self.ss = ss
                if 4 <= len(self.bytes):
                    self.es = es
                    self.putx([ann_data, ['Data(%d): ' % (len(self.bytes)-3) + (' '.join(format(n, '02x')
                                          for n in self.bytes[3:]))]])
            elif 0xaa == self.bytes[0]:  # Read scratchpad
                if 2 == len(self.bytes):
                    self.ss = ss
                elif 3 == len(self.bytes):
                    self.es = es
                    self.putx([ann_addr, ['Target address: 0x%04x'
                                          % ((self.bytes[2] << 8) + self.bytes[1])]])
                elif 4 == len(self.bytes):
                    tmp = ss + int((es-ss)/4) * 3
                    self.ss, self.es = ss, tmp
                    self.putx([ann_end, ['Ending Offset: %d' % (self.bytes[3] & 0x3f)]])
                    self.ss, self.es = tmp, es
                    self.putx([ann_stat, ['Data status: %s' % ('OK' if (self.bytes[3] & 0xc0 == 0) else 'Err')]])
                elif 5 == len(self.bytes):
                    self.ss = ss
                if 5 <= len(self.bytes):
                    self.es = es
                    self.putx([0, ['Data(%d): ' % (len(self.bytes)-4) + (' '.join(format(n, '02x')
                                   for n in self.bytes[4:]))]])
            elif 0x99 == self.bytes[0]:  # Copy Scratchpad with Password
                if 2 == len(self.bytes):
                    self.ss = ss
                elif 4 == len(self.bytes):
                    self.es = es
                    self.putx([0, ['Authorization pattern (TA1, TA2, E/S): '
                                   + (', '.join(format(n, '#04x') for n in self.bytes[1:4]))]])
                elif 5 == len(self.bytes):
                    self.ss = ss
                elif 12 == len(self.bytes):
                    self.es = es
                    self.putx([ann_pwd, ['Full Access Password: '
                                         + (' '.join(format(n, '02x') for n in self.bytes[4:]))]])
                    # self.put(ss, es, self.out_binary, [bin_full, bytes(self.bytes[4:])])
                elif 13 == len(self.bytes):
                    self.ss, self.es = ss, es
                    if 0xaa == self.bytes[-1] or 0x55 == self.bytes[-1]:
                        self.putx([ann_succ, ['Operation Succeeded', 'Success', 'S']])
                    else:
                        self.putx([ann_fail, ['Operation Failed', 'Failed', 'F']])
            elif 0x69 == self.bytes[0]:  # Read Memory with Password
                if 2 == len(self.bytes):
                    self.ss = ss
                elif 3 == len(self.bytes):
                    self.es = es
                    self.putx([ann_addr, ['Target address: 0x%04x' % ((self.bytes[2] << 8) + self.bytes[1])]])
                elif 4 == len(self.bytes):
                    self.ss = ss
                elif 11 == len(self.bytes):
                    self.es = es
                    self.putx([ann_pwd, ['Read Access Password: ' + (' '.join(format(n, '02x')
                                         for n in self.bytes[3:]))]])
                elif 12 == len(self.bytes):
                    self.ss = ss
                if 12 <= len(self.bytes):
                    self.es = es
                    self.putx([ann_data, ['Data(%d): ' % (len(self.bytes)-11) + (' '.join(format(n, '02x')
                                          for n in self.bytes[11:]))]])
