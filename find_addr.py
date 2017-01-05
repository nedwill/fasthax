import sys
import struct

def search(binary, pattern, skip=0, masks=None, return_offset=False, start_offset=0):
    pattern_len = len(pattern)
    for idx in xrange(start_offset, len(binary) - pattern_len):
        b = binary[idx : idx + pattern_len]
        if masks:
            for offset, maskbit in masks:
                target_uint = struct.unpack('I', (b[offset:offset + 4]))[0]
                b = b[:offset] + struct.pack('I', target_uint & maskbit) + b[offset + 4:]
        if b != pattern:
            continue
        if return_offset:
            return idx + skip
        return struct.unpack('I', (binary[idx + skip: idx + skip + 4]))[0]

def find_handle_lookup(binary):
    # F0 41 2D E9       STMFD   Sp!, {R4-R8,LR}
    # 01 50 A0 E1       MOV     R5, R1
    # 00 60 A0 E1       MOV     R6, R0
    # E8 10 9F E5       LDR     R1, =0xFFFF9000
    # 10 00 80 E2       ADD     R0, R0, #0x10
    # 00 40 A0 E1       MOV     R4, R0
    # 00 10 91 E5       LDR     R1, [R1]
    # 9F 2F 90 E1       LDREX   R2, [R0]
    addr = search(binary,
                  '\xf0\x41\x2d\xe9\x01\x50\xa0\xe1\x00\x60\xa0\xe1\xe8\x10\x9f\xe5'
                  '\x10\x00\x80\xe2\x00\x40\xa0\xe1\x00\x10\x91\xe5\x9f\x2f\x90\xe1',
                  return_offset=True)
    return addr

def find_random_stub(binary):
    # 0C 10 91 E5       LDR     R1, [R1, #0xC]
    # 00 10 80 E5       STR     R1, [R0]
    # 1E FF 2F E1       BX      LR
    # 0C 10 81 E2       ADD     R1, R1, #0xC
    # 00 10 80 E5       STR     R1, [R0]
    # 1E FF 2F E1       BX      LR
    addr = search(binary,
                  '\x0c\x10\x91\xe5\x00\x10\x80\xe5\x1e\xff\x2f\xe1'
                  '\x0c\x10\x81\xe2\x00\x10\x80\xe5\x1e\xff\x2f\xe1',
                  return_offset=True)
    return addr

def find_svc_handler_table(binary):
    # 0F 00 BD E8       LDMFD   SP!, {R0-R3}
    # 24 80 9D E5       LDR     R8, [SP, #0x24]
    # 00 00 58 E3       CMP     R8, #0
    # 28 D0 8D 02       ADDEQ   SP, SP, #0x28
    # FF 50 BD 18       LDMNEFD SP!, {R0-R7, R12, LR}
    # 30 E0 DD E5       LDRB    LR, [SP, #x30]
    # EF FF FF EA       B       0x1FF822CC
    # 00 00 00 00       ; svc table start
    # 4C 36 F0 FF
    addr = search(binary,
                  '\x0f\x00\xbd\xe8\x24\x80\x9d\xe5\x00\x00\x58\xe3\x28\xd0\x8d\x02'
                  '\xff\x50\xbd\x18\x30\xe0\xdd\xe5\xef\xff\xff\xea\x00\x00\x00\x00'
                  '\x00\x00\xf0\xff\x00\x00\xf0\xff\x00\x00\xf0\xff\x00\x00\xf0\xff',
                  skip=0x1C,
                  masks=((0x20, 0xfff00000), (0x24, 0xfff00000),
                         (0x28, 0xfff00000), (0x2c, 0xfff00000)),
                  return_offset=True)
    return addr

def find_free_40_bytes_area(binary):
    # 0C 10 90 E5       LDR     R1, [R0, #0xC]
    # 04 00 A0 E1       MOV     R0, R4
    # 31 FF 2F E1       BLX     R1
    # 04 10 A0 E1       MOV     R1, R4
    # 08 00 9F E5       LDR     R0, =0xFFF33340
    # 10 40 BD E8       LDMFM   SP!, {R4, LR}
    # 7E BB FF EA       B       0x1FF9C5E4
    # 28 33 F3 FF
    # 40 33 F3 FF
    # FF FF FF FF       ; target
    addr = search(binary,
                  '\x0c\x10\x90\xe5\x04\x00\xa0\xe1\x31\xff\x2f\xe1\x04\x10\xa0\xe1'
                  '\x08\x00\x9f\xe5\x10\x40\xbd\xe8\x00\x00\xff\xea\x00\x00\xf3\xff'
                  '\x00\x00\xf3\xff\xff\xff\xff\xff',
                  skip=0x24,
                  masks=((0x18, 0xeaff0000), (0x1c, 0xfff30000), (0x20, 0xfff30000)),
                  return_offset=True)

    if binary[addr:addr + 40] == ('\xff' * 40):
        return addr

def read_op2_value(op2):
    if op2 == 0x901:
        return 0x4000
    if op2 == 0xb12:
        return 0x4800
    if op2 == 0xf92:
        return 0x248
    if op2 == 0xf56:
        return 0x158
    print 'WARN: unknown op2', hex(op2)
    return 0

def find_ktimer_pool_info(binary):
    # n3ds patterns
    # 01 29 84 E2       ADD     R2, R4, KTIMER_BASE_OFFSET_1
    # E1 3E A0 E3       MOV     R3, KTIMER_POOL_SIZE
    # E2 2E 82 E2       ADD     R2, R2, KTIMER_BASE_OFFSET_2
    # B4 61 C0 E1       STRH    R6, [R0, #20]
    # 50 03 9F E5       LDR     R0, =KTIMER_POOL_HEAD
    # 3C 10 A0 E3       MOV     R1, #60
    # 54 51 00 EB       BL      0x1FF94738

    # maybe >= 11.0
    idx = search(binary,
                 '\x00\x20\x84\xe2\x00\x3e\xa0\xe3\x00\x2e\x82\xe2\xb4\x61\xc0\xe1'
                 '\x50\x03\x9f\xe5\x3c\x10\xa0\xe3\x00\x00\x00\xeb',
                 masks=((0x0, ~0xfff), (0x4, ~0xff), (0x8, ~0xff), (0x18, ~0xffff)),
                 return_offset=True)
    if idx:
        size = (struct.unpack('I', (binary[idx + 4:idx + 8]))[0] & 0xff) << 4
        addr = struct.unpack('I', (binary[idx + 0x368:idx + 0x368 + 4]))[0]
        offset1 = struct.unpack('I', (binary[idx:idx + 4]))[0] & 0xfff
        offset2 = (struct.unpack('I', (binary[idx + 8:idx + 12]))[0] & 0xff) << 4
        return size, addr, read_op2_value(offset1) + offset2

    # maybe >= 9.0
    idx = search(binary,
                 '\x00\x20\x84\xe2\x00\x3e\xa0\xe3\x00\x2e\x82\xe2\xb4\x61\xc0\xe1'
                 '\x48\x03\x9f\xe5\x3c\x10\xa0\xe3\x00\x00\x00\xeb',
                 masks=((0x0, ~0xfff), (0x4, ~0xff), (0x8, ~0xff), (0x18, ~0xffff)),
                 return_offset=True)
    if idx:
        size = (struct.unpack('I', (binary[idx + 4:idx + 8]))[0] & 0xff) << 4
        addr = struct.unpack('I', (binary[idx + 0x360:idx + 0x360 + 4]))[0]
        offset1 = struct.unpack('I', (binary[idx:idx + 4]))[0] & 0xfff
        offset2 = (struct.unpack('I', (binary[idx + 8:idx + 12]))[0] & 0xff) << 4
        return size, addr, read_op2_value(offset1) + offset2

    # o3ds patterns
    # 12 2B 84 E2       ADD     R2, R4, KTIMER_BASE_OFFSET_1
    # 54 33 9F E5       LDR     R3, =KTIMER_POOL_SIZE_PTR
    # 92 2F 82 E2       ADD     R2, R2, KTIMER_BASE_OFFSET_2
    # B4 61 C0 E1       STRH    R6, [R0, #20]
    # 4C 03 9F E5       LDR     R0, =KTIMER_POOL_HEAD
    # 3C 10 A0 E3       MOV     R1, #60
    # E3 4F 00 EB       BL      0x1FF9416c

    # maybe >= 11.0
    idx = search(binary,
                 '\x00\x20\x84\xe2\x00\x00\x9f\xe5\x00\x2f\x82\xe2\xb4\x61\xc0\xe1'
                 '\x4c\x03\x9f\xe5\x3c\x10\xa0\xe3\x00\x00\x00\xeb',
                 masks=((0x0, ~0xfff), (0x4, ~0xffff), (0x8, ~0xff), (0x18, ~0xffff)),
                 return_offset=True)
    if idx:
        size_ptr = struct.unpack('I', (binary[idx + 4:idx + 8]))[0]
        addr = struct.unpack('I', (binary[idx + 0x348:idx + 0x348 + 4]))[0]
        offset1 = struct.unpack('I', (binary[idx:idx + 4]))[0] & 0xfff
        offset2 = struct.unpack('I', (binary[idx + 8:idx + 12]))[0] & 0xfff
        return 0xdead, addr, read_op2_value(offset1) + read_op2_value(offset2)

    # maybe >= 9.0
    idx = search(binary,
                 '\x00\x20\x84\xe2\x00\x00\x9f\xe5\x00\x2f\x82\xe2\xb4\x61\xc0\xe1'
                 '\x58\x03\x9f\xe5\x3c\x10\xa0\xe3\x00\x00\x00\xeb',
                 masks=((0x0, ~0xfff), (0x4, ~0xffff), (0x8, ~0xff), (0x18, ~0xffff)),
                 return_offset=True)
    if idx:
        size_ptr = struct.unpack('I', (binary[idx + 4:idx + 8]))[0]
        addr = struct.unpack('I', (binary[idx + 0x370:idx + 0x370 + 4]))[0]
        offset1 = struct.unpack('I', (binary[idx:idx + 4]))[0] & 0xfff
        offset2 = struct.unpack('I', (binary[idx + 8:idx + 12]))[0] & 0xfff
        return 0xdead, addr, read_op2_value(offset1) + read_op2_value(offset2)

    # need to check
    return (None, None, None)

def hex_or_dead(addr):
    return hex(addr or 0xdeadbabe)

def convert_addr(addr, offset):
    if not addr:
        return
    return addr + offset - 0x1ff80000 + 0xfff00000

def read_section_info(native_firm, idx):
    offset = idx * 0x30 + 0x40 # 0x40 - section info start
    section_offset = struct.unpack('I', native_firm[offset:offset + 4])[0]
    section_addr_offset = struct.unpack('I', native_firm[offset + 4:offset+8])[0]
    section_size = struct.unpack('I', native_firm[offset + 8:offset+12])[0]
    return section_offset, section_addr_offset, section_size

if len(sys.argv) < 2:
    print '%s <native_firm.bin>' % sys.argv[0]
    raise SystemExit(1)

with open(sys.argv[1], 'rb') as r:
    native_firm = r.read()

    arm11_bin_offset, arm11_bin_addr, arm11_bin_size = read_section_info(native_firm, 1)
    arm11bin = native_firm[arm11_bin_offset:arm11_bin_offset + arm11_bin_size]
    svc_handler_table = find_svc_handler_table(arm11bin)
    handle_lookup = find_handle_lookup(arm11bin)
    random_stub = find_random_stub(arm11bin)
    free_area = find_free_40_bytes_area(arm11bin)
    ktimer_pool_size, ktimer_pool_head, ktimer_pool_offset = find_ktimer_pool_info(arm11bin)
    print '#define SVC_HANDLER_TABLE %s' % hex_or_dead(convert_addr(svc_handler_table,
                                                                    arm11_bin_addr))
    print '#define HANDLE_LOOKUP %s' % hex_or_dead(convert_addr(handle_lookup, arm11_bin_addr))
    print '#define RANDOM_STUB %s' % hex_or_dead(convert_addr(random_stub, arm11_bin_addr))
    print '#define FREE_40_AREA %s' % hex_or_dead(convert_addr(free_area, arm11_bin_addr))
    print '#define KTIMER_POOL_SIZE %s' % hex_or_dead(ktimer_pool_size)
    print '#define KTIMER_POOL_HEAD %s' % hex_or_dead(ktimer_pool_head)
    print '#define KTIMER_POOL_OFFSET %s' % hex_or_dead(ktimer_pool_offset)
