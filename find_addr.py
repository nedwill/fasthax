import sys
import struct

def search(binary, pattern, skip=0, masks=None, return_offset=False):
    pattern_len = len(pattern)
    for idx in xrange(len(binary) - pattern_len):
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
    # ...
    addr = search(binary,
                  '\x0f\x00\xbd\xe8\x24\x80\x9d\xe5\x00\x00\x58\xe3\x28\xd0\x8d\x02'
                  '\xff\x50\xbd\x18\x30\xe0\xdd\xe5\xef\xff\xff\xea\x00\x00\x00\x00'
                  '\x00\x00\xf0\xff\x00\x00\xf0\xff\x00\x00\xf0\xff\x00\x00\xf0\xff',
                  skip=0x1C,
                  masks=((0x20, 0xfff00000), (0x24, 0xfff00000),
                         (0x28, 0xfff00000), (0x2c, 0xfff00000)),
                  return_offset=True)
    return addr

def hex_or_dead(addr):
    return hex(addr or 0xdeadbabe)

def convert_addr(addr, offset):
    if not addr:
        return
    return addr + offset - 0x1ff80000 + 0xfff00000

if len(sys.argv) < 2:
    print '%s <native_firm.bin>' % sys.argv[0]
    raise SystemExit(1)

with open(sys.argv[1], 'rb') as r:
    native_firm = r.read()
    arm11_bin_offset = struct.unpack('I', native_firm[0x70:0x74])[0]
    arm11_offset = struct.unpack('I', native_firm[0x74:0x78])[0]
    arm11_size = struct.unpack('I', native_firm[0x78:0x7c])[0]
    arm11bin = native_firm[arm11_bin_offset:arm11_bin_offset + arm11_size]
    svc_handler_table = find_svc_handler_table(arm11bin)
    handle_lookup = find_handle_lookup(arm11bin)
    random_stub = find_random_stub(arm11bin)
    print '#define SVC_HANDLER_TABLE %s' % hex_or_dead(convert_addr(svc_handler_table,
                                                                    arm11_offset))
    print '#define HANDLE_LOOKUP %s' % hex_or_dead(convert_addr(handle_lookup, arm11_offset))
    print '#define RANDOM_STUB %s' % hex_or_dead(convert_addr(random_stub, arm11_offset))
