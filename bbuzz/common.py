#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz
#
# Licensed under the MIT license (MIT)
# Please see LICENSE file for more details

import ipaddress
from binascii import unhexlify
from math import log
from collections import Counter


BIT = 1
BYTE = 8
WORD = 16
DWORD = 32
QWORD = 64


def error_handler(message):
    """Trivial error reporter"""
    print("=========== ERROR ===========")
    print(message)
    return False


def ipversion(ip_address):
    """Identify IP version"""
    return ipaddress.ip_address(ip_address).version


def mac2hex(mac_address):
    """Return hex value string of a MAC address"""
    return unhexlify(mac_address.replace(':', ''))


def ip2hex(ip_address):
    """Return hex value string of an IP address"""
    ip_version = ipversion(ip_address)

    if ip_version == 4:
        octets = ip_address.split('.')
        hexip = b""
        for octet in octets:
            hexoct = hex(int(octet))[2:].zfill(2)
            hexip = hexip + unhexlify(hexoct)
        return hexip
    if ip_version == 6:
        zeroes = 16 - len(mac2hex(ip_address))
        full_ip_address = ip_address.replace(
            '::', '00' * zeroes).replace(':', '')
        return unhexlify(full_ip_address)


def ip2bin(ip_address):
    """Return binary represenation of an IP address"""
    hexip = ip2hex(ip_address)
    lenip = len(hexip) * BYTE
    return bytes2bin(hexip, lenip)


def hex2bin(hexvalue, init_length=0):
    """Convert hexadecimal value to binary"""
    if not init_length:
        init_length = len(hexvalue) * (BYTE / 2)
    value = str(bin(int(hexvalue, 16))[2:])
    return value.zfill(init_length)


def bin2hex(binvalue):
    """Convert binary string to hex string.
    Sould be BYTE aligned"""
    step = BYTE
    binlen = len(binvalue)
    hexvalue = ""
    if len(binvalue) % step == 0:
        for octet in range(0, binlen, step):
            binoctet = binvalue[octet:(octet + step)]
            hexoctet = hex(int(binoctet, 2))[2:].zfill(2)
            hexvalue += hexoctet
    else:
        error_handler("Cannot perform binary conversion to bytes")
    return hexvalue


def oct2bin(octvalue, init_length):
    """Convert octal value to binary"""
    value = str(bin(int(octvalue, 8))[2:])
    return value.zfill(init_length)


def dec2bin(decvalue, init_length):
    """Convert decimal value to binary"""
    value = str(bin(int(decvalue))[2:])
    return value.zfill(init_length)


def str2bin(strvalue, init_length=0):
    """Convert string value to binary"""
    if not init_length:
        init_length = len(strvalue) * BYTE
    bin_string = ""
    for char in strvalue:
        bin_string += bin(ord(char))[2:].zfill(BYTE)
    value = bin_string
    return value.zfill(init_length)


def bytes2bin(bytesvalue, init_length=0):
    """Convert bytes to binary string"""
    if not init_length:
        init_length = len(bytesvalue)
    value = str(bin(int(bytesvalue.hex(), 16))[2:])
    return value.zfill(init_length)


def bin2bytes(binvalue):
    """Convert binary string to bytes.
    Sould be BYTE aligned"""
    hexvalue = bin2hex(binvalue)
    bytevalue = unhexlify(hexvalue)
    return bytevalue


def load_assemble(payload):
    """Assemble payload from a list of values"""
    asm_load = ""
    for field in payload:
        asm_load += field
    return asm_load


def zerocase(case):
    """Check if the binary string is all zeroes"""
    if int(case, 2) == 0:
        return True
    else:
        return False


def onecase(case):
    """Check if the binary string is all ones"""
    if case == "1" * len(case):
        return True
    else:
        return False


def payload_analyze(data_lists=[], datafile="", detailed_analysis=2):
    """Perform statistical analysis on a set of captured payloads.
    Payloads should be presented as binary strings"""
    if datafile:
        with open(datafile, 'r') as bindata:
            for data in bindata:
                data_lists.append(data.strip())
            bindata.close()
    if data_lists:
        # Get the bit mask of payload
        reflist = data_lists[0]
        payload_mask = ['#'] * len(reflist)
        fail = False
        for position in range(0, len(reflist)):
            symbol = reflist[position]
            for data in data_lists[1::]:
                data_symbol = data[position]
                if data_symbol != symbol and not fail:
                    fail = True
                    break
            if not fail:
                payload_mask[position] = symbol
            if fail:
                payload_mask[position] = "*"
                fail = False
        str_payload_mask = ''.join(payload_mask)
        print("[+] Payload mask:\n{0}".format(str_payload_mask))

        if detailed_analysis >= 1:
            # Extract bit-groups
            print("[+] Bit-groups:")
            field_list = group_fields(reflist, str_payload_mask, silent=False)
            print("\t[-] Bit group: {}".format(field_list))

        if detailed_analysis >= 2:
            # Calculate entropy for bit-groups
            print("[+] Bit group entropy:")
            payload_entropy = entropy(reflist)
            print("\t[-] Payload entropy: {}".format(payload_entropy))

    if not data_lists and not datafile:
        error_handler("No data presented for pattern analysis!")


def group_fields(payload, payload_mask, silent=True):
    """Retrieves payload and bit-mask group intersections"""
    bit_group = ""
    payload_groups = []
    if payload_mask[0] in {'0', '1'}:
        char = False
        prevchar = False
    if payload_mask[0] == '*':
        char = True
        prevchar = True
    for position in range(0, len(payload_mask)):
        if payload_mask[position] in {'0', '1'}:
            char = False
        if payload_mask[position] == '*':
            char = True
        if char == prevchar:
            bit_group += payload[position]
        if char != prevchar:
            instance = (bit_group, 'immutable' if char else 'mutable')
            payload_groups.append(instance)
            if not silent:
                print(instance)
            bit_group = payload[position]
        prevchar = char
    if bit_group:
        instance = (
            bit_group, 'mutable' if payload[-1] == '*' else 'immutable'
            )
        if not silent:
            print(instance)
        payload_groups.append(instance)
    return payload_groups


def entropy(data):
    """Calculate Shannon entropy of a string.
    Courtesy of rosettacode.org"""
    counter = Counter(data)
    length = float(len(data))
    ent = -sum(
        count / length * log(count / length, 2)
        for count in counter.values()
        )
    return ent
