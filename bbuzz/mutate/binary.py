#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz
#
# Licensed under the MIT license (MIT)
# Please see LICENSE file for more details

import bbuzz.common


def binary(case, caselen):
    mutations = []
    mutations.append(case)
    if bbuzz.common.zerocase(case):
        # Handle special case of all zeroes
        mutations = mutations + bitshift_right(case, caselen)
        mutations = mutations + knownvalues(caselen)
    elif bbuzz.common.onecase(case):
        # Handle special case of all ones
        mutations = mutations + bitshift_left(case, caselen)
        mutations = mutations + knownvalues(caselen)
    else:
        mutations.append(bitflip(case, caselen))
        mutations = mutations + bitshift_left(case, caselen)
        mutations = mutations + bitshift_right(case, caselen)
        mutations = mutations + knownvalues(caselen)
        endianess = endian(case, caselen)
        if endianess:
            mutations.append(endianess)
    return mutations


def bitflip(case, caselen):
    mask = "1" * caselen
    flip = str(bin(int(case, 2) ^ int(mask, 2)))[2:]
    return flip.zfill(caselen)


def bitshift_right(case, caselen):
    """Shift bit by bit right, adding ones from the left"""
    bitshifts = []
    for bit in range(1, caselen + 1):
        shift = "1" * bit + case[0:(len(case) - bit)]
        bitshifts.append(shift)
    return bitshifts


def bitshift_left(case, caselen):
    """Shift bit by bit to left, adding zeroes from the right"""
    bitshifts = []
    for bit in range(1, caselen + 1):
        shift = case[bit:] + "0" * bit
        bitshifts.append(shift)
    return bitshifts


def endian(case, caselen):
    step = bbuzz.common.BYTE
    if caselen % step == 0:
        split = [case[i:i + step] for i in range(0, caselen, step)][::-1]
        swap = ''.join(split)
        return swap
    else:
        return False


def knownvalues(caselen):
    values = []
    values.append(
            ("01"*(caselen * 2))[:caselen]
            )
    values.append(
            ("10"*(caselen * 2))[:caselen]
            )
    return values
