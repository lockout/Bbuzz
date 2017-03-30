#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz
#
# Licensed under the MIT license (MIT)
# Please see LICENSE file for more details

import random


def rand_bin(value, length=0, seed=0):
    """Random binary value generator"""
    if not length:
        length = len(value)
    if seed:
        random.seed(seed)
    binval = bin(random.getrandbits(length))[2:].zfill(length)
    return binval


def gen_binall(binlength):
    """All binary value combination generator"""
    maxnum = 2 ** binlength - 1
    for num in range(0, maxnum):
        binval = bin(num)[2:].zfill(binlength)
        yield binval
