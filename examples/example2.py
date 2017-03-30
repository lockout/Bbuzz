#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz
#
# Licensed under the MIT license (MIT)
# Please see LICENSE file for more details

import bbuzz


# Analyze captured packets
bbuzz.common.data_pattern(datafile="icc2.packets")

# Layer-5 fuzzing example
# Define base Layer-4 connection
print("Establishing connection...")
interface = "enp0s25"
PROTO = 2                 # SOCK_DGRAM - UDP
dstip = "192.168.17.255"
dport = 1229
proto = bbuzz.protocol.Protocol(
        'raw4',
        ((dstip, dport), PROTO)
        )
proto.configure(broadcast=True)
proto.create(interface)

# Describe the Layer-5 payload - unknown binary data protocol
print("Parsing payload...")
load = bbuzz.payload.Payload()
load.add(
        'b>11000000011000100000000000101100000010000101101100000',
        'static',
        53
        )
load.add('b>0011000100', 'binary', 10)
load.add('b>1000000000000000000000000011000110100011100000001', 'static', 49)
load.add('b>10110', 'binary', 5)
load.add('b>00111', 'static', 5)
load.add('b>01110', 'binary', 5)
load.add('b>1', 'static', 1)
load.add('b>000100', 'binary', 6)
load.add('b>11', 'static', 2)
load.add('b>1111010', 'binary', 7)
load.add('b>110100101001101011010100100010001', 'static', 33)
load.add('b>1110111', 'binary', 7)
load.add('b>1', 'static', 1)
load.add('b>0', 'binary', 1)
load.add('b>00000', 'static', 5)
load.add('b>1', 'binary', 1)
load.add('b>1', 'static', 1)
load.add('b>0000000', 'binary', 7)
load.add('b>11', 'static', 2)
load.add('b>001010', 'binary', 6)
load.add('b>1000010000101101100000', 'static', 22)
load.add('b>0011000101', 'binary', 10)
load.add('b>0000000000000000000000000011000110100011100000001', 'static', 49)
load.add('b>10110', 'binary', 5)
load.add('b>00111', 'static', 5)
load.add('b>01110', 'binary', 5)
load.add('b>1', 'static', 1)
load.add('b>000100', 'binary', 6)
load.add('b>11', 'static', 2)
load.add('b>1111010', 'binary', 7)
load.add(
        'b>1001001110000010101000001010000010000000100000001000000011',
        'static',
        58
        )
load.add('b>1110011', 'binary', 7)

# Generate payload mutations
print("Generating mutations...")
mutagen = bbuzz.mutate.Mutate(load)
mutagen.configure(random=True)
mutagen.go()
