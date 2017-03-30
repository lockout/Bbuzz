#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz
#
# Licensed under the MIT license (MIT)
# Please see LICENSE file for more details

import bbuzz


# Layer-3 fuzzing example
# Define the base Layer-2 connection
print("[+] Setting up the base layer connection...")
interface = "lo"
srcmac = '54:ee:75:40:9b:e6'
dstmac = '98:5a:eb:dc:57:67'
proto = bbuzz.protocol.Protocol(
        'raw2',
        {
            "SOURCE_MAC": srcmac,
            "DESTINATION_MAC": dstmac,
            "ETHER_TYPE": "0x86DD"
            }
        )
proto.create(interface)

# Describe the Layer-3 payload - plain IPv6 header
print("[+] Parsing payload fields...")
load = bbuzz.payload.Payload()
load.add('6',                                       # Version number
        {
            "FORMAT": "dec",
            "TYPE": "static",
            "LENGTH": 4,
            }
        )
load.add('0',                                      # Traffic class
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 8
            }
        )
load.add('00000000000000000000',                    # Flow label
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 20
            }
        )
load.add('0000',                                    # Payload length
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": False
            }
        )
load.add('11',                                      # Next header
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 8,
            "FUZZABLE": False
            }
        )
load.add('ff',                                      # Hop limit
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 8,
            "FUZZABLE": False
            }
        )
load.add(bbuzz.common.ip2bin('fe80::61f7:44e6:1fbb:5980'),
        {                                           # Source IP
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 128,
            "FUZZABLE": False
            }
        )
load.add(bbuzz.common.ip2bin('fe80::1471:b0bd:d614:55bc'),
        {                                           # Destination IP
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 128,
            "FUZZABLE": False
            }
        )

# Generate payload mutations
print("[+] Generating mutations...")
mutagen = bbuzz.mutate.Mutate(load)
while True:
    case = mutagen.get_mutation()
    if not case:
        break

mutagen.generate_random()

"""
# Setup and execute fuzzing
print("[+] Fuzzing...")
print("Overall test cases: {0}".format(mutagen.summary()[0]))
print(
    "To obeserve output run: tcpdump -i {0} -nvveXA -s0 ether host {1}"
    .format(interface, srcmac)
    )
fuzz = bbuzz.fuzz.Fuzz()
fuzz.fuzz(mutagen, proto)
"""
