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
interface = "tap0"
srcmac = '12:e9:d8:6a:e8:f0'
dstmac = '52:54:00:12:34:56'
proto = bbuzz.protocol.Protocol(
        'raw2',
        {
            "SOURCE_MAC": srcmac,
            "DESTINATION_MAC": dstmac,
            "ETHER_TYPE": "0x86DD"                  # IPv6
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
            "FUZZABLE": False
            }
        )
load.add('0',                                      # Traffic class
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 8,
            "FUZZABLE": True,
            }
        )
load.add('00000000000000000000',                    # Flow label
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 20,
            "FUZZABLE": False
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
            "FUZZABLE": True
            }
        )
load.add('ff',                                      # Hop limit
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 8,
            "FUZZABLE": True
            }
        )
load.add(bbuzz.common.ip2bin('fe80::10e9:d8ff:fe6a:e8f0'),
        {                                           # Source IP
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 128,
            "FUZZABLE": True
            }
        )
load.add(bbuzz.common.ip2bin('fe80::5054:ff:fe12:3456'),
        {                                           # Destination IP
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 128,
            "FUZZABLE": False
            }
        )

# Generate payload mutations
print("[+] Generating mutations...")
mutagen = bbuzz.mutate.Mutate(load, {"STATIC": True, "RANDOM": True})

# Sart fuzzing
print("[+] Starting fuzzing...")
fuzzer = bbuzz.fuzz.Fuzz()
fuzzer.fuzz(mutagen, proto)
