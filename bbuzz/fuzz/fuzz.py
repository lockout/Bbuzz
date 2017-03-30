#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz
#
# Licensed under the MIT license (MIT)
# Please see LICENSE file for more details

from time import sleep


class Fuzz():
    timeout = 0

    def __init__(self, timeout=0.1):
        """Set fuzzing parameters"""
        self.timeout = timeout

    def fuzz(self, mutant, protocol):
        """Start the fuzzing process"""
        cases = mutant.summary()
        for c in range(cases[0]):
            case = mutant.next()
            sleep(self.timeout)
            protocol.send(case)
        # Start the random module
        protocol.kill()
        return True

    def monitor(self):
        """Monitor the fuzzing target"""
        pass

    def track(self):
        """Track the fuzzing process"""
        pass
