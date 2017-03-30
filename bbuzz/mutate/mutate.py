#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz
#
# Licensed under the MIT license (MIT)
# Please see LICENSE file for more details

import bbuzz.common
import bbuzz.mutate.binary
import bbuzz.mutate.delimiter
import bbuzz.mutate.numeric
import bbuzz.mutate.static
import bbuzz.mutate.string
import bbuzz.mutate.random

from itertools import product


class Mutate():
    def __init__(self, mutate_payload, mutate_options=None):
        self.payload = mutate_payload
        self.options = mutate_options

        self.mutate()

    def mutate(self):
        """Manage the mutation engines and produce a test case"""
        self.convert()
        self.generate_known()
        self.mutations = self.generate_random()

    def convert(self):
        """Convert all field values to binary"""
        self.bitfields = []

        for field_number in range(self.payload.field_count()):
            data_value = self.payload.bitfield_data(field_number)
            data_length = self.payload.bitfield_length(field_number)
            data_format = self.payload.bitfield_format(field_number).lower()
            if data_format == "bin":
                data = data_value
            elif data_format == "hex":
                data = bbuzz.common.hex2bin(
                        data_value,
                        data_length
                        )
            elif data_format == "dec":
                data = bbuzz.common.dec2bin(
                        data_value,
                        data_length
                        )
            elif data_format == "oct":
                data = bbuzz.common.oct2bin(
                        data_value,
                        data_length
                        )
            elif data_format == "str":
                data = bbuzz.common.str2bin(
                        data_value,
                        data_length
                        )
            elif data_format == "bytes":
                data = bbuzz.common.bytes2bin(
                        data_value,
                        data_length
                        )
            else:
                bbuzz.common.error_handler(
                        "No field {0} format specified".format(field_number)
                        )
                data = None

            self.bitfields.append(data.zfill(data_length))

    def generate_known(self):
        """Generate known bad mutations depending on the field type"""
        field_count = self.payload.field_count()
        self.mutations = [None] * field_count

        for field_number in range(field_count):
            data = self.bitfields[field_number]
            if self.payload.bitfield_fuzzable(field_number):
                data_type = self.payload.bitfield_type(field_number)
                data_len = self.payload.bitfield_length(field_number)
                if data_type == "binary":
                    self.mutations[field_number] = bbuzz.mutate.binary.binary(
                                                    data, data_len
                                                    )
                # TODO: Implement all other mutation types
                elif data_type == "numeric":
                    self.mutations[field_number] = [data]
                elif data_type == "string":
                    self.mutations[field_number] = [data]
                elif data_type == "delimiter":
                    self.mutations[field_number] = [data]
                elif data_type == "static":
                    self.mutations[field_number] = [data]
                else:
                    bbuzz.common.error_handler(
                            "No field {0} type specified".format(field_number)
                            )
            else:
                self.mutations[field_number] = [data]

        self.generated_mutations = product(*self.mutations)

    def generate_random(self):
        """"Generate random mutations"""
        field_count = self.payload.field_count()
        mutation = [None] * field_count

        for field_number in range(field_count):
            data = self.bitfields[field_number]
            if self.payload.bitfield_fuzzable(field_number):
                data_len = self.payload.bitfield_length(field_number)
                mutation[field_number] = bbuzz.mutate.random.rand_bin(
                                                data, data_len
                                                )
            else:
                mutation[field_number] = data

        yield mutation

    def assemble_payload(self, mutant_instance):
        """Assemble all the fields bitwise and transfer into bytes for network
        transmission."""
        payload_bits = bbuzz.common.load_assemble(mutant_instance)
        payload_bytes = bbuzz.common.bin2bytes(payload_bits)
        return payload_bytes

    def get_mutation(self):
        """Return the next mutation for sending over network socket"""
        try:
            mutation_instance = next(self.generated_mutations)
            mutation_bytes = self.assemble_payload(mutation_instance)
            return mutation_bytes
        except StopIteration:
            return False
