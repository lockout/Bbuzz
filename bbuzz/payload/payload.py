#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz
#
# Licensed under the MIT license (MIT)
# Please see LICENSE file for more details

import random
import string
from hashlib import sha256


class Payload():
    """Payload Class"""
    bit_fields = []

    def add(self, bit_field_data, bit_field_options):
        """
        Add and define the fields of a payload, which will be fuzzed and
        delivered to the target.

        Variable bit_field_data accepts a string containing field value(s).
        bit_field_data: "STR_FIELD_DATA"
                        Value of the field. Can also contain multiple comma
                        separated values to represent a group of data.
                        In that case bit_field_group has to be set to True.

        Variable bit_field_options accepts a dictionary with the following
        options:
        FORMAT: "STR_FIELD_FORMAT"
                        Specify the format in which the data is represented:
                        bin - binary value
                        hex - hexadeximal value
                        dec - decimal value
                        oct - octal value
                        str - string value
                        bytes - bytes value
        TYPE: "STR_FIELD_TYPE"
                        Represents what type of data the field contains.
                        Based on this type mutation strategies are applied.
                        binary - binary mutations will be performed
                        numeric - integer mutations will be perfomed
                        string - string mutations will be performed
                        delimiter - delimiter variations will be performed
                        static - no mutations will be applied
        LENGTH: INT_FIELD_LENGTH
                        Size of the bit field in bits. Defined constants can
                        be used. This value is required in order to perform
                        field alignment if presented data or mutated data does
                        not meet the field length requirements. If set to -1
                        the field is considered of variable length and no
                        alignment is performed.
        GROUP: BOOL_TRUE-FALSE
                        If multiple comma separated values are presented in
                        bit_field_data, then they are treated as a group, and
                        within mutation either one will be selected. Makes
                        sense when a specific bit field can contain different
                        legit static values in order not to perform useless
                        fuzzing.
        FUZZABLE: BOOL_TRUE-FALSE
                        Specifies if this field is to be treated as
                        fuzz-able or as static.
        HASH: STR_FIELD_HASH
                        Unique value assigned to the particular field.
                        This value is calculated and assigned automatically.
        """

        if "LENGTH" not in bit_field_options.keys():
            bit_field_options["LENGTH"] = len(bit_field_data)
        if "GROUP" not in bit_field_options.keys():
            bit_field_options["GROUP"] = False
        if "FUZZABLE" not in bit_field_options.keys():
            if bit_field_options["TYPE"].lower() == "static":
                bit_field_options["FUZZABLE"] = False
            else:
                bit_field_options["FUZZABLE"] = True
        bit_field_options["HASH"] = self.gen_bitfield_hash(bit_field_data)

        self.bit_field = [
            bit_field_data,
            bit_field_options
            ]
        self.bit_fields.append(self.bit_field)

    def gen_bitfield_hash(self, field_value, seed=0, length=128):
        """Generate a pesudo-random bit field hash"""
        if seed:
            random.seed(seed)
        rand_string = ''.join(
                random.choice(
                    string.ascii_letters + string.digits
                    ) for _ in range(length)
                )
        hash_string = field_value + rand_string
        return sha256(hash_string.encode('utf-8')).hexdigest()

    def bitfield(self, field_number):
        """Return all values of the requested bit field.
        NOTE: Bit field numbering starts with 0."""
        if field_number >= self.field_count():
            return False
        else:
            return self.bit_fields[field_number]

    def all_bitfields(self):
        """Return the whole populated payload specification"""
        return self.bit_fields

    def field_count(self):
        """Retrun the count of bit fields in the payload specification"""
        return len(self.bit_fields)

    def bitfield_data(self, bitfield_number):
        """Return the requested bit field data"""
        return self.bit_fields[bitfield_number][0]

    def bitfield_length(self, bitfield_number):
        """Return the requested bit field length"""
        return self.bit_fields[bitfield_number][1]["LENGTH"]

    def bitfield_format(self, bitfield_number):
        """Return the requested bit field data format"""
        return self.bit_fields[bitfield_number][1]["FORMAT"]

    def bitfield_type(self, bitfield_number):
        """Return the requested bit field type"""
        return self.bit_fields[bitfield_number][1]["TYPE"]

    def bitfield_fuzzable(self, bitfield_number):
        """Return if the requested bit field is fuzzable"""
        return self.bit_fields[bitfield_number][1]["FUZZABLE"]

    def bitfield_hash(self, bitfield_number):
        """Return the requested bit field type"""
        return self.bit_fields[bitfield_number][1]["HASH"]

    def payload_length(self):
        """Calculate the overall payload length of all bit fields combined"""
        length = 0
        for field in range(self.field_count()):
            length = length + self.bitfield_length(field)
        return length
