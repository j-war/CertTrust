#!/usr/bin/env python3
# CertTrust.py
#
# Run with one of:
#    python3 CertTrust.py -a CERTIFICATE.cer -t TrustStore.sqlite3 -y
#    python3 CertTrust.py -a CERTIFICATE.cer -y
#
# Script to manage additional trusted root certificate in the simulator
#
#  For help:
#    python3 CertTrust.py -h
#

import os
import sys
import argparse
import sqlite3
import ssl
import hashlib
import subprocess
import plistlib

import collections
import re
from builtins import bytes
from builtins import int
from builtins import range
from builtins import str
from enum import IntEnum
from numbers import Number

def query_yes_no(question, default="yes"):
    """Ask a yes/no question via input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is one of "yes" or "no".
    """
    valid = {"yes": "yes",   "y": "yes",  "ye": "yes",
             "no": "no",     "n": "no"}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while 1:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return default
        elif choice in valid.keys():
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

#----------------------------------------------------------------------
# This module provides ASN.1 encoder and decoder. [v2.6.0]
#----------------------------------------------------------------------

class Numbers(IntEnum):
    Boolean = 0x01
    Integer = 0x02
    BitString = 0x03
    OctetString = 0x04
    Null = 0x05
    ObjectIdentifier = 0x06
    Enumerated = 0x0a
    UTF8String = 0x0c
    Sequence = 0x10
    Set = 0x11
    PrintableString = 0x13
    IA5String = 0x16
    UTCTime = 0x17
    GeneralizedTime = 0x18
    UnicodeString = 0x1e


class Types(IntEnum):
    Constructed = 0x20
    Primitive = 0x00


class Classes(IntEnum):
    Universal = 0x00
    Application = 0x40
    Context = 0x80
    Private = 0xc0


Tag = collections.namedtuple('Tag', 'nr typ cls')
"""A named tuple to represent ASN.1 tags as returned by `Decoder.peek()` and
`Decoder.read()`."""


class Error(Exception):
    """ASN.11 encoding or decoding error."""


class Encoder(object):
    """ASN.1 encoder. Uses DER encoding.
    """

    def __init__(self):  # type: () -> None
        """Constructor."""
        self.m_stack = None

    def start(self):  # type: () -> None
        """Start encoding.
        This method instructs the encoder to start encoding a new ASN.1
        output. This method may be called at any time to reset the encoder,
        and resets the current output (if any).
        """
        self.m_stack = [[]]

    def enter(self, nr, cls=None):  # type: (int, int) -> None
        """Start a constructed data value.
        This method starts the construction of a constructed type.

        Args:
            nr (int): The desired ASN.1 type. Use ``Numbers`` enumeration.

            cls (int): This optional parameter specifies the class
                of the constructed type. The default class to use is the
                universal class. Use ``Classes`` enumeration.

        Returns:
            None

        Raises:
            `Error`
        """
        if self.m_stack is None:
            raise Error('Encoder not initialized. Call start() first.')
        if cls is None:
            cls = Classes.Universal
        self._emit_tag(nr, Types.Constructed, cls)
        self.m_stack.append([])

    def leave(self):  # type: () -> None
        """Finish a constructed data value.
        This method completes the construction of a constructed type and
        writes the encoded representation to the output buffer.
        """
        if self.m_stack is None:
            raise Error('Encoder not initialized. Call start() first.')
        if len(self.m_stack) == 1:
            raise Error('Tag stack is empty.')
        value = b''.join(self.m_stack[-1])
        del self.m_stack[-1]
        self._emit_length(len(value))
        self._emit(value)

    def write(self, value, nr=None, typ=None, cls=None):  # type: (object, int, int, int) -> None
        """Write a primitive data value.
        This method encodes one ASN.1 tag and writes it to the output buffer.

        Note:
            Normally, ``value`` will be the only parameter to this method.
            In this case Python-ASN1 will autodetect the correct ASN.1 type from
            the type of ``value``, and will output the encoded value based on this
            type.

        Args:
            value (any): The value of the ASN.1 tag to write. Python-ASN1 will
                try to autodetect the correct ASN.1 type from the type of
                ``value``.

            nr (int): If the desired ASN.1 type cannot be autodetected or is
                autodetected wrongly, the ``nr`` parameter can be provided to
                specify the ASN.1 type to be used. Use ``Numbers`` enumeration.

            typ (int): This optional parameter can be used to write constructed
                types to the output by setting it to indicate the constructed
                encoding type. In this case, ``value`` must already be valid ASN.1
                encoded data as plain Python bytes. This is not normally how
                constructed types should be encoded though, see `Encoder.enter()`
                and `Encoder.leave()` for the recommended way of doing this.
                Use ``Types`` enumeration.

            cls (int): This parameter can be used to override the class of the
                ``value``. The default class is the universal class.
                Use ``Classes`` enumeration.

        Returns:
            None

        Raises:
            `Error`
        """
        if self.m_stack is None:
            raise Error('Encoder not initialized. Call start() first.')

        if typ is None:
            typ = Types.Primitive
        if cls is None:
            cls = Classes.Universal

        if cls != Classes.Universal and nr is None:
            raise Error('Please specify a tag number (nr) when using classes Application, Context or Private')

        if nr is None:
            if isinstance(value, bool):
                nr = Numbers.Boolean
            elif isinstance(value, int):
                nr = Numbers.Integer
            elif isinstance(value, str):
                nr = Numbers.PrintableString
            elif isinstance(value, bytes):
                nr = Numbers.OctetString
            elif value is None:
                nr = Numbers.Null

        value = self._encode_value(cls, nr, value)
        self._emit_tag(nr, typ, cls)
        self._emit_length(len(value))
        self._emit(value)

    def output(self):  # type: () -> bytes
        """Return the encoded output.
        This method returns the encoded ASN.1 data as plain Python ``bytes``.
        This method can be called multiple times, also during encoding.
        In the latter case the data that has been encoded so far is
        returned.

        Note:
            It is an error to call this method if the encoder is still
            constructing a constructed type, i.e. if `Encoder.enter()` has been
            called more times that `Encoder.leave()`.

        Returns:
            bytes: The DER encoded ASN.1 data.

        Raises:
            `Error`
        """
        if self.m_stack is None:
            raise Error('Encoder not initialized. Call start() first.')
        if len(self.m_stack) != 1:
            raise Error('Stack is not empty.')
        output = b''.join(self.m_stack[0])
        return output

    def _emit_tag(self, nr, typ, cls):  # type: (int, int, int) -> None
        """Emit a tag."""
        if nr < 31:
            self._emit_tag_short(nr, typ, cls)
        else:
            self._emit_tag_long(nr, typ, cls)

    def _emit_tag_short(self, nr, typ, cls):  # type: (int, int, int) -> None
        """Emit a short (< 31 bytes) tag."""
        assert nr < 31
        self._emit(bytes([nr | typ | cls]))

    def _emit_tag_long(self, nr, typ, cls):  # type: (int, int, int) -> None
        """Emit a long (>= 31 bytes) tag."""
        head = bytes([typ | cls | 0x1f])
        self._emit(head)
        values = [(nr & 0x7f)]
        nr >>= 7
        while nr:
            values.append((nr & 0x7f) | 0x80)
            nr >>= 7
        values.reverse()
        for val in values:
            self._emit(bytes([val]))

    def _emit_length(self, length):  # type: (int) -> None
        """Emit length octects."""
        if length < 128:
            self._emit_length_short(length)
        else:
            self._emit_length_long(length)

    def _emit_length_short(self, length):  # type: (int) -> None
        """Emit the short length form (< 128 octets)."""
        assert length < 128
        self._emit(bytes([length]))

    def _emit_length_long(self, length):  # type: (int) -> None
        """Emit the long length form (>= 128 octets)."""
        values = []
        while length:
            values.append(length & 0xff)
            length >>= 8
        values.reverse()
        # really for correctness as this should not happen anytime soon
        assert len(values) < 127
        head = bytes([0x80 | len(values)])
        self._emit(head)
        for val in values:
            self._emit(bytes([val]))

    def _emit(self, s):  # type: (bytes) -> None
        """Emit raw bytes."""
        assert isinstance(s, bytes)
        self.m_stack[-1].append(s)

    def _encode_value(self, cls, nr, value):  # type: (int, int, any) -> bytes
        """Encode a value."""
        if cls != Classes.Universal:
            return value
        if nr in (Numbers.Integer, Numbers.Enumerated):
            return self._encode_integer(value)
        if nr in (Numbers.OctetString, Numbers.PrintableString,
                  Numbers.UTF8String, Numbers.IA5String,
                  Numbers.UnicodeString, Numbers.UTCTime,
                  Numbers.GeneralizedTime):
            return self._encode_octet_string(value)
        if nr == Numbers.BitString:
            return self._encode_bit_string(value)
        if nr == Numbers.Boolean:
            return self._encode_boolean(value)
        if nr == Numbers.Null:
            return self._encode_null()
        if nr == Numbers.ObjectIdentifier:
            return self._encode_object_identifier(value)
        return value

    @staticmethod
    def _encode_boolean(value):  # type: (bool) -> bytes
        """Encode a boolean."""
        return value and bytes(b'\xff') or bytes(b'\x00')

    @staticmethod
    def _encode_integer(value):  # type: (int) -> bytes
        """Encode an integer."""
        if value < 0:
            value = -value
            negative = True
            limit = 0x80
        else:
            negative = False
            limit = 0x7f
        values = []
        while value > limit:
            values.append(value & 0xff)
            value >>= 8
        values.append(value & 0xff)
        if negative:
            # create two's complement
            for i in range(len(values)):  # Invert bits
                values[i] = 0xff - values[i]
            for i in range(len(values)):  # Add 1
                values[i] += 1
                if values[i] <= 0xff:
                    break
                assert i != len(values) - 1
                values[i] = 0x00
        if negative and values[len(values) - 1] == 0x7f:  # Two's complement corner case
            values.append(0xff)
        values.reverse()
        return bytes(values)

    @staticmethod
    def _encode_octet_string(value):  # type: (object) -> bytes
        """Encode an octetstring."""
        # Use the primitive encoding
        assert isinstance(value, str) or isinstance(value, bytes)
        if isinstance(value, str):
            return value.encode('utf-8')
        else:
            return value

    @staticmethod
    def _encode_bit_string(value):  # type: (object) -> bytes
        """Encode a bitstring. Assumes no unused bytes."""
        # Use the primitive encoding
        assert isinstance(value, bytes)
        return b'\x00' + value

    @staticmethod
    def _encode_null():  # type: () -> bytes
        """Encode a Null value."""
        return bytes(b'')

    _re_oid = re.compile(r'^[0-9]+(\.[0-9]+)+$')

    def _encode_object_identifier(self, oid):  # type: (str) -> bytes
        """Encode an object identifier."""
        if not self._re_oid.match(oid):
            raise Error('Illegal object identifier')
        cmps = list(map(int, oid.split('.')))
        if cmps[0] > 39 or cmps[1] > 39:
            raise Error('Illegal object identifier')
        cmps = [40 * cmps[0] + cmps[1]] + cmps[2:]
        cmps.reverse()
        result = []
        for cmp_data in cmps:
            result.append(cmp_data & 0x7f)
            while cmp_data > 0x7f:
                cmp_data >>= 7
                result.append(0x80 | (cmp_data & 0x7f))
        result.reverse()
        return bytes(result)


class Decoder(object):
    """ASN.1 decoder. Understands BER (and DER which is a subset).
    """

    def __init__(self):  # type: () -> None
        """Constructor."""
        self.m_stack = None
        self.m_tag = None

    def start(self, data):  # type: (bytes) -> None
        """Start processing ``data``.
        This method instructs the decoder to start decoding the ASN.1 input
        ``data``, which must be a passed in as plain Python bytes.
        This method may be called at any time to start a new decoding job.
        If this method is called while currently decoding another input, that
        decoding context is discarded.

        Note:
            It is not necessary to specify the encoding because the decoder
            assumes the input is in BER or DER format.

        Args:
            data (bytes): ASN.1 input, in BER or DER format, to be decoded.

        Returns:
            None

        Raises:
            `Error`
        """
        if not isinstance(data, bytes):
            raise Error('Expecting bytes instance.')
        self.m_stack = [[0, bytes(data)]]
        self.m_tag = None

    def peek(self):  # type: () -> Tag
        """Return the value of the next tag without moving to the next
        TLV record.
        This method returns the current ASN.1 tag (i.e. the tag that a
        subsequent `Decoder.read()` call would return) without updating the
        decoding offset. In case no more data is available from the input,
        this method returns ``None`` to signal end-of-file.

        This method is useful if you don't know whether the next tag will be a
        primitive or a constructed tag. Depending on the return value of `peek`,
        you would decide to either issue a `Decoder.read()` in case of a primitive
        type, or an `Decoder.enter()` in case of a constructed type.

        Note:
            Because this method does not advance the current offset in the input,
            calling it multiple times in a row will return the same value for all
            calls.

        Returns:
            `Tag`: The current ASN.1 tag.

        Raises:
            `Error`
        """
        if self.m_stack is None:
            raise Error('No input selected. Call start() first.')
        if self._end_of_input():
            return None
        if self.m_tag is None:
            self.m_tag = self._read_tag()
        return self.m_tag

    def read(self, tagnr=None):  # type: (Number) -> tuple(Tag, any)
        """Read a simple value and move to the next TLV record.
        This method decodes one ASN.1 tag from the input and returns it as a
        ``(tag, value)`` tuple. ``tag`` is a 3-tuple ``(nr, typ, cls)``,
        while ``value`` is a Python object representing the ASN.1 value.
        The offset in the input is increased so that the next `Decoder.read()`
        call will return the next tag. In case no more data is available from
        the input, this method returns ``None`` to signal end-of-file.

        Returns:
            `Tag`, value: The current ASN.1 tag and its value.

        Raises:
            `Error`
        """
        if self.m_stack is None:
            raise Error('No input selected. Call start() first.')
        if self._end_of_input():
            return None
        tag = self.peek()
        length = self._read_length()
        if tagnr is None:
            tagnr = tag.nr
        value = self._read_value(tag.cls, tagnr, length)
        self.m_tag = None
        return tag, value

    def eof(self):  # type: () -> bool
        """Return True if we are at the end of input.

        Returns:
            bool: True if all input has been decoded, and False otherwise.
        """
        return self._end_of_input()

    def enter(self):  # type: () -> None
        """Enter a constructed tag.
        This method enters the constructed type that is at the current
        decoding offset.

        Note:
            It is an error to call `Decoder.enter()` if the to be decoded ASN.1 tag
            is not of a constructed type.

        Returns:
            None
        """
        if self.m_stack is None:
            raise Error('No input selected. Call start() first.')
        tag = self.peek()
        if tag.typ != Types.Constructed:
            raise Error('Cannot enter a non-constructed tag.')
        length = self._read_length()
        bytes_data = self._read_bytes(length)
        self.m_stack.append([0, bytes_data])
        self.m_tag = None

    def leave(self):  # type: () -> None
        """Leave the last entered constructed tag.
        This method leaves the last constructed type that was
        `Decoder.enter()`-ed.

        Note:
            It is an error to call `Decoder.leave()` if the current ASN.1 tag
            is not of a constructed type.

        Returns:
            None
        """
        if self.m_stack is None:
            raise Error('No input selected. Call start() first.')
        if len(self.m_stack) == 1:
            raise Error('Tag stack is empty.')
        del self.m_stack[-1]
        self.m_tag = None

    def _read_tag(self):  # type: () -> Tag
        """Read a tag from the input."""
        byte = self._read_byte()
        cls = byte & 0xc0
        typ = byte & 0x20
        nr = byte & 0x1f
        if nr == 0x1f:  # Long form of tag encoding
            nr = 0
            while True:
                byte = self._read_byte()
                nr = (nr << 7) | (byte & 0x7f)
                if not byte & 0x80:
                    break
        return Tag(nr=nr, typ=typ, cls=cls)

    def _read_length(self):  # type: () -> int
        """Read a length from the input."""
        byte = self._read_byte()
        if byte & 0x80:
            count = byte & 0x7f
            if count == 0x7f:
                raise Error('ASN1 syntax error')
            bytes_data = self._read_bytes(count)
            length = 0
            for byte in bytes_data:
                length = (length << 8) | int(byte)
            try:
                length = int(length)
            except OverflowError:
                pass
        else:
            length = byte
        return length

    def _read_value(self, cls, nr, length):  # type: (int, int, int) -> any
        """Read a value from the input."""
        bytes_data = self._read_bytes(length)
        if cls != Classes.Universal:
            value = bytes_data
        elif nr == Numbers.Boolean:
            value = self._decode_boolean(bytes_data)
        elif nr in (Numbers.Integer, Numbers.Enumerated):
            value = self._decode_integer(bytes_data)
        elif nr == Numbers.OctetString:
            value = self._decode_octet_string(bytes_data)
        elif nr == Numbers.Null:
            value = self._decode_null(bytes_data)
        elif nr == Numbers.ObjectIdentifier:
            value = self._decode_object_identifier(bytes_data)
        elif nr in (Numbers.PrintableString, Numbers.IA5String,
                    Numbers.UTF8String, Numbers.UTCTime,
                    Numbers.GeneralizedTime):
            value = self._decode_printable_string(bytes_data)
        elif nr == Numbers.BitString:
            value = self._decode_bitstring(bytes_data)
        else:
            value = bytes_data
        return value

    def _read_byte(self):  # type: () -> int
        """Return the next input byte, or raise an error on end-of-input."""
        index, input_data = self.m_stack[-1]
        try:
            byte = input_data[index]
        except IndexError:
            raise Error('Premature end of input.')
        self.m_stack[-1][0] += 1
        return byte

    def _read_bytes(self, count):  # type: (int) -> bytes
        """Return the next ``count`` bytes of input. Raise error on
        end-of-input."""
        index, input_data = self.m_stack[-1]
        bytes_data = input_data[index:index + count]
        if len(bytes_data) != count:
            raise Error('Premature end of input.')
        self.m_stack[-1][0] += count
        return bytes_data

    def _end_of_input(self):  # type: () -> bool
        """Return True if we are at the end of input."""
        index, input_data = self.m_stack[-1]
        assert not index > len(input_data)
        return index == len(input_data)

    @staticmethod
    def _decode_boolean(bytes_data):  # type: (bytes) -> bool
        """Decode a boolean value."""
        if len(bytes_data) != 1:
            raise Error('ASN1 syntax error')
        if bytes_data[0] == 0:
            return False
        return True

    @staticmethod
    def _decode_integer(bytes_data):  # type: (bytes) -> int
        """Decode an integer value."""
        values = [int(b) for b in bytes_data]
        # check if the integer is normalized
        if len(values) > 1 and (values[0] == 0xff and values[1] & 0x80 or values[0] == 0x00 and not (values[1] & 0x80)):
            raise Error('ASN1 syntax error')
        negative = values[0] & 0x80
        if negative:
            # make positive by taking two's complement
            for i in range(len(values)):
                values[i] = 0xff - values[i]
            for i in range(len(values) - 1, -1, -1):
                values[i] += 1
                if values[i] <= 0xff:
                    break
                assert i > 0
                values[i] = 0x00
        value = 0
        for val in values:
            value = (value << 8) | val
        if negative:
            value = -value
        try:
            value = int(value)
        except OverflowError:
            pass
        return value

    @staticmethod
    def _decode_octet_string(bytes_data):  # type: (bytes) -> bytes
        """Decode an octet string."""
        return bytes_data

    @staticmethod
    def _decode_null(bytes_data):  # type: (bytes) -> any
        """Decode a Null value."""
        if len(bytes_data) != 0:
            raise Error('ASN1 syntax error')
        return None

    @staticmethod
    def _decode_object_identifier(bytes_data):  # type: (bytes) -> str
        """Decode an object identifier."""
        result = []
        value = 0
        for i in range(len(bytes_data)):
            byte = int(bytes_data[i])
            if value == 0 and byte == 0x80:
                raise Error('ASN1 syntax error')
            value = (value << 7) | (byte & 0x7f)
            if not byte & 0x80:
                result.append(value)
                value = 0
        if len(result) == 0 or result[0] > 1599:
            raise Error('ASN1 syntax error')
        result = [result[0] // 40, result[0] % 40] + result[1:]
        result = list(map(str, result))
        return str('.'.join(result))

    @staticmethod
    def _decode_printable_string(bytes_data):  # type: (bytes) -> str
        """Decode a printable string."""
        return bytes_data.decode('utf-8')

    @staticmethod
    def _decode_bitstring(bytes_data):  # type: (bytes) -> str
        """Decode a bitstring."""
        if len(bytes_data) == 0:
            raise Error('ASN1 syntax error')

        num_unused_bits = bytes_data[0]
        if not (0 <= num_unused_bits <= 7):
            raise Error('ASN1 syntax error')

        if num_unused_bits == 0:
            return bytes_data[1:]

        # Shift off unused bits
        remaining = bytearray(bytes_data[1:])
        bitmask = (1 << num_unused_bits) - 1
        removed_bits = 0

        for i in range(len(remaining)):
            byte = int(remaining[i])
            remaining[i] = (byte >> num_unused_bits) | (removed_bits << num_unused_bits)
            removed_bits = byte & bitmask

        return bytes(remaining)

#----------------------------------------------------------------------
# Certificate class
#----------------------------------------------------------------------

class Certificate:
    """Represents a loaded certificate
    """
    def __init__(self):
        self._init_data()

    def _init_data(self):
        self._data = None
        self._subject = None
        self._filepath = None

    def load_PEMfile(self, certificate_path):
        """Load a certificate from a file in PEM format
        """
        self._init_data()
        self._filepath = certificate_path
        with open(self._filepath, "r") as inputFile:
            PEMdata = inputFile.read()
        # convert to binary (DER format)
        self._data = ssl.PEM_cert_to_DER_cert(PEMdata)

    def save_PEMfile(self, certificate_path):
        """Save a certificate to a file in PEM format
        """
        self._filepath = certificate_path
        # convert to text (PEM format)
        PEMdata = ssl.DER_cert_to_PEM_cert(self._data)
        with open(self._filepath, "w") as output_file:
            output_file.write(PEMdata)

    def load_data(self, data):
        self._init_data()
        self._data = data

    def get_data(self):
        return self._data

    def get_fingerprint(self, hash):
        if self._data is None:
            return
        sha = hashlib.sha1() if hash == 'sha1' else hashlib.sha256()
        sha.update(self._data)
        return sha.digest()

    def get_subject(self):
        """Get the certificate subject in human readable one line format
        """
        if self._data != None:
            # use openssl to extract the subject text in single line format
            possl = subprocess.Popen(['openssl',  'x509', '-inform',  'DER',  '-noout',  '-subject', '-nameopt', 'oneline'],
                shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None)
            subjectText, error_text = possl.communicate(self.get_data())
            return subjectText
        return None

    def get_subject_ASN1(self):
        """Get the certificate subject in ASN1 encoded format as expected for the trusted certificate keychain store
        """
        if self._subject == None and self._data != None:
            self._subject = bytearray()
            decoder = Decoder()
            decoder.start(self._data) # Start.
            decoder.enter()
            decoder.enter()
            tag, value = decoder.read()  # read version
            tag, value = decoder.read()  # serial
            tag, value = decoder.read()
            tag, value = decoder.read()  # issuer
            tag, value = decoder.read()  # date
            decoder.enter()  # enter in subject
            encoder = Encoder()
            encoder.start()
            self._process_subject(decoder, encoder)
            self._subject = encoder.output()
            #print("ASN1 Subject:")
            #print(self._subject.decode('utf-8'))
        return self._subject

    def _process_subject(self, input, output, indent=0):
        # trace = sys.stdout
        while not input.eof():
            tag = input.peek()
            if tag[1] == Types.Primitive:
                tag, value = input.read()
                if tag[0] == Numbers.PrintableString:
                    value = value.upper()
                output.write(value, tag[0], tag[1], tag[2])
                #trace.write(' ' * indent)
                #trace.write('[%s] %s (value %s)' %
                #         (strclass(tag[2]), strid(tag[0]), repr(value)))
                #trace.write('\n')
            elif tag[1] == Types.Constructed:
                #trace.write(' ' * indent)
                #trace.write('[%s] %s:\n' % (strclass(tag[2]), strid(tag[0])))
                input.enter()
                output.enter(tag[0], tag[2])
                self._process_subject(input, output, indent+2)
                output.leave()
                input.leave()

#----------------------------------------------------------------------
# TrustStore.sqlite3 handling
#----------------------------------------------------------------------

class TrustStore:
    """Represents the trusted certificate store
    """
    def __init__(self, path, title=None, always_yes=False):
        self._path = path
        self._hash = None
        self.always_yes = always_yes
        if title:
            self._title = title
        else:
            self._title = path
        self._tset = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"\
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"\
            "<plist version=\"1.0\">\n"\
            "<array/>\n"\
            "</plist>\n"

        #self._tset = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"\
        #    b"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"\
        #    b"<plist version=\"1.0\">\n"\
        #    b"<array/>\n"\
        #    b"</plist>\n"

        #with open('cert_tset.plist', "rb") as inputFile:
        #    self._tset = inputFile.read()

    def is_valid(self):
        conn = sqlite3.connect(self._path)
        c = conn.cursor()
        row = c.execute('SELECT count(*) FROM sqlite_master WHERE type=\'table\' AND name=\'tsettings\'').fetchone()
        if row[0] == 0:
            conn.close()
            return False
        c = conn.cursor()
        row = c.execute('SELECT sql FROM sqlite_master WHERE name=\'tsettings\'').fetchone()
        self._hash = 'sha256' if 'sha256' in row[0] else 'sha1'
        conn.close()
        return True

    def _add_record(self, sha, subj, tset, data):
        if not self.is_valid():
            print("  Invalid TrustStore.sqlite3")
            return
        conn = sqlite3.connect(self._path)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM tsettings WHERE subj=?', [sqlite3.Binary(subj)])
        row = c.fetchone()
        if row[0] == 0:
            c.execute('INSERT INTO tsettings (' + self._hash + ', subj, tset, data) VALUES (?, ?, ?, ?)', [sqlite3.Binary(sha), sqlite3.Binary(subj), sqlite3.Binary(tset), sqlite3.Binary(data)])
            print('  Certificate added')
        else:
            c.execute('UPDATE tsettings SET ' + self._hash + '=?, tset=?, data=? WHERE subj=?', [sqlite3.Binary(sha), sqlite3.Binary(tset), sqlite3.Binary(data), sqlite3.Binary(subj)])
            print('  Existing certificate replaced')
        conn.commit()
        conn.close()

    def _loadBlob(self, baseName, name):
        with open(baseName + '_' + name + '.bin', 'rb') as inputFile:
            return inputFile.read()

    def _saveBlob(self, baseName, name, data):
        with open(baseName + '_' + name + '.bin', 'wb') as outputFile:
            outputFile.write(data)

    def add_certificate(self, certificate):
        # this also populates self._hash
        if not self.is_valid():
            print("  Invalid TrustStore.sqlite3")
            return
        self._add_record(certificate.get_fingerprint(self._hash), certificate.get_subject_ASN1(),
            self._tset.encode(), certificate.get_data())

    def export_certificates(self, base_filename):
        if not self.is_valid():
            print("  Invalid TrustStore.sqlite3")
            return
        conn = sqlite3.connect(self._path)
        c = conn.cursor()
        index = 1
        print
        print(self._title)
        for row in c.execute('SELECT subj, data FROM tsettings'):
            cert = Certificate()
            cert.load_data(row[1])
            if self.always_yes or query_yes_no("  " + cert.get_subject() + "    Export certificate", "no") == "yes":
                cert.save_PEMfile(base_filename + "_" + str(index) + ".crt")
                index = index + 1
        conn.close()

    def export_certificates_data(self, base_filename):
        if not self.is_valid():
            print("  Invalid TrustStore.sqlite3")
            return
        conn = sqlite3.connect(self._path)
        c = conn.cursor()
        index = 1
        for row in c.execute('SELECT subj, tset, data FROM tsettings'):
            cert = Certificate()
            cert.load_data(row[2])
            if self.always_yes or query_yes_no("  " + cert.get_subject() + "    Export certificate", "no") == "yes":
                base_filename2 = base_filename + "_" + str(index)
                self._saveBlob(base_filename2, 'subj', row[0])
                self._saveBlob(base_filename2, 'tset', row[1])
                self._saveBlob(base_filename2, 'data', row[2])
        conn.close()

    def import_certificate_data(self, base_filename):
        # this also populates self._hash
        if not self.is_valid():
            print("  Invalid TrustStore.sqlite3")
            return
        certificateSubject = self._loadBlob(base_filename, 'subj')
        certificateTSet = self._loadBlob(base_filename, 'tset')
        certificateData = self._loadBlob(base_filename, 'data')
        cert = Certificate()
        cert.load_data(certificateData)
        certificateSha = cert.get_fingerprint(self._hash)

        self._add_record(certificateSha, certificateSubject, certificateTSet, certificateData)

    def list_certificates(self):
        print("\nCertificates in:")
        print(self._title)
        if not self.is_valid():
            print("  Invalid TrustStore.sqlite3")
            return
        conn = sqlite3.connect(self._path)
        c = conn.cursor()
        for row in c.execute('SELECT data FROM tsettings'):
            cert = Certificate()
            cert.load_data(row[0])
            result = cert.get_subject().decode('utf-8')
            print("  " + result)
        conn.close()

    def delete_certificates(self): # Warning: Does not delete all references.
        print("\nCertificates in:")
        if not self.is_valid():
            print("  Invalid TrustStore.sqlite3")
            return
        conn = sqlite3.connect(self._path)
        c = conn.cursor()
        print
        print(self._title)
        todelete = []
        for row in c.execute('SELECT subj, data FROM tsettings'):
            cert = Certificate()
            cert.load_data(row[1])
            result = cert.get_subject().decode('utf-8')
            if self.always_yes or query_yes_no("  " + result + "    Delete certificate", "no") == "yes":
                todelete.append(row[0])
        for item in todelete:
            c.execute('DELETE FROM tsettings WHERE subj=?', [item])
        conn.commit()
        conn.close()

#----------------------------------------------------------------------
# Simulator access
#----------------------------------------------------------------------

class Simulator:
    """Represents an instance of an simulator folder.
    """
    simulatorDir = os.getenv('HOME') + "/Library/Developer/CoreSimulator/Devices/"
    trustStorePaths = [
        "/data/private/var/protected/trustd/private/TrustStore.sqlite3",
        #"/data/Library/Keychains/TrustStore.sqlite3",
    ]
    runtimeName = "com.apple.CoreSimulator.SimRuntime."

    def __init__(self, simulatordir):
        self._is_valid = False
        infofile = simulatordir + "/device.plist"
        if os.path.isfile(infofile):
            with open(infofile, "rb") as file:
                info = plistlib.load(file)
                # print(info)
                runtime = info["runtime"]
                if runtime.startswith(self.runtimeName):
                    self.version = (runtime[len(self.runtimeName):].replace("-", ".")).replace("OS.", "OS ")
                else:
                    self.version = runtime
                self.title = info["name"] + " " + self.version
                for path in self.trustStorePaths:
                    self.truststore_file = simulatordir + path
                    if os.path.isfile(self.truststore_file):
                        self._is_valid = True
                        return

    def is_valid(self):
        return self._is_valid

def simulators():
    """An iterator over the available simulator versions.
    """
    for subdir in os.listdir(Simulator.simulatorDir):
        simulatordir = Simulator.simulatorDir + subdir
        if os.path.isdir(simulatordir):
            simulator = Simulator(simulatordir)
            if simulator.is_valid():
                yield simulator

#----------------------------------------------------------------------
# Device backup support
#----------------------------------------------------------------------

class DeviceBackup:
    """Represents an instance of an simulator folder
    """
    trustStore_filename = "61c8b15a0110ab17d1b7467c3a042eb1458426c6"

    def __init__(self, path):
        self._path = path
        self._isvalid = False
        info_plist = self._path + "/Info.plist"
        if os.path.isfile(info_plist):
            try:
                info = plistlib.readPlist(info_plist)
                self.device_name = info["Device Name"]
                self.title = "Backup of " + self.device_name + " - " + str(info["Last Backup Date"])
                self._isvalid = True
            except:
                pass

    def is_valid(self):
        return self._isvalid

    def get_truststore_file(self):
        return self._path + "/" + DeviceBackup.trustStore_filename


def device_backups():
    """An iterator over the available device backups
    """
    base_backupdir = os.getenv('HOME') + "/Library/Application Support/MobileSync/Backup/"
    for backup_dir in os.listdir(base_backupdir):
        backup = DeviceBackup(base_backupdir + backup_dir)
        if backup.is_valid():
            yield backup

#----------------------------------------------------------------------
# Individual command implementation and main function
#----------------------------------------------------------------------

class Program:
    def import_to_simulator(self, certificate_filepath, truststore_filepath=None):
        cert = Certificate()
        cert.load_PEMfile(certificate_filepath)
        print("Attempting to import: ")
        print(cert.get_subject().decode('utf-8'))
        if truststore_filepath:
            if self.always_yes or query_yes_no("Import certificate to " + truststore_filepath, "no") == "yes":
                print("Importing to truststore: " + truststore_filepath)
                tstore = TrustStore(truststore_filepath, always_yes=self.always_yes)
                tstore.add_certificate(cert)
            return
        for simulator in simulators():
            if self.always_yes or query_yes_no("Import certificate to " + simulator.title, "no") == "yes":
                print("Importing to sim: " + simulator.truststore_file)
                tstore = TrustStore(simulator.truststore_file, always_yes=self.always_yes)
                tstore.add_certificate(cert)

    def addfromdump(self, dump_base_filename, truststore_filepath=None):
        if truststore_filepath:
            if self.always_yes or query_yes_no("Import to " + truststore_filepath, "no") == "yes":
                tstore = TrustStore(truststore_filepath, always_yes=self.always_yes)
                tstore.import_certificate_data(dump_base_filename)
            return
        for simulator in simulators():
            if self.always_yes or query_yes_no("Import to " + simulator.title, "no") == "yes":
                print("Importing to " + simulator.truststore_file)
                tstore = TrustStore(simulator.truststore_file, always_yes=self.always_yes)
                tstore.import_certificate_data(dump_base_filename)

    def list_simulator_trustedcertificates(self, truststore_filepath=None):
        if truststore_filepath:
            tstore = TrustStore(truststore_filepath, always_yes=self.always_yes)
            tstore.list_certificates()
            return
        for simulator in simulators():
            tstore = TrustStore(simulator.truststore_file, simulator.title, always_yes=self.always_yes)
            tstore.list_certificates()

    def export_simulator_trustedcertificates(self, certificate_base_filename, mode_dump, truststore_filepath=None):
        if truststore_filepath:
            tstore = TrustStore(truststore_filepath, always_yes=self.always_yes)
            if mode_dump:
                tstore.export_certificates_data(certificate_base_filename)
            else:
                tstore.export_certificates(certificate_base_filename)
            return
        for simulator in simulators():
            tstore = TrustStore(simulator.truststore_file, simulator.title, always_yes=self.always_yes)
            if mode_dump:
                tstore.export_certificates_data(certificate_base_filename + "_" + simulator.version)
            else:
                tstore.export_certificates(certificate_base_filename + "_" + simulator.version)

    def delete_simulator_trustedcertificates(self, truststore_filepath=None):
        if truststore_filepath:
            tstore = TrustStore(truststore_filepath, always_yes=self.always_yes)
            tstore.delete_certificates()
            return
        for simulator in simulators():
            tstore = TrustStore(simulator.truststore_file, simulator.title, always_yes=self.always_yes)
            tstore.delete_certificates()

    def list_device_trustedcertificates(self):
        for backup in device_backups():
            tstore = TrustStore(backup.get_truststore_file(), backup.title, always_yes=self.always_yes)
            tstore.list_certificates()

    def export_device_trustedcertificates(self, certificate_base_filename, mode_dump):
        for backup in device_backups():
            tstore = TrustStore(backup.get_truststore_file(), backup.title, always_yes=self.always_yes)
            if mode_dump:
                tstore.export_certificates_data(certificate_base_filename + "_" + backup.device_name)
            else:
                tstore.export_certificates(certificate_base_filename + "_" + backup.device_name)

    def run(self):
        parser = argparse.ArgumentParser()
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-l", "--list", help="list custom trusted certificates in simulator", action="store_true")
        group.add_argument("-d", "--delete", help="delete custom trusted certificates in simulator", action="store_true")
        group.add_argument("-a", "--add", help="specifies a certificate file in PEM format to import and add to the simulator trusted list", dest='certificate_file')
        group.add_argument("-e", "--export", help="export custom trusted certificates from simulator in PEM format. ", dest='export_base_filename')
        group.add_argument("--dump", help="dump custom trusted certificates records from simulator. ", dest='dump_base_filename')
        group.add_argument("--addfromdump", help="add custom trusted certificates records to simulator from dump file created with --dump. ", dest='adddump_base_filename')
        parser.add_argument("-t", "--truststore", help="specify the path of the TrustStore.sqlite3 file to edit. The default is to select and prompt for each available version")
        parser.add_argument("-b", "--devicebackup", help="(experimental) select a device backup as the TrustStore.sqlite3 source for list or export", action="store_true")
        parser.add_argument("-y", "--yes", help="always answer yes to prompts", action="store_true")
        args = parser.parse_args()
        if args.yes:
            self.always_yes = True
        else:
            self.always_yes = False
        if args.truststore and not os.path.isfile(args.truststore):
            print("invalid file: " + args.truststore)
            exit(1)
        if args.devicebackup:
            if args.list:
                self.list_device_trustedcertificates()
            elif args.export_base_filename:
                self.export_device_trustedcertificates(args.export_base_filename, False)
            elif args.dump_base_filename:
                self.export_device_trustedcertificates(args.dump_base_filename, True)
            else:
                print("option not supported")
        elif args.list:
            self.list_simulator_trustedcertificates(args.truststore)
        elif args.delete:
            self.delete_simulator_trustedcertificates(args.truststore)
        elif args.certificate_file:
            self.import_to_simulator(args.certificate_file, args.truststore)
        elif args.export_base_filename:
            self.export_simulator_trustedcertificates(args.export_base_filename, False, args.truststore)
        elif args.dump_base_filename:
            self.export_simulator_trustedcertificates(args.dump_base_filename, True, args.truststore)
        elif args.adddump_base_filename:
            self.addfromdump(args.adddump_base_filename, args.truststore)
        print

if __name__ == "__main__":
    program = Program()
    program.run()
