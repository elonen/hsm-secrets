# ssh_data_types.py

from typing import Union
import struct


class SSHDataType:
    """
    Encoding and decoding OpenSSH data types.
    Reference: https://tools.ietf.org/html/rfc4251#section-5
    """
    @staticmethod
    def encode_byte(data: int) -> bytes:
        return struct.pack('!B', data)

    @staticmethod
    def decode_byte(data: bytes) -> tuple[int, bytes]:
        return struct.unpack('!B', data[:1])[0], data[1:]

    @staticmethod
    def encode_boolean(data: bool) -> bytes:
        return struct.pack('!?', data)

    @staticmethod
    def decode_boolean(data: bytes) -> tuple[bool, bytes]:
        return struct.unpack('!?', data[:1])[0], data[1:]

    @staticmethod
    def encode_uint32(data: int) -> bytes:
        return struct.pack('!I', data)

    @staticmethod
    def decode_uint32(data: bytes) -> tuple[int, bytes]:
        return struct.unpack('!I', data[:4])[0], data[4:]

    @staticmethod
    def encode_uint64(data: int) -> bytes:
        return struct.pack('!Q', data)

    @staticmethod
    def decode_uint64(data: bytes) -> tuple[int, bytes]:
        return struct.unpack('!Q', data[:8])[0], data[8:]

    @staticmethod
    def encode_bytes(data: bytes) -> bytes:
        return SSHDataType.encode_uint32(len(data)) + data

    @staticmethod
    def encode_string(data: str, encoding: str = 'utf-8') -> bytes:
        return SSHDataType.encode_bytes(data.encode(encoding))

    @staticmethod
    def decode_bytes(data: bytes) -> tuple[bytes, bytes]:
        length, data = SSHDataType.decode_uint32(data)
        return data[:length], data[length:]

    @staticmethod
    def decode_string(data: bytes, encoding='ascii') -> tuple[str, bytes]:
        string_bytes, data = SSHDataType.decode_bytes(data)
        return string_bytes.decode(encoding), data

    @staticmethod
    def encode_mpint(data: int) -> bytes:
        """
        Encode an integer as an SSH Multiple Precision Integer (mpint).

        The mpint format is:
        - A 4-byte length field (big-endian) indicating the number of bytes of integer data
        - The integer data itself in two's complement format, big-endian

        Special cases:
        - Zero is encoded as 00 00 00 00 (4 bytes of zero length)
        - Positive numbers with the MSB set have a leading zero byte to distinguish from negative numbers
        - Negative numbers are in two's complement format with no leading 1 bytes beyond the minimum required

        This format allows for arbitrary precision integers of any size.
        """
        if data == 0:
            return b'\x00\x00\x00\x00'

        assert data >= 0, "Negative mpint not supported"

        byte_length = (data.bit_length() + 7) // 8
        byte_data = data.to_bytes(byte_length, byteorder='big', signed=False)

        # Add a leading zero byte if the MSB is set for a positive number
        if byte_data[0] & 0x80:
            byte_data = b'\x00' + byte_data

        return SSHDataType.encode_uint32(len(byte_data)) + byte_data

    @staticmethod
    def decode_mpint(data: bytes) -> tuple[int, bytes]:
        """
        Decode an SSH Multiple Precision Integer (mpint) from the given data.

        :param data: The input data containing the mpint.
        :return: A tuple containing the decoded integer value and the remaining data.
        :raises ValueError: If the input data is invalid or too short.
        """
        length, data = SSHDataType.decode_uint32(data)
        if length == 0:
            return 0, data

        value_bytes = data[:length]
        value = int.from_bytes(value_bytes, byteorder='big', signed=False)

        # Check if it's a negative number
        if value_bytes[0] & 0x80:
            value = value - (1 << (len(value_bytes) * 8))

        return value, data[length:]

    @staticmethod
    def encode_name_list(names: list[str]) -> bytes:
        res = b''
        for n in names:
            res += SSHDataType.encode_string(n, 'ascii')
        return SSHDataType.encode_bytes(res)

    @staticmethod
    def decode_name_list(data: bytes) -> tuple[list[str], bytes]:
        list_data, data = SSHDataType.decode_bytes(data)
        res = []
        while list_data:
            name, list_data = SSHDataType.decode_string(list_data)
            res.append(name)
        return res, data

    @staticmethod
    def encode_options(options: dict[str, bytes]) -> bytes:
        """
        Encode certificate options (critical options or extensions).

        :param options: A dictionary of option names and values.
        :return: The encoded options as bytes.
        """
        encoded = b""
        for name, data in options.items():
            encoded += SSHDataType.encode_string(name, 'ascii')
            encoded += SSHDataType.encode_bytes(data)
        return SSHDataType.encode_bytes(encoded)

    @staticmethod
    def decode_options(data: bytes) -> tuple[dict[str, bytes], bytes]:
        """
        Decode certificate options (critical options or extensions).

        :param data: The bytes to decode.
        :return: A tuple containing the decoded options dictionary and any remaining bytes.
        """
        options_data, data = SSHDataType.decode_bytes(data)
        options = {}

        while options_data:
            name, options_data = SSHDataType.decode_string(options_data)
            value_bytes, options_data = SSHDataType.decode_bytes(options_data)
            options[name] = value_bytes

        return options, data
