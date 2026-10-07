import ctypes
import struct
import subprocess
import tempfile
from pathlib import Path

from _support import ROOT


SOURCE = ROOT / "sysmodules/rosalina/source/bbp_relay_message.c"
INCLUDE = ROOT / "sysmodules/rosalina/include"


def test_status_query_capability_and_full_u16_reply():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "libbbp-status.so"
        subprocess.run(["cc", "-shared", "-fPIC", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-I", str(INCLUDE), str(SOURCE), "-o", str(path)], check=True)
        codec = ctypes.CDLL(str(path))
        codec.udsRelayV3BodyValidate.argtypes = [ctypes.c_uint8, ctypes.c_uint8,
                                               ctypes.c_void_p, ctypes.c_uint16]
        codec.udsRelayV3BodyValidate.restype = ctypes.c_bool
        for online in (65, 4097, 65535):
            body = b"12345678" + struct.pack("<HH5B3x", online, online, 0, 1, 2, 3, 4)
            assert codec.udsRelayV3BodyValidate(0x14, 0, body, 20)
        invalid = b"12345678" + struct.pack("<HH5B3x", 64, 65, 0, 0, 0, 0, 0)
        assert not codec.udsRelayV3BodyValidate(0x14, 0, invalid, 20)
        codec.udsRelayV3StatusQueryPrepare.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        codec.udsRelayV3StatusQueryPrepare.restype = ctypes.c_bool
        body = ctypes.create_string_buffer(20)
        assert codec.udsRelayV3StatusQueryPrepare(body, b"12345678")
        assert body.raw == b"12345678\x01\x01\x00" + bytes(9)
        assert codec.udsRelayV3BodyValidate(0x13, 0, body, 20)
        assert codec.udsRelayV3BodyValidate(0x13, 0, b"12345678" + bytes(12), 20)
        assert not codec.udsRelayV3StatusQueryPrepare(body, bytes(8))
        assert not codec.udsRelayV3StatusQueryPrepare(None, b"12345678")


class Header(ctypes.Structure):
    _fields_ = [
        ("packet_type", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
        ("token", ctypes.c_uint8 * 16),
        ("fragment_id", ctypes.c_uint32),
        ("fragment_index", ctypes.c_uint8),
        ("fragment_count", ctypes.c_uint8),
        ("logical_body_length", ctypes.c_uint16),
    ]


def test_v3_message_header_round_trips_literal_wire_bytes():
    with tempfile.TemporaryDirectory() as directory:
        library_path = Path(directory) / "libbbp-message.so"
        subprocess.run(
            [
                "cc", "-shared", "-fPIC", "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-I", str(INCLUDE), str(SOURCE), "-o", str(library_path),
            ],
            check=True,
        )
        codec = ctypes.CDLL(str(library_path))
        codec.udsRelayV3HeaderDecode.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(Header),
        ]
        codec.udsRelayV3HeaderDecode.restype = ctypes.c_bool
        codec.udsRelayV3HeaderEncode.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(Header),
        ]
        codec.udsRelayV3HeaderEncode.restype = ctypes.c_bool

        wire = bytes.fromhex(
            "5544535003001000"
            "000102030405060708090a0b0c0d0e0f"
            "0000000000011000"
        ) + bytes(16)
        header = Header()
        assert codec.udsRelayV3HeaderDecode(
            ctypes.create_string_buffer(wire), len(wire), ctypes.byref(header)
        )
        assert header.packet_type == 0x10
        assert bytes(header.token) == bytes(range(16))

        encoded = ctypes.create_string_buffer(32)
        assert codec.udsRelayV3HeaderEncode(encoded, len(encoded), ctypes.byref(header))
        assert encoded.raw == wire[:32]


if __name__ == "__main__":
    test_v3_message_header_round_trips_literal_wire_bytes()
