import ctypes
import subprocess
import tempfile
from pathlib import Path

from _support import ROOT


SOURCE = ROOT / "sysmodules/rosalina/source/bbp_relay_message.c"
INCLUDE = ROOT / "sysmodules/rosalina/include"


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
