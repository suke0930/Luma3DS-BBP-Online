import ctypes
import subprocess
import tempfile
from pathlib import Path

from _support import ROOT


SOURCE = ROOT / "sysmodules/rosalina/source"
INCLUDE = ROOT / "sysmodules/rosalina/include"

# Wire vectors use synthetic test keys.
CLIENT_HELLO = bytes.fromhex(
    "5544535004000100"
    "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
)
COOKIE = bytes.fromhex(
    "55445350040002000200000000000000"
    "9a462b93539dfde30ca524bdb19f901c"
)
CLIENT_RETRY = bytes.fromhex(
    "5544535004000300"
    "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
    "02000000000000009a462b93539dfde30ca524bdb19f901c"
)
SERVER_HELLO = bytes.fromhex(
    "5544535004000400"
    "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b"
    "1f2a59a8bc716648f6d2ab1e2807b2a735bbfba42dd7e823"
)
CLIENT_DATA = bytes.fromhex(
    "554453500400050008070605040302010000000000000000"
    "32f883af9f4ea6f20a1dfa9b27497eb5b658a4c6be8a9a3d96b649c38a33b4fe"
    "7670da668bac26120b2babc6e1a93f"
)
SERVER_RESPONSE = bytes.fromhex(
    "554453500400050008070605040302010000000000000000"
    "574795287d7b476d8fd2bbd697dbf9f3fee35242a50921776f622836cf"
)


def _call(function, state, source=b"", capacity=1240):
    source_buffer = ctypes.create_string_buffer(source) if source else None
    output = ctypes.create_string_buffer(capacity)
    length = ctypes.c_size_t()
    accepted = function(
        state, source_buffer, len(source), output, capacity, ctypes.byref(length)
    )
    return accepted, output.raw[: length.value]


def test_secure_transport_interoperates_with_relay_and_rejects_replay():
    with tempfile.TemporaryDirectory() as directory:
        library_path = Path(directory) / "libbbp-transport.so"
        subprocess.run(
            [
                "cc", "-shared", "-fPIC", "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-DBLAKE2_NO_UNROLLING", "-I", str(INCLUDE),
                str(SOURCE / "bbp_secure_transport.c"),
                str(SOURCE / "monocypher.c"), "-o", str(library_path),
            ],
            check=True,
        )
        codec = ctypes.CDLL(str(library_path))
        codec.udsRelayV4ClientSize.restype = ctypes.c_size_t
        codec.udsRelayV4ClientInit.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        codec.udsRelayV4ClientInit.restype = ctypes.c_bool
        codec.udsRelayV4ClientHello.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        codec.udsRelayV4ClientHello.restype = ctypes.c_bool
        codec.udsRelayV4ClientReady.argtypes = [ctypes.c_void_p]
        codec.udsRelayV4ClientReady.restype = ctypes.c_bool
        for name in (
            "udsRelayV4ClientHandshake",
            "udsRelayV4ClientEncrypt",
            "udsRelayV4ClientDecrypt",
        ):
            function = getattr(codec, name)
            function.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                ctypes.c_void_p, ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_size_t),
            ]
            function.restype = ctypes.c_bool

        state = ctypes.create_string_buffer(codec.udsRelayV4ClientSize())
        client_secret = bytes(range(1, 33))
        assert codec.udsRelayV4ClientInit(
            state, ctypes.create_string_buffer(client_secret)
        )
        hello_buffer = ctypes.create_string_buffer(1240)
        hello_length = ctypes.c_size_t()
        assert codec.udsRelayV4ClientHello(
            state, hello_buffer, len(hello_buffer), ctypes.byref(hello_length)
        )
        assert hello_buffer.raw[: hello_length.value] == CLIENT_HELLO

        accepted, retry = _call(codec.udsRelayV4ClientHandshake, state, COOKIE)
        assert accepted and retry == CLIENT_RETRY

        accepted, reply = _call(codec.udsRelayV4ClientHandshake, state, SERVER_HELLO)
        assert accepted and reply == b"" and codec.udsRelayV4ClientReady(state)

        message = b"authenticated BBP relay payload"
        accepted, encrypted = _call(codec.udsRelayV4ClientEncrypt, state, message)
        assert accepted and encrypted == CLIENT_DATA
        assert message not in encrypted

        accepted, plaintext = _call(
            codec.udsRelayV4ClientDecrypt, state, SERVER_RESPONSE
        )
        assert accepted and plaintext == b"peer response"
        accepted, plaintext = _call(
            codec.udsRelayV4ClientDecrypt, state, SERVER_RESPONSE
        )
        assert not accepted and plaintext == b""


if __name__ == "__main__":
    test_secure_transport_interoperates_with_relay_and_rejects_replay()
