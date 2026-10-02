#!/usr/bin/env python3
"""Run the portable BBP Proxy tests; no external test framework."""

import importlib.util
import sys
from pathlib import Path


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR))
TEST_FILES = (
    "test_kernel_redirect_scope.py",
    "test_relay_message.py",
    "test_secure_transport.py",
    "test_public_menu_scope.py",
    "test_public_menu_behavior.py",
    "test_minisoc_lifecycle.py",
    "test_relay_integration.py",
    "test_uds_ipc_validation.py",
    "test_uds_service.py",
)


def main():
    passed = 0
    for filename in TEST_FILES:
        path = TEST_DIR / filename
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        tests = [
            (name, value)
            for name, value in vars(module).items()
            if name.startswith("test_") and callable(value)
        ]
        if not tests:
            raise RuntimeError(f"no tests found in {filename}")
        for name, test in tests:
            test()
            passed += 1
            print(f"PASS {filename}::{name}", flush=True)
    print(f"{passed} tests passed")


if __name__ == "__main__":
    main()
