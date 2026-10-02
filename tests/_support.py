"""Small helpers for source-level checks in the public test bundle."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _strip_c_comments(source):
    result = []
    state = "code"
    escaped = False
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""

        if state == "code":
            if char == '"':
                state = "string"
                result.append(char)
            elif char == "'":
                state = "character"
                result.append(char)
            elif char == "/" and following == "/":
                state = "line-comment"
                result.extend((" ", " "))
                index += 1
            elif char == "/" and following == "*":
                state = "block-comment"
                result.extend((" ", " "))
                index += 1
            else:
                result.append(char)
        elif state in ("string", "character"):
            result.append(char)
            quote = '"' if state == "string" else "'"
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                state = "code"
        elif state == "line-comment":
            if char == "\n":
                result.append(char)
                state = "code"
            else:
                result.append(" ")
        else:
            if char == "*" and following == "/":
                result.extend((" ", " "))
                index += 1
                state = "code"
            else:
                result.append("\n" if char == "\n" else " ")

        index += 1
    return "".join(result)


def read_c(path):
    return _strip_c_comments(Path(path).read_text(encoding="utf-8"))


def function_body(source, name):
    """Return one C function body, without depending on its line formatting."""
    definition = re.search(
        r"\b" + re.escape(name) + r"\s*\([^{};]*\)\s*\{", source, re.S
    )
    if definition is None:
        raise AssertionError(f"C function definition not found: {name}")

    opening = definition.end() - 1
    depth = 0
    quote = None
    escaped = False
    for index in range(opening, len(source)):
        char = source[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise AssertionError(f"unterminated C function body: {name}")


def call_match(source, name):
    return re.search(r"\b" + re.escape(name) + r"\s*\(", source)
