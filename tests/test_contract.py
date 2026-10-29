"""Enforce the documented read-only process contract and public code quality."""

import ast
from pathlib import Path


def test_no_process_control_or_keyboard_calls() -> None:
    """Detection code must never call key state, injection, or process-control APIs."""
    forbidden = {"terminate", "kill", "suspend", "resume", "send_signal", "SetWindowsHookExA",
                 "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
                 "RegisterRawInputDevices", "GetRawInputData", "WriteProcessMemory",
                 "CreateRemoteThread", "VirtualAllocEx", "SendInput"}
    package = Path(__file__).resolve().parents[1] / "keyguard"
    for path in package.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else ""
                assert name not in forbidden, f"Forbidden call {name} in {path}"


def test_function_annotations_and_docstrings() -> None:
    """Every named production function has a docstring and complete type annotations."""
    package = Path(__file__).resolve().parents[1] / "keyguard"
    for path in package.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assert ast.get_docstring(node), f"Missing docstring: {path}:{node.name}"
                assert node.returns is not None, f"Missing return type: {path}:{node.name}"
                for argument in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                    assert argument.arg in {"self", "cls"} or argument.annotation is not None, f"Missing argument type: {path}:{node.name}"
