"""Static PE import analysis; never load or execute a target executable."""

from pathlib import Path

import pefile

from keyguard.models import Detection, Finding

KEYBOARD_APIS = frozenset({
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
    "GetKeyboardState", "RegisterRawInputDevices", "GetRawInputData",
})


def analyze_imports(path: str, max_bytes: int) -> Detection:
    """Inspect normal and delay imports, bounding PE file size and closing handles."""
    result = Detection(data={"keyboard_apis": []})
    pe = None
    try:
        if Path(path).stat().st_size > max_bytes:
            result.issues.append(f"Import analysis skipped: file exceeds {max_bytes} bytes")
            return result
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        ])
        imports: set[str] = set()
        for attribute in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for descriptor in getattr(pe, attribute, []):
                for entry in descriptor.imports:
                    if entry.name:
                        name = entry.name.decode("ascii", errors="replace")
                        if name in KEYBOARD_APIS:
                            imports.add(name)
        result.data["keyboard_apis"] = sorted(imports)
        if imports:
            result.findings.append(Finding("keyboard_imports", "imports",
                                           "Imports " + ", ".join(sorted(imports))))
    except (OSError, pefile.PEFormatError, ValueError, OverflowError) as exc:
        result.issues.append(f"Import analysis unavailable: {exc}")
    finally:
        if pe is not None:
            pe.close()
    return result
