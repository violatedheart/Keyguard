"""Windows path discovery and conservative command-line target parsing."""

import ntpath
import os
import re
from collections.abc import Mapping


def expand_variables(value: str, env: Mapping[str, str] | None = None) -> str:
    """Expand percent-delimited variables without altering command-line quoting."""
    variables = {key.casefold(): val for key, val in (os.environ if env is None else env).items()}

    def replace(match: re.Match[str]) -> str:
        """Preserve unknown variables rather than inventing an absolute path."""
        return variables.get(match.group(1).casefold(), match.group(0))

    return re.sub(r"%([^%]+)%", replace, value)


def expand_path(value: str, env: Mapping[str, str] | None = None) -> str:
    """Expand and normalize a single Windows path, preserving unknown variables."""
    value = expand_variables(value.strip().strip('"'), env)
    variables = {key.casefold(): val for key, val in (os.environ if env is None else env).items()}
    if value.casefold().startswith("\\systemroot\\") and variables.get("systemroot"):
        value = ntpath.join(variables["systemroot"], value[len("\\SystemRoot\\"):])
    if value.startswith("\\??\\") or value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normpath(value)


def canonical(value: str) -> str:
    """Normalize case and separators for Windows comparisons, without opening files."""
    return ntpath.normcase(expand_path(value)) if value else ""


def is_under(path: str, root: str) -> bool:
    """Match a directory boundary; TempBackup must not match Temp."""
    if not path or not root:
        return False
    path_key, root_key = canonical(path), canonical(root)
    try:
        return ntpath.isabs(path_key) and ntpath.commonpath([path_key, root_key]) == root_key
    except ValueError:
        return False


def shell_folders() -> tuple[dict[str, str], list[str]]:
    """Read redirected user/common shell folders with read-only registry handles."""
    result: dict[str, str] = {}
    issues: list[str] = []
    if os.name != "nt":
        return result, issues
    import winreg

    specs = [
        (winreg.HKEY_CURRENT_USER, "Downloads", "{374DE290-123F-4565-9164-39C4925E467B}"),
        (winreg.HKEY_CURRENT_USER, "Startup", "Startup"),
        (winreg.HKEY_LOCAL_MACHINE, "CommonStartup", "Common Startup"),
    ]
    key_name = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    for hive, label, value_name in specs:
        try:
            with winreg.OpenKey(hive, key_name, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, value_name)
                if isinstance(value, str):
                    result[label] = expand_path(value)
        except FileNotFoundError:
            continue
        except OSError as exc:
            issues.append(f"Shell folder {label}: {exc}")
    return result, issues


def risk_roots(folders: Mapping[str, str] | None = None,
               env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Discover risky directories from environment and redirected shell folders."""
    values = os.environ if env is None else env
    roots = {f"%{name}%": values[name] for name in ("TEMP", "TMP", "APPDATA", "LOCALAPPDATA", "PUBLIC")
             if values.get(name)}
    downloads = (folders or {}).get("Downloads")
    if not downloads and values.get("USERPROFILE"):
        downloads = ntpath.join(values["USERPROFILE"], "Downloads")
    if downloads:
        roots["Downloads"] = downloads
    return roots


def suspicious_paths(path: str, roots: Mapping[str, str]) -> list[str]:
    """Return every matching risky directory label."""
    return sorted(label for label, root in roots.items() if is_under(path, root))


def command_targets(command: str) -> list[str]:
    """Extract absolute executable/script paths as text; never execute a command.

    Unquoted service executable paths containing spaces are handled through their
    .exe suffix. Arbitrary shell expressions and relative targets remain unresolved.
    """
    text = expand_variables(command.strip())
    candidates: list[str] = []
    if text.startswith('"'):
        match = re.match(r'^"([^\"]+)"', text)
    else:
        match = re.match(r"^(.+?\.(?:exe|com|bat|cmd|ps1|vbs|js|py))(?=\s|$)", text, re.I)
    if match:
        candidates.append(match.group(1))
    for quoted, bare in re.findall(r'"([^\"]+)"|([^\s\"]+)', text):
        token = quoted or bare
        if re.search(r"\.(exe|dll|com|bat|cmd|ps1|vbs|js|py)$", token, re.I):
            candidates.append(token)
    return list(dict.fromkeys(expand_path(p) for p in candidates if ntpath.isabs(p)))
