"""Constrained built-in rules and explicit, hash-pinned user exceptions."""

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from keyguard.config import default_data
from keyguard.models import Detection, Finding, SignatureInfo
from keyguard.paths import canonical, is_under


@dataclass(frozen=True)
class BuiltinRule:
    """A product name is useful only with a matching verified signer and root."""

    product: str
    names: frozenset[str]
    publishers: frozenset[str]


BUILTINS = (
    BuiltinRule("AutoHotkey", frozenset({"autohotkey.exe", "autohotkey64.exe", "autohotkey32.exe", "autohotkeyu64.exe"}),
                frozenset({"autohotkey foundation llc"})),
    BuiltinRule("NVDA screen reader", frozenset({"nvda.exe", "nvda_slave.exe"}), frozenset({"nv access limited"})),
    BuiltinRule("JAWS screen reader", frozenset({"jfw.exe"}), frozenset({"freedom scientific inc.", "freedom scientific, inc."})),
    BuiltinRule("Steam game overlay", frozenset({"gameoverlayui.exe", "steam.exe"}), frozenset({"valve corp.", "valve corporation"})),
    BuiltinRule("NVIDIA overlay", frozenset({"nvidia share.exe", "nvidia overlay.exe"}), frozenset({"nvidia corporation"})),
    BuiltinRule("Microsoft IME/accessibility", frozenset({"ctfmon.exe", "textinputhost.exe", "narrator.exe"}),
                frozenset({"microsoft corporation"})),
    BuiltinRule("1Password", frozenset({"1password.exe"}), frozenset({"agilebits inc.", "1password"})),
    BuiltinRule("Bitwarden", frozenset({"bitwarden.exe"}), frozenset({"bitwarden inc.", "bitwarden inc"})),
    BuiltinRule("KeePass", frozenset({"keepass.exe"}), frozenset({"dominik reichl"})),
    BuiltinRule("KeePassXC", frozenset({"keepassxc.exe"}), frozenset({"keepassxc team"})),
)


def sha256_file(path: Path) -> str:
    """Hash a file in bounded chunks without loading or executing it."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def default_allowlist_path() -> Path:
    """Store editable user state outside frozen executable resources."""
    root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    return Path(root) / "KeyGuard" / "allowlist.json" if root else Path.home() / ".keyguard" / "allowlist.json"


def load_allowlist(path: Path) -> dict[str, Any]:
    """Load strict user rules; a missing file means no user exceptions."""
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else default_data("allowlist.json")
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("entries"), list):
        raise ValueError("Allowlist must have schema_version 1 and an entries list")
    for entry in data["entries"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("Every allowlist entry needs an absolute path and sha256")
        digest = entry.get("sha256", "")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Allowlist sha256 must be 64 lowercase hexadecimal characters")
        import ntpath
        if not ntpath.isabs(entry["path"]):
            raise ValueError("Allowlist paths must be absolute")
    return data


def add_user_entry(executable: Path, destination: Path) -> dict[str, Any]:
    """Explicitly add a path+hash exception using an atomic JSON replacement."""
    executable = executable.expanduser().resolve(strict=True)
    if not executable.is_file() or executable.suffix.casefold() != ".exe":
        raise ValueError("Allowlist target must be an existing .exe file")
    data = load_allowlist(destination)
    entry = {"path": str(executable), "sha256": sha256_file(executable)}
    data["entries"] = [item for item in data["entries"] if canonical(item["path"]) != canonical(str(executable))]
    data["entries"].append(entry)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=destination.parent, delete=False) as stream:
            temporary = stream.name
            json.dump(data, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, destination)
    finally:
        if temporary and Path(temporary).exists():
            Path(temporary).unlink()
    return entry


def analyze_allowlist(path: str, signature: SignatureInfo, data: dict[str, Any]) -> Detection:
    """Return a discount without hiding any findings or bypassing other modules."""
    result = Detection(data={"allowlisted": False})
    import ntpath
    name = ntpath.basename(path).casefold()
    roots = [os.environ[key] for key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "SystemRoot")
             if os.environ.get(key)]
    for rule in BUILTINS:
        if (signature.status == "valid" and name in rule.names
                and signature.publisher.casefold() in rule.publishers
                and any(is_under(path, root) for root in roots)):
            result.findings.append(Finding("builtin_allowlist", "allowlist",
                                           f"Built-in {rule.product} rule: verified signer, filename, and installation root"))
            result.data["allowlisted"] = True
            break
    for entry in data["entries"]:
        if canonical(entry["path"]) != canonical(path):
            continue
        try:
            if sha256_file(Path(path)) == entry["sha256"]:
                result.findings.append(Finding("user_allowlist", "allowlist", "User allowlist matched exact executable path and SHA-256"))
                result.data["allowlisted"] = True
            else:
                result.issues.append("Allowlisted file changed: SHA-256 mismatch; user discount not applied")
        except OSError as exc:
            result.issues.append(f"Cannot verify allowlist hash: {exc}")
        break
    return result
