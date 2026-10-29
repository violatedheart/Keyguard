"""Offline embedded Authenticode verification through Windows WinVerifyTrust.

Signer details are read from the provider chain that WinVerifyTrust validated,
not from unverified PE version strings or a separately selected certificate.
"""

import ctypes
import os
from ctypes import wintypes as wt
from dataclasses import asdict

from keyguard.models import Detection, Finding, SignatureInfo


class GUID(ctypes.Structure):
    """Windows GUID with native alignment."""

    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


class WINTRUST_FILE_INFO(ctypes.Structure):
    """WINTRUST_FILE_INFO for the WTD_CHOICE_FILE union arm."""

    _fields_ = [("cbStruct", wt.DWORD), ("pcwszFilePath", wt.LPCWSTR),
                ("hFile", wt.HANDLE), ("pgKnownSubject", ctypes.POINTER(GUID))]


class WINTRUST_DATA(ctypes.Structure):
    """WINTRUST_DATA layout including its pointer-sized union storage."""

    _fields_ = [("cbStruct", wt.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wt.DWORD),
                ("fdwRevocationChecks", wt.DWORD), ("dwUnionChoice", wt.DWORD),
                ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                ("dwStateAction", wt.DWORD), ("hWVTStateData", wt.HANDLE),
                ("pwszURLReference", wt.LPWSTR), ("dwProvFlags", wt.DWORD),
                ("dwUIContext", wt.DWORD), ("pSignatureSettings", ctypes.c_void_p)]


class CRYPT_PROVIDER_CERT(ctypes.Structure):
    """Leading fields of CRYPT_PROVIDER_CERT used to obtain PCCERT_CONTEXT."""

    _fields_ = [("cbStruct", wt.DWORD), ("pCert", ctypes.c_void_p)]


class CRYPT_PROVIDER_SGNR(ctypes.Structure):
    """Leading fields of CRYPT_PROVIDER_SGNR through pasCertChain."""

    _fields_ = [("cbStruct", wt.DWORD), ("sftVerifyAsOf", wt.FILETIME),
                ("csCertChain", wt.DWORD),
                ("pasCertChain", ctypes.POINTER(CRYPT_PROVIDER_CERT))]


def classify_status(status: int) -> str:
    """Separate missing signatures, failed trust, and operational errors."""
    value = status & 0xFFFFFFFF
    if value == 0:
        return "valid"
    if value == 0x800B0100:  # TRUST_E_NOSIGNATURE (catalogs not checked here)
        return "unsigned"
    if value in {0x80096010, 0x800B0101, 0x800B0109, 0x800B010A, 0x800B010C,
                 0x800B0111, 0x800B0004, 0x80096004, 0x800B010E}:
        return "invalid"
    return "unknown"


def _verified_signer(wintrust: ctypes.CDLL, state: int) -> tuple[str, str]:
    """Read organization and display name from the trusted provider's leaf cert."""
    provider = wintrust.WTHelperProvDataFromStateData
    provider.argtypes, provider.restype = [wt.HANDLE], ctypes.c_void_p
    signer = wintrust.WTHelperGetProvSignerFromChain
    signer.argtypes = [ctypes.c_void_p, wt.DWORD, wt.BOOL, wt.DWORD]
    signer.restype = ctypes.POINTER(CRYPT_PROVIDER_SGNR)
    data = provider(state)
    record = signer(data, 0, False, 0) if data else None
    if not record or not record.contents.csCertChain or not record.contents.pasCertChain:
        return "", ""
    cert = record.contents.pasCertChain[0].pCert
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    get_name = crypt32.CertGetNameStringW
    get_name.argtypes = [ctypes.c_void_p, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.LPWSTR, wt.DWORD]
    get_name.restype = wt.DWORD

    def cert_name(kind: int, parameter: ctypes.c_char_p | None = None) -> str:
        """Read a certificate name using a dynamically sized output buffer."""
        count = get_name(cert, kind, 0, parameter, None, 0)
        if count <= 1:
            return ""
        buffer = ctypes.create_unicode_buffer(count)
        if get_name(cert, kind, 0, parameter, buffer, count) <= 1:
            return ""
        return buffer.value

    return cert_name(3, ctypes.c_char_p(b"2.5.4.10")), cert_name(4)


def verify_signature(path: str) -> SignatureInfo:
    """Verify embedded trust offline, with no UI or revocation network requests.

    Catalog-only signatures and fresh revocation information are outside coverage.
    Every allocated WinVerifyTrust provider state is closed in a finally block.
    """
    if os.name != "nt":
        return SignatureInfo(detail="WinVerifyTrust is available only on Windows")
    try:
        wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
        verify = wintrust.WinVerifyTrust
        verify.argtypes = [wt.HWND, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)]
        verify.restype = ctypes.c_long
        action = GUID(0x00AAC56B, 0xCD44, 0x11D0,
                      (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(file_info)
        file_info.pcwszFilePath = path
        data = WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(data)
        data.dwUIChoice = 2  # WTD_UI_NONE
        data.dwUnionChoice = 1  # WTD_CHOICE_FILE
        data.pFile = ctypes.pointer(file_info)
        data.dwStateAction = 1  # WTD_STATEACTION_VERIFY
        data.dwProvFlags = 0x1000 | 0x10  # CACHE_ONLY_URL_RETRIEVAL | REVOCATION_CHECK_NONE
        try:
            status = verify(None, ctypes.byref(action), ctypes.byref(data)) & 0xFFFFFFFF
            category = classify_status(status)
            publisher, subject = ("", "")
            detail = "Embedded signature only; offline chain validation; revocation not checked"
            if category == "valid":
                try:
                    publisher, subject = _verified_signer(wintrust, data.hWVTStateData)
                except (OSError, ValueError, AttributeError) as exc:
                    detail += f"; signer metadata unavailable: {exc}"
            return SignatureInfo(category, publisher, subject, f"0x{status:08X}", detail)
        finally:
            if data.hWVTStateData:
                data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
                verify(None, ctypes.byref(action), ctypes.byref(data))
    except (OSError, ValueError, AttributeError) as exc:
        return SignatureInfo(detail=f"WinVerifyTrust unavailable: {exc}")


def is_microsoft(info: SignatureInfo) -> bool:
    """Require both valid trust and an exact Microsoft signer organization."""
    return info.status == "valid" and info.publisher.casefold() == "microsoft corporation"


def analyze_signature(info: SignatureInfo, trusted_publishers: list[str]) -> Detection:
    """Convert the signature result into one signal or an explicit coverage issue."""
    result = Detection(data={"signature": asdict(info)})
    if info.status == "unknown":
        result.issues.append(f"Signature unknown ({info.status_code}): {info.detail}")
        return result
    if info.status == "unsigned":
        code, reason = "unsigned", "No embedded Authenticode signature (catalog signatures not checked)"
    elif info.status == "invalid":
        code, reason = "invalid_signature", f"Embedded signature failed trust validation ({info.status_code})"
    elif is_microsoft(info):
        code, reason = "microsoft_signed", "Valid embedded signature from Microsoft Corporation (offline)"
    elif info.publisher and info.publisher.casefold() in {p.casefold() for p in trusted_publishers}:
        code, reason = "trusted_publisher", f"Valid embedded signature from configured publisher {info.publisher}"
    else:
        code, reason = "valid_signature", f"Valid embedded signature: {info.publisher or info.subject or 'signer unavailable'} (offline)"
    result.findings.append(Finding(code, "signature", reason))
    return result
