import os
import math
import re
import json
import subprocess

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    print('[static_engine] WARNING: pefile not installed — PE analysis disabled')

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print('[static_engine] WARNING: yara-python not installed — YARA disabled')


# APIs commonly abused by malware
SUSPICIOUS_APIS = {
    # Process injection
    'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx', 'VirtualAlloc',
    'NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'RtlCreateUserThread',
    'NtCreateThreadEx', 'QueueUserAPC',
    # Registry persistence
    'RegSetValueEx', 'RegCreateKeyEx', 'RegOpenKeyEx',
    # Anti-debug / evasion
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
    'OutputDebugStringA', 'OutputDebugStringW',
    # Networking
    'WSAStartup', 'InternetOpenA', 'InternetOpenW', 'HttpSendRequestA', 'HttpSendRequestW',
    'URLDownloadToFileA', 'URLDownloadToFileW', 'InternetOpenUrlA', 'InternetOpenUrlW',
    # Execution
    'WinExec', 'ShellExecuteA', 'ShellExecuteW', 'CreateProcessA', 'CreateProcessW',
    'system', '_popen',
    # Keylogging / spying
    'SetWindowsHookExA', 'SetWindowsHookExW', 'GetAsyncKeyState', 'GetKeyState',
    # Crypto (often ransomware)
    'CryptEncrypt', 'CryptGenKey', 'CryptAcquireContextA', 'CryptAcquireContextW',
}

KNOWN_SECTION_NAMES = {
    '.text', '.code', '.data', '.rdata', '.rsrc', '.reloc',
    '.bss', '.idata', '.edata', '.tls', '.pdata', '.debug',
    '.crt', '.gfids', '.00cfg', 'UPX0', 'UPX1',
}


def _entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0.0 = uniform, 8.0 = maximum)."""
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _run_die(file_path: str, die_binary: str = 'diec') -> dict:
    """
    Run Detect It Easy CLI and return parsed JSON output.
    Returns empty dict on any failure — never raises.
    """
    try:
        result = subprocess.run(
            [die_binary, '--json', file_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except FileNotFoundError:
        pass  # diec not installed — expected in non-Docker environments
    except subprocess.TimeoutExpired:
        pass
    except json.JSONDecodeError:
        pass
    except Exception:
        pass
    return {}


def _run_yara(file_path: str, rules_path: str) -> list:
    """
    Compile and run YARA rules against a file.
    Returns list of matching rule names. Never raises.
    """
    if not YARA_AVAILABLE:
        return []
    if not rules_path or not os.path.exists(rules_path):
        return []
    try:
        rules = yara.compile(rules_path)
        matches = rules.match(file_path, timeout=30)
        return [m.rule for m in matches]
    except yara.SyntaxError as e:
        print(f'[static_engine] YARA syntax error: {e}')
        return []
    except yara.TimeoutError:
        return []
    except Exception as e:
        print(f'[static_engine] YARA error: {e}')
        return []


def _extract_strings(file_path: str) -> dict:
    """
    Extract printable ASCII strings (≥4 chars) from binary and categorise them.
    Returns a structured dict. Never raises.
    """
    urls, ips, reg_keys, suspicious_strings, printable = [], [], [], [], []

    url_pattern = re.compile(rb'https?://[\w\-./?=%&+#@!~]+', re.IGNORECASE)
    ip_pattern = re.compile(rb'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
    reg_pattern = re.compile(rb'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_[\w_]+)[\\\w]+', re.IGNORECASE)
    susp_pattern = re.compile(
        rb'(?:cmd\.exe|powershell|base64|invoke-expression|iex\(|wget|curl\b|nc\.exe|'
        rb'mimikatz|meterpreter|shellcode|payload|backdoor)',
        re.IGNORECASE,
    )

    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        printable = re.findall(rb'[\x20-\x7e]{4,}', data)

        for s in printable:
            decoded = s.decode('ascii', errors='ignore')[:300]
            if url_pattern.search(s):
                urls.append(decoded)
            if ip_pattern.search(s):
                ips.append(decoded[:60])
            if reg_pattern.search(s):
                reg_keys.append(decoded)
            if susp_pattern.search(s):
                suspicious_strings.append(decoded)

    except Exception:
        pass

    return {
        'urls': list(dict.fromkeys(urls))[:20],
        'ips': list(dict.fromkeys(ips))[:20],
        'registry_keys': list(dict.fromkeys(reg_keys))[:20],
        'suspicious': list(dict.fromkeys(suspicious_strings))[:20],
        'total_strings': len(printable),
    }


def analyze(file_path: str, yara_rules_path: str = '', die_binary: str = 'diec') -> dict:
    """
    Run full static analysis on a PE file.
    Returns a structured dict even if pefile fails — graceful degradation throughout.
    """
    strings_data = _extract_strings(file_path)
    die_output = _run_die(file_path, die_binary)
    yara_matches = _run_yara(file_path, yara_rules_path)

    result = {
        'is_pe': False,
        'pe_headers': {},
        'sections': [],
        'imports': {
            'total_count': 0,
            'dll_count': 0,
            'suspicious_apis': [],
            'all_dlls': [],
        },
        'strings': strings_data,
        'packing': {
            'is_packed': False,
            'confidence': 0.0,
            'signals': [],
            'packer_name': None,
            'max_entropy': 0.0,
            'avg_entropy': 0.0,
        },
        'die_output': die_output,
        'yara_matches': yara_matches,
    }

    # Extract packer name from DiE output (handles both 'detects' and 'Detects' keys)
    packer_name = None
    if die_output:
        detects = die_output.get('detects') or die_output.get('Detects') or []
        for d in detects:
            dtype = (d.get('type') or '').lower()
            if 'packer' in dtype or 'protector' in dtype or 'compiler' in dtype:
                packer_name = d.get('name')
                break
    result['packing']['packer_name'] = packer_name

    if not PEFILE_AVAILABLE:
        return result

    try:
        pe = pefile.PE(file_path, fast_load=False)
        result['is_pe'] = True

        # ── PE Headers ──────────────────────────────────────────────────
        try:
            result['pe_headers'] = {
                'compile_timestamp': pe.FILE_HEADER.TimeDateStamp,
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
                'num_sections': pe.FILE_HEADER.NumberOfSections,
                'machine_type': hex(pe.FILE_HEADER.Machine),
                'subsystem': pe.OPTIONAL_HEADER.Subsystem,
                'dll_characteristics': hex(pe.OPTIONAL_HEADER.DllCharacteristics),
                'checksum': hex(pe.OPTIONAL_HEADER.CheckSum),
            }
        except AttributeError:
            pass

        # ── Sections ────────────────────────────────────────────────────
        section_entropies = []
        for s in pe.sections:
            try:
                name = s.Name.decode('utf-8', errors='replace').strip('\x00').strip()
                raw_data = s.get_data()
                ent = _entropy(raw_data)
                section_entropies.append(ent)
                result['sections'].append({
                    'name': name,
                    'virtual_size': s.Misc_VirtualSize,
                    'raw_size': s.SizeOfRawData,
                    'entropy': round(ent, 4),
                    'is_known': name in KNOWN_SECTION_NAMES,
                    'characteristics': hex(s.Characteristics),
                })
            except Exception:
                continue

        # ── Imports ─────────────────────────────────────────────────────
        found_suspicious = []
        all_dlls = []
        total_imports = 0

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    all_dlls.append(dll_name)
                    for imp in entry.imports:
                        total_imports += 1
                        if imp.name:
                            api_name = imp.name.decode('utf-8', errors='ignore')
                            if api_name in SUSPICIOUS_APIS:
                                found_suspicious.append(api_name)
                except Exception:
                    continue

        result['imports'] = {
            'total_count': total_imports,
            'dll_count': len(all_dlls),
            'suspicious_apis': sorted(set(found_suspicious)),
            'all_dlls': all_dlls[:30],
        }

        # ── Packing Detection ────────────────────────────────────────────
        packing_signals = []
        max_ent = max(section_entropies) if section_entropies else 0.0
        avg_ent = (sum(section_entropies) / len(section_entropies)) if section_entropies else 0.0

        if max_ent > 7.0:
            packing_signals.append('high_section_entropy')
        if avg_ent > 6.5:
            packing_signals.append('high_average_entropy')
        if total_imports < 5 and result['is_pe']:
            packing_signals.append('very_few_imports')
        if packer_name:
            packing_signals.append('known_packer_signature')
        unknown_count = sum(1 for s in result['sections'] if not s['is_known'])
        if unknown_count > 1:
            packing_signals.append('unknown_section_names')
        if strings_data['total_strings'] < 20 and result['is_pe']:
            packing_signals.append('very_few_strings')

        packing_confidence = min(len(packing_signals) / 3.0, 1.0)
        result['packing'] = {
            'is_packed': len(packing_signals) >= 2,
            'confidence': round(packing_confidence, 3),
            'signals': packing_signals,
            'packer_name': packer_name,
            'max_entropy': round(max_ent, 4),
            'avg_entropy': round(avg_ent, 4),
        }

        pe.close()

    except pefile.PEFormatError:
        result['is_pe'] = False
    except Exception as e:
        print(f'[static_engine] Unexpected error during PE analysis: {e}')
        # Return whatever was collected so far — never re-raise

    return result
