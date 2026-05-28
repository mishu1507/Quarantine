rule Suspicious_Process_Injection
{
    meta:
        description = "Possible process injection techniques (hollow process / DLL injection)"
        severity    = "high"
        author      = "Quarantine"
    strings:
        $a = "CreateRemoteThread"   ascii
        $b = "WriteProcessMemory"   ascii
        $c = "VirtualAllocEx"       ascii
        $d = "NtUnmapViewOfSection" ascii
        $e = "RtlCreateUserThread"  ascii
    condition:
        2 of them
}

rule Suspicious_PowerShell
{
    meta:
        description = "PowerShell execution or obfuscated command observed in binary"
        severity    = "high"
        author      = "Quarantine"
    strings:
        $a = "powershell"       nocase
        $b = "-EncodedCommand"  nocase
        $c = "IEX("            nocase
        $d = "Invoke-Expression" nocase
        $e = "-nop -w hidden"   nocase
        $f = "bypass"           nocase
    condition:
        2 of them
}

rule Suspicious_Network
{
    meta:
        description = "Suspicious network activity indicators"
        severity    = "medium"
        author      = "Quarantine"
    strings:
        $a = "URLDownloadToFile"  ascii
        $b = "InternetOpenUrl"    ascii
        $c = "HttpSendRequest"    ascii
        $d = "WinHttpConnect"     ascii
        $e = "WSAStartup"         ascii
    condition:
        2 of them
}

rule Suspicious_AntiDebug
{
    meta:
        description = "Anti-debugging / anti-analysis techniques"
        severity    = "medium"
        author      = "Quarantine"
    strings:
        $a = "IsDebuggerPresent"            ascii
        $b = "CheckRemoteDebuggerPresent"   ascii
        $c = "NtQueryInformationProcess"    ascii
        $d = "FindWindow"                   ascii
        $e = "GetTickCount"                 ascii
    condition:
        2 of them
}

rule Suspicious_Ransomware_Crypto
{
    meta:
        description = "Cryptographic API usage consistent with ransomware"
        severity    = "high"
        author      = "Quarantine"
    strings:
        $a = "CryptEncrypt"         ascii
        $b = "CryptGenKey"          ascii
        $c = "CryptAcquireContext"  ascii
        $d = "BCryptEncrypt"        ascii
        $e = "BCryptGenRandom"      ascii
    condition:
        2 of them
}

rule Suspicious_Keylogger
{
    meta:
        description = "Potential keylogging behaviour"
        severity    = "high"
        author      = "Quarantine"
    strings:
        $a = "SetWindowsHookEx"   ascii
        $b = "GetAsyncKeyState"   ascii
        $c = "GetKeyState"        ascii
        $d = "GetKeyboardState"   ascii
    condition:
        2 of them
}

rule EICAR_Test
{
    meta:
        description = "EICAR antivirus test file — not malware, used for testing AV"
        severity    = "info"
        author      = "Quarantine"
    strings:
        $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $a
}
