# MRAC.exe — Reversing a VMProtect-Packed Malware Loader

**Author:** 0xMastEB  
**Date:** March 2025  
**Tools:** IDA Pro, x64dbg, ScyllaHide

---

## Overview

MRAC.exe is a 64-bit malware loader/injector protected with VMProtect. Its purpose is to fingerprint the target machine, authenticate with a remote C2 server, receive an encrypted payload, and inject it into a target process — all while aggressively detecting and blocking debuggers.

This writeup covers both the static analysis in IDA Pro and the dynamic analysis in x64dbg, including the anti-debug bypass.

---

## Packing & Protection

The binary is packed with VMProtect. Over 90% of the code is virtualized, making static analysis extremely difficult. Control flow is obfuscated, and most functions are unreadable in IDA's decompiler.

However, not everything is hidden. Through string analysis and RTTI recovery, I was able to identify key structures and reconstruct the malware's logic.

---

## C2 Communication & Hardware Fingerprinting

The loader collects hardware identifiers from the target machine:

- **GPU model**
- **CPU info**
- **Driver signatures**

These are tagged internally as DRV, GPU, and CPU and sent to a remote server referred to as "ac-server" in the binary's strings. The communication follows a handshake pattern — the client sends a hello, the server authenticates based on the hardware fingerprint, and if accepted, delivers the payload.

When the C2 is unreachable, the binary returns "authorization timed out."

---

## Injection Technique

The loader avoids standard Windows API calls that EDRs typically hook. Instead, it uses:

- **Direct syscalls via NtCreateThreadEx** — bypasses user-mode hooks entirely
- **BCrypt for payload decryption** — the shellcode arrives encrypted from the C2
- **Manual mapping** — the payload is mapped into the target process manually, without calling LoadLibrary

This combination makes detection significantly harder for traditional antivirus and EDR solutions.

---

## Internal Structure (RTTI Analysis)

Through RTTI data that survived the packing, I identified a C++ class called `loader_client_t` in the `loader` namespace. Key methods include:

- `resolve_and_send_imports` — resolves available DLLs on the victim machine and sends the list to the C2
- `handle_shellcode` — receives, decrypts, and executes the shellcode from the server

This reveals a clean client-server architecture: the loader is just the delivery mechanism, the actual malicious logic lives in the shellcode sent by the C2.

---

## Anti-Debug Bypass

This was the most interesting part of the analysis.

Running MRAC.exe under a standard x64dbg setup immediately triggered an "initialization error" — the binary detected the debugger and refused to proceed.

The protection uses multiple detection vectors:

- **RDTSC timing checks** — measures CPU cycles between instructions to detect single-stepping
- **INT 2D** — generates exceptions that behave differently under a debugger
- **KUSER_SHARED_DATA check** — reads the byte at `0x7FFE02D4` to detect kernel debuggers

### The Bypass

1. **ScyllaHide** with VMProtect x86/x64 profile enabled
2. **Timing hooks activated** — GetTickCount, GetTickCount64, GetLocalTime, GetSystemTime, NtQuerySystemTime, NtQueryPerformanceCounter
3. **DRx Protection** enabled
4. **KUSER_SHARED_DATA patched** — byte at `0x7FFE02D4` set to `0x00`
5. **Shift+F9** to pass first-chance exceptions back to the program instead of breaking

### Confirmation

After applying all bypass techniques, the error changed from "initialization error" to "authentication timeout."

This single change confirmed two things simultaneously:
- The anti-debug protection was fully defeated
- The C2 server is offline, so the shellcode will never arrive

---

## Conclusion

Even without a live C2 server, the analysis revealed the full architecture of the loader: hardware fingerprinting, encrypted C2 communication, direct syscall injection, and multi-layered anti-debug protection.

The key takeaway: modern malware loaders don't need to be sophisticated in their payload — the delivery mechanism itself is where the engineering goes. VMProtect packing, timing-based anti-debug, and direct syscalls make this binary significantly harder to analyze than most samples.

---

*Questions or feedback? Reach me on [X](https://x.com/0xMastEB) or [LinkedIn](https://www.linkedin.com/in/filippo-licitra-02977038b/).*
