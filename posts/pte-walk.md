# Manual Page Table Walk: Translating Virtual to Physical Addresses from a Kernel Driver

**Author:** 0xMastEB  
**Date:** March 2026  
**Tools:** Visual Studio 2022, WDK, WinDbg

---

## Overview

I wrote a Windows kernel driver that translates the virtual address of its own `DriverEntry` function into the corresponding physical address in RAM by manually walking the x64 page tables — reimplementing in software what the CPU does in hardware on every single memory access.

This writeup explains how x64 virtual memory translation works, walks through the driver code, and shows what happens at each level of the page table hierarchy.

---

## How x64 Virtual Memory Works

Programs don't access physical RAM directly. Every memory access goes through a translation: the CPU takes a virtual address, walks a 4-level hierarchy of tables, and arrives at the physical address where the data actually resides.

The four levels are:

- **PML4** (Page Map Level 4) — the root, pointed to by the CR3 register
- **PDPT** (Page Directory Pointer Table)
- **PD** (Page Directory)
- **PT** (Page Table)

Each table contains 512 entries (9 bits of index = 512 entries × 8 bytes = 4KB per table). The virtual address itself tells us which entry to read at each level.

### Virtual Address Breakdown (48-bit)

```
 63    48 47    39 38    30 29    21 20    12 11       0
┌────────┬────────┬────────┬────────┬────────┬──────────┐
│ Sign   │ PML4   │ PDPT   │  PD    │  PT    │  Offset  │
│ Extend │ Index  │ Index  │ Index  │ Index  │ (12 bit) │
└────────┴────────┴────────┴────────┴────────┴──────────┘
           9 bit    9 bit    9 bit    9 bit    12 bit
```

The 12-bit offset at the end addresses a byte within the final 4KB page (2^12 = 4096).

### Translation Flow

```
CR3 ──> PML4 Table ──> PDPT Table ──> Page Directory ──> Page Table ──> Physical Page
         [index]        [index]         [index]          [index]       + offset
```

At each level, the entry contains the physical address of the next table (bits 51:12) and a Present bit (bit 0). If the Present bit is 0, the page is not mapped and the CPU raises a page fault.

---

## The Driver

### Index Extraction Macros

```c
#define PML4_INDEX(va) (((ULONG64)(va) >> 39) & 0x1FF)
#define PDPT_INDEX(va) (((ULONG64)(va) >> 30) & 0x1FF)
#define PD_INDEX(va)   (((ULONG64)(va) >> 21) & 0x1FF)
#define PT_INDEX(va)   (((ULONG64)(va) >> 12) & 0x1FF)
```

Each macro shifts the virtual address right by the appropriate number of bits and masks with `0x1FF` (511 in decimal, 9 bits) to extract the index for that level. For example, `PML4_INDEX` shifts right 39 bits to skip the PDPT/PD/PT/offset fields, leaving only the 9-bit PML4 index.

### Reading Physical Memory

```c
ULONG64 ReadPhysical(ULONG64 PhysAddr)
{
    ULONG64 value = 0;
    MM_COPY_ADDRESS addr;
    SIZE_T bytesRead = 0;
    addr.PhysicalAddress.QuadPart = PhysAddr;
    MmCopyMemory(&value, addr, sizeof(ULONG64),
                 MM_COPY_MEMORY_PHYSICAL, &bytesRead);
    return value;
}
```

`MmCopyMemory` with the `MM_COPY_MEMORY_PHYSICAL` flag lets us read raw physical memory from kernel mode. We use this at each level to read the page table entry at the calculated physical address.

### Walking the Tables

```c
VOID WalkPageTables(PVOID VirtualAddress)
{
    // Step 0: Read CR3 — the physical address of the PML4 table
    ULONG64 cr3 = __readcr3();
    ULONG64 pml4Phys = cr3 & 0xFFFFFFFFF000;

    // Step 1: Read PML4 entry
    ULONG64 pml4e = ReadPhysical(pml4Phys + PML4_INDEX(VirtualAddress) * 8);
    DbgPrint("[Walk] PML4E: 0x%llX (index %llu)\n", pml4e,
             PML4_INDEX(VirtualAddress));
    if (!(pml4e & 1)) { DbgPrint("[Walk] PML4E Not Present!\n"); return; }

    // Step 2: Read PDPT entry
    ULONG64 pdpte = ReadPhysical((pml4e & 0xFFFFFFFFF000) +
                                  PDPT_INDEX(VirtualAddress) * 8);
    DbgPrint("[Walk] PDPTE: 0x%llX (index %llu)\n", pdpte,
             PDPT_INDEX(VirtualAddress));
    if (!(pdpte & 1)) { DbgPrint("[Walk] PDPTE not present!\n"); return; }

    // Step 3: Read PD entry
    ULONG64 pde = ReadPhysical((pdpte & 0xFFFFFFFFF000) +
                                PD_INDEX(VirtualAddress) * 8);
    DbgPrint("[Walk] PDE: 0x%llX (index %llu)\n", pde,
             PD_INDEX(VirtualAddress));
    if (!(pde & 1)) { DbgPrint("[Walk] PDE not present!\n"); return; }

    // Step 3.5: Check for 2MB large page (PS bit = bit 7)
    if (pde & 0x80) {
        ULONG64 physAddr = (pde & 0xFFFFFE00000) |
                           ((ULONG64)VirtualAddress & 0x1FFFFF);
        DbgPrint("[Walk] 2MB Large Page! Physical: 0x%llX\n", physAddr);
        return;
    }

    // Step 4: Read PT entry
    ULONG64 pte = ReadPhysical((pde & 0xFFFFFFFFF000) +
                                PT_INDEX(VirtualAddress) * 8);
    DbgPrint("[Walk] PTE: 0x%llX (index %llu)\n", pte,
             PT_INDEX(VirtualAddress));
    if (!(pte & 1)) { DbgPrint("[Walk] PTE not present!\n"); return; }

    // Step 5: Calculate final physical address
    ULONG64 physAddr = (pte & 0xFFFFFFFFF000) |
                       ((ULONG64)VirtualAddress & 0xFFF);
    DbgPrint("[Walk] Physical Address: 0x%llX\n", physAddr);
}
```

At each level:
1. Extract the physical base address from the entry (bits 51:12, masked with `0xFFFFFFFFF000`)
2. Add the index for the next level × 8 (each entry is 8 bytes)
3. Read the entry at that physical address
4. Check the Present bit — if 0, the translation fails
5. Move to the next level

The large page check at the PD level handles 2MB pages (PS bit set), which skip the PT level entirely. The physical address is calculated differently: bits 47:21 from the PDE + bits 20:0 from the virtual address.

### Entry Point

```c
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("[HelloKernel] Walking page tables for DriverEntry itself...\n");
    WalkPageTables((PVOID)DriverEntry);

    return STATUS_SUCCESS;
}
```

The driver walks the page tables for its own `DriverEntry` function — translating the virtual address where this code is loaded into the physical address where it resides in RAM.

---

## Why This Matters

This isn't just an academic exercise. Understanding page tables at this level is fundamental for:

- **Kernel exploit development** — many exploits manipulate PTEs to gain arbitrary read/write
- **Anti-cheat / anti-tamper analysis** — systems like BattlEye delete their own PTEs to hide code from memory scanners
- **Memory forensics** — tools like Volatility walk page tables to reconstruct process memory from physical dumps
- **Hypervisor development** — EPT (Extended Page Tables) uses the same 4-level structure for guest-to-host translation

The CPU does this translation billions of times per second, cached by the TLB. This driver does it once, manually, to make the invisible visible.

---

## Full Source Code

```c
#include <ntddk.h>
#include <intrin.h>

#define PML4_INDEX(va) (((ULONG64)(va) >> 39) & 0x1FF)
#define PDPT_INDEX(va) (((ULONG64)(va) >> 30) & 0x1FF)
#define PD_INDEX(va)   (((ULONG64)(va) >> 21) & 0x1FF)
#define PT_INDEX(va)   (((ULONG64)(va) >> 12) & 0x1FF)

ULONG64 ReadPhysical(ULONG64 PhysAddr)
{
    ULONG64 value = 0;
    MM_COPY_ADDRESS addr;
    SIZE_T bytesRead = 0;
    addr.PhysicalAddress.QuadPart = PhysAddr;
    MmCopyMemory(&value, addr, sizeof(ULONG64),
                 MM_COPY_MEMORY_PHYSICAL, &bytesRead);
    return value;
}

VOID WalkPageTables(PVOID VirtualAddress)
{
    ULONG64 cr3 = __readcr3();
    ULONG64 pml4Phys = cr3 & 0xFFFFFFFFF000;

    ULONG64 pml4e = ReadPhysical(pml4Phys + PML4_INDEX(VirtualAddress) * 8);
    DbgPrint("[Walk] PML4E: 0x%llX (index %llu)\n", pml4e,
             PML4_INDEX(VirtualAddress));
    if (!(pml4e & 1)) { DbgPrint("[Walk] PML4E Not Present!\n"); return; }

    ULONG64 pdpte = ReadPhysical((pml4e & 0xFFFFFFFFF000) +
                                  PDPT_INDEX(VirtualAddress) * 8);
    DbgPrint("[Walk] PDPTE: 0x%llX (index %llu)\n", pdpte,
             PDPT_INDEX(VirtualAddress));
    if (!(pdpte & 1)) { DbgPrint("[Walk] PDPTE not present!\n"); return; }

    ULONG64 pde = ReadPhysical((pdpte & 0xFFFFFFFFF000) +
                                PD_INDEX(VirtualAddress) * 8);
    DbgPrint("[Walk] PDE: 0x%llX (index %llu)\n", pde,
             PD_INDEX(VirtualAddress));
    if (!(pde & 1)) { DbgPrint("[Walk] PDE not present!\n"); return; }

    if (pde & 0x80) {
        ULONG64 physAddr = (pde & 0xFFFFFE00000) |
                           ((ULONG64)VirtualAddress & 0x1FFFFF);
        DbgPrint("[Walk] 2MB Large Page! Physical: 0x%llX\n", physAddr);
        return;
    }

    ULONG64 pte = ReadPhysical((pde & 0xFFFFFFFFF000) +
                                PT_INDEX(VirtualAddress) * 8);
    DbgPrint("[Walk] PTE: 0x%llX (index %llu)\n", pte,
             PT_INDEX(VirtualAddress));
    if (!(pte & 1)) { DbgPrint("[Walk] PTE not present!\n"); return; }

    ULONG64 physAddr = (pte & 0xFFFFFFFFF000) |
                       ((ULONG64)VirtualAddress & 0xFFF);
    DbgPrint("[Walk] Physical Address: 0x%llX\n", physAddr);
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[HelloKernel] Driver Unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("[HelloKernel] Walking page tables for DriverEntry itself...\n");
    WalkPageTables((PVOID)DriverEntry);

    return STATUS_SUCCESS;
}
```

---

*Questions or feedback? Reach me on [X](https://x.com/0xMastEB) or [LinkedIn](https://www.linkedin.com/in/filippo-licitra-02977038b/).*
