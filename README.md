# Frankenstein_APC_Injection_PoC

Injecting shellcode into already running processes without calling VirtualAllocEx or 
WriteProcessMemory. Instead of allocating new memory, this technique creates a shared 
section object and maps it directly into the target process as RX. APC is queued via 
NtQueueApcThreadEx2 Special APC which doesn't require the thread to be in alertable state.
Shellcode slot is left empty on purpose.

## Usage

Compile and run the EXE without any parameters.

## Steps

* Resolve kernel32 / KernelBase / ntdll base addresses by walking the PEB directly.
* Resolve all required APIs by hashing the export table — no GetProcAddress, no GetModuleHandle.
* Extract syscall service numbers from ntdll stubs (Hell's Gate + Halo's Gate fallback for hooked stubs).
* Build indirect syscall trampolines that jump through a ntdll gadget to pass kernel return address checks.
* Enumerate running processes using NtGetNextProcess — no Toolhelp snapshot.
* Skip processes with ACG (ProhibitDynamicCode) enabled since NtMapViewOfSection is blocked there too.
* Create a pagefile-backed section with NtCreateSection.
* Map a local RW view, write the RC4-decrypted payload, then unmap.
* Open the target process and map an RX view of the same section — target never gets a RWX region.
* Enumerate threads with NtGetNextThread and queue a Special User APC pointing to the mapped view.

## Shellcode

Drop any position-independent shellcode into enc_shellcode[] after RC4 encrypting it with rc4_key.
Shellcode must be self-contained and not rely on a fixed base address.

## Build

MSVC only.



Requires Windows 11 / Server 2022+ for NtQueueApcThreadEx2 Special APC support.


For educational purposes only.
