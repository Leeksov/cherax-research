# Cache-load injector toolkit (C#)

A minimal C# toolkit that lets you load the Cherax module DLL into
GTA5 via the standard cache-bypass technique that the loader uses
internally. Built primarily for **understanding the loader's load
sequence**, not for distribution.

## Tools

| File                 | Purpose |
|----------------------|---------|
| `CheraxInjector.cs`  | Console DLL injector. Opens a target process by name, allocates a buffer for the DLL path, writes it, calls `CreateRemoteThread` with `LoadLibraryA` |
| `CheraxInjectorUI.cs`| Same but with a WinForms GUI. Drop a DLL onto it, pick the target process |
| `CheraxWatcher.cs`   | File-system watcher that detects when a DLL appears in `%USERPROFILE%\Documents\Cherax\Cache\Loader\` and acquires it with `FileShare.ReadWrite \| Delete` (the trick that lets you copy the module out before the loader cleans it up) |

## Process access flags used

```cs
const uint PROCESS_ACCESS = 0x43A;
// = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
//   PROCESS_VM_WRITE      | PROCESS_VM_READ      | PROCESS_QUERY_INFORMATION
```

Same access mask the Cherax loader uses for its own
`CreateRemoteThread + LoadLibraryA` injection sequence — confirmed in
`CheraxLoader.exe` via `OpenProcess(0x43A, ...)` call sites.

## Build

```sh
csc /target:exe CheraxInjector.cs
csc /target:winexe CheraxInjectorUI.cs   # requires WinForms references
csc /target:exe CheraxWatcher.cs
```

(Use `csc.exe` from the .NET Framework, not `dotnet build`. The
files use C# 6-compatible syntax.)

## Intended use

These are research-only tools to understand the injection lifecycle.
Using them to actually run the cheat would:

- Trigger Cherax's tamper webhook (the loader detects custom injection
  and exfils a screenshot + process/window/file list to Discord)
- Result in `403 ACCOUNT_DISABLED` on next login
- Risk a BattlEye ban on the connected GTA-V account

If you have a legitimate research need (e.g., behavioral sandboxing
of the module in an isolated VM with no game), the injector is
sufficient — but use a throwaway account and an offline VM.
