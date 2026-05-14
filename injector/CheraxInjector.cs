// CheraxInjector.exe — reproduces sub_1402CDF90 injection pattern from CheraxLoader.exe.
//
// Loader flow (FNV-1a-resolved APIs, anti-IAT-scan):
//   OpenProcess(0x43A = CREATE_THREAD|VM_OP|VM_WRITE|VM_READ|QUERY_INFO, FALSE, pid)
//   VirtualAllocEx(h, NULL, strlen(path)+1, MEM_COMMIT|RESERVE, PAGE_READWRITE)
//   GetModuleHandleA("kernel32.dll") + GetProcAddress("LoadLibraryA")
//   WriteProcessMemory(h, remote, path, len+1, NULL)
//   Sleep(~50 sec)                                       <- skipped by default here
//   CreateRemoteThread(h, NULL, 0, LoadLibraryA, remote, 0, NULL)
//   VirtualFreeEx(h, remote, 0, MEM_RELEASE)
//   CloseHandle(h)
//
// We use direct P/Invoke imports (since we're not hiding from analysis), but the
// runtime behaviour is byte-for-byte identical to what the loader does. GTA's
// loader then calls DllMain inside its process => module is in.
//
// Compile:
//   "%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /optimize+ /target:exe /out:CheraxInjector.exe CheraxInjector.cs
//
// Usage:
//   CheraxInjector.exe context\3790447328.dll
//   CheraxInjector.exe -p GTA5 c:\some\path\foo.dll
//   CheraxInjector.exe --match-loader context\3790447328.dll    (50sec anti-AV delay)

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

class CheraxInjector
{
    // ===== Win32 imports =====================================================
    const uint PROCESS_CREATE_THREAD     = 0x0002;
    const uint PROCESS_VM_OPERATION      = 0x0008;
    const uint PROCESS_VM_READ           = 0x0010;
    const uint PROCESS_VM_WRITE          = 0x0020;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_ACCESS            = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                                           PROCESS_VM_READ | PROCESS_VM_WRITE |
                                           PROCESS_QUERY_INFORMATION;  // = 0x43A (matches loader)

    const uint MEM_COMMIT     = 0x1000;
    const uint MEM_RESERVE    = 0x2000;
    const uint MEM_RELEASE    = 0x8000;
    const uint PAGE_READWRITE = 0x04;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr addr, IntPtr size, uint type, uint protect);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr addr, IntPtr size, uint freeType);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr written);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr attrs, uint stack,
                                            IntPtr startAddr, IntPtr param, uint flags, out uint tid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeThread(IntPtr h, out uint exitCode);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetModuleHandleA(string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);


    // ===== entry =============================================================
    static int Main(string[] args)
    {
        string dllPath = null;
        string[] targetNames = null;
        int delaySec = 0;
        bool wait = true;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-p":
                case "--process":      targetNames = new[] { args[++i] }; break;
                case "--delay":        delaySec = int.Parse(args[++i]); break;
                case "--match-loader": delaySec = 50; break;
                case "--no-wait":      wait = false; break;
                case "-h":
                case "--help":         PrintHelp(); return 0;
                default:               dllPath = args[i]; break;
            }
        }

        if (string.IsNullOrEmpty(dllPath))
        {
            Console.Error.WriteLine("error: DLL path required\n");
            PrintHelp();
            return 1;
        }

        // 0. Resolve and validate DLL
        dllPath = Path.GetFullPath(dllPath);
        if (!File.Exists(dllPath))
        {
            Console.Error.WriteLine("error: DLL not found: " + dllPath);
            return 1;
        }
        long peSize;
        if (!IsValidPE(dllPath, out peSize))
        {
            Console.Error.WriteLine("error: not a valid PE file (MZ/PE magic missing)");
            return 1;
        }
        Banner();
        Info("DLL", string.Format("{0} ({1:N0} bytes, valid PE)", dllPath, peSize));

        // 1. Wait for target process (matches loader's sub_1403061F0 polling loop)
        if (targetNames == null) targetNames = new[] { "GTA5_Enhanced", "GTA5" };
        Process target = WaitForTarget(targetNames);

        // 2. OpenProcess with same flags as loader
        IntPtr hProc = OpenProcess(PROCESS_ACCESS, false, target.Id);
        if (hProc == IntPtr.Zero) Die("OpenProcess");
        Info("OpenProcess", string.Format("access=0x{0:X3}, pid={1}, handle=0x{2:X}",
                                          PROCESS_ACCESS, target.Id, hProc.ToInt64()));

        try
        {
            // 3. Allocate buffer for DLL path
            byte[] pathBytes = Encoding.ASCII.GetBytes(dllPath + "\0");
            IntPtr remoteBuf = VirtualAllocEx(hProc, IntPtr.Zero, (IntPtr)pathBytes.Length,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (remoteBuf == IntPtr.Zero) Die("VirtualAllocEx");
            Info("VirtualAllocEx", string.Format("{0} bytes @ 0x{1:X}", pathBytes.Length, remoteBuf.ToInt64()));

            try
            {
                // 4. Resolve LoadLibraryA from our own kernel32 (same base as target's kernel32)
                IntPtr k32 = GetModuleHandleA("kernel32.dll");
                IntPtr loadLibraryA = GetProcAddress(k32, "LoadLibraryA");
                if (loadLibraryA == IntPtr.Zero) Die("GetProcAddress(LoadLibraryA)");
                Info("LoadLibraryA", string.Format("0x{0:X}", loadLibraryA.ToInt64()));

                // 5. Write path to remote process
                IntPtr written;
                if (!WriteProcessMemory(hProc, remoteBuf, pathBytes, (IntPtr)pathBytes.Length, out written))
                    Die("WriteProcessMemory");
                Info("WriteProcessMemory", written.ToInt64() + " bytes");

                // 6. Optional anti-detection sleep (loader uses ~50 sec)
                if (delaySec > 0)
                {
                    Info("Sleep", delaySec + " sec (anti-AV delay)");
                    Thread.Sleep(delaySec * 1000);
                }

                // 7. CreateRemoteThread(LoadLibraryA, dllPath)
                uint tid;
                IntPtr hThread = CreateRemoteThread(hProc, IntPtr.Zero, 0, loadLibraryA, remoteBuf, 0, out tid);
                if (hThread == IntPtr.Zero) Die("CreateRemoteThread");
                Info("CreateRemoteThread", "tid=" + tid + ", handle=0x" + hThread.ToInt64().ToString("X"));

                try
                {
                    if (wait)
                    {
                        Info("Wait", "for LoadLibraryA to return...");
                        uint rc = WaitForSingleObject(hThread, 30000);
                        if (rc != 0)
                        {
                            Warn("WaitForSingleObject", "rc=" + rc + " (thread didn't complete in 30s)");
                        }
                        else
                        {
                            uint exit;
                            GetExitCodeThread(hThread, out exit);
                            if (exit != 0)
                            {
                                Good("LoadLibraryA",
                                     "returned HMODULE=0x" + exit.ToString("X8") + " — DLL loaded inside target!");
                            }
                            else
                            {
                                Warn("LoadLibraryA",
                                     "returned NULL — load failed (DLL deps missing? wrong arch? path bad?)");
                            }
                        }
                    }
                }
                finally { CloseHandle(hThread); }
            }
            finally { VirtualFreeEx(hProc, remoteBuf, IntPtr.Zero, MEM_RELEASE); }
        }
        finally { CloseHandle(hProc); }

        Info("Done", "");
        return 0;
    }

    // ===== helpers ===========================================================
    static Process WaitForTarget(string[] names)
    {
        Info("Wait", "for target process: " + string.Join(" or ", names));
        Process found = null;
        while (found == null)
        {
            foreach (var n in names)
            {
                var p = Process.GetProcessesByName(n);
                if (p.Length > 0) { found = p[0]; break; }
            }
            if (found == null) Thread.Sleep(500);
        }
        Info("Found", found.ProcessName + ".exe pid=" + found.Id);
        return found;
    }

    static bool IsValidPE(string path, out long size)
    {
        size = 0;
        try
        {
            using (var fs = File.OpenRead(path))
            {
                size = fs.Length;
                if (size < 0x40) return false;
                byte[] head = new byte[0x40];
                fs.Read(head, 0, 0x40);
                if (head[0] != 0x4D || head[1] != 0x5A) return false;
                int peOff = BitConverter.ToInt32(head, 0x3C);
                if (peOff <= 0 || peOff + 4 > size) return false;
                fs.Seek(peOff, SeekOrigin.Begin);
                byte[] sig = new byte[4];
                fs.Read(sig, 0, 4);
                return sig[0] == 'P' && sig[1] == 'E' && sig[2] == 0 && sig[3] == 0;
            }
        }
        catch { return false; }
    }

    static void Banner()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("CheraxInjector — reproduces CheraxLoader.exe sub_1402CDF90 inject pattern");
        Console.ResetColor();
    }
    static void Info(string tag, string msg)
    {
        Console.Write("[*] ");
        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.Write("{0,-22}", tag);
        Console.ResetColor();
        Console.WriteLine(" " + msg);
    }
    static void Good(string tag, string msg)
    {
        Console.Write("[+] ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write("{0,-22}", tag);
        Console.ResetColor();
        Console.WriteLine(" " + msg);
    }
    static void Warn(string tag, string msg)
    {
        Console.Write("[!] ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("{0,-22}", tag);
        Console.ResetColor();
        Console.WriteLine(" " + msg);
    }
    static void Die(string what)
    {
        int err = Marshal.GetLastWin32Error();
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Error.WriteLine("[!!] {0} failed: Win32 error 0x{1:X} ({1})", what, err);
        Console.ResetColor();
        Environment.Exit(1);
    }
    static void PrintHelp()
    {
        Console.WriteLine(
@"CheraxInjector.exe — DLL injector matching CheraxLoader.exe pattern

Usage: CheraxInjector.exe [options] <dll_path>

Options:
  -p, --process <name>   Target process name without .exe (default: GTA5_Enhanced or GTA5)
  --delay <sec>          Sleep before CreateRemoteThread (default: 0)
  --match-loader         Use loader's 50sec anti-AV delay
  --no-wait              Don't wait for LoadLibraryA to complete (fire-and-forget)
  -h, --help             This help

Examples:
  CheraxInjector.exe context\3790447328.dll
  CheraxInjector.exe -p GTA5 c:\path\foo.dll
  CheraxInjector.exe --match-loader --no-wait context\3790447328.dll

Notes:
  - DLL must be x64 (same arch as target). 3790447328.dll is x64 PE = match for GTA5.
  - Injector and target must run at same or higher integrity level. If GTA runs
    as admin (BattlEye in GTA5_Enhanced may require this), injector also needs admin.
  - LoadLibraryA returning HMODULE=0 means GTA loaded the DLL but DllMain returned
    FALSE, OR the DLL has unmet dependencies. Check Process Hacker for actually-loaded
    modules to confirm.");
    }
}
