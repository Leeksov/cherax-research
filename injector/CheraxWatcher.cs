// CheraxWatcher.exe
//
// Watches the 3 Cherax cache fallback paths and copies every file that
// appears there to a capture directory. Uses FileShare.ReadWrite|Delete so
// the loader's DeleteFile call can't yank the file out before we read it
// (Windows defers the actual delete until all handles close).
//
// Compile:
//   "%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /optimize+ /target:exe /out:CheraxWatcher.exe CheraxWatcher.cs
//
// Run:
//   CheraxWatcher.exe              (uses default capture dir = .\cherax-captures)
//   CheraxWatcher.exe -o "C:\dump" (override capture dir)
//
// Stop: Ctrl+C

using System;
using System.IO;
using System.Threading;
using System.Collections.Generic;

class CheraxWatcher
{
    static string CaptureDir;
    static string LogPath;
    static object LogLock = new object();
    static int CaptureCount = 0;
    static volatile bool Running = true;

    struct WatchSpec { public string Path; public string Tag; }

    static readonly WatchSpec[] Targets = new WatchSpec[]
    {
        new WatchSpec { Path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Cherax"),                Tag = "docs"   },
        new WatchSpec { Path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), @"AppData\LocalLow\Cherax"), Tag = "lowapp" },
        new WatchSpec { Path = @"C:\Cherax",                                                                                                Tag = "croot"  },
    };

    static void Main(string[] args)
    {
        // parse -o <dir>
        string outDir = null;
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "-o" || args[i] == "--output") { outDir = args[i + 1]; break; }
        }
        CaptureDir = outDir ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cherax-captures");
        Directory.CreateDirectory(CaptureDir);
        LogPath = Path.Combine(CaptureDir, "_events.log");

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("CheraxWatcher  pid={0}  capture={1}", System.Diagnostics.Process.GetCurrentProcess().Id, CaptureDir);
        Console.ResetColor();
        Log(string.Format("watcher start  pid={0}", System.Diagnostics.Process.GetCurrentProcess().Id));

        var watchers = new List<FileSystemWatcher>();
        foreach (var t in Targets)
        {
            if (!Directory.Exists(t.Path))
            {
                try { Directory.CreateDirectory(t.Path); Console.WriteLine("[*] created {0}", t.Path); }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[!] cannot create {0}: {1} (need admin?) - skipping", t.Path, ex.Message);
                    Console.ResetColor();
                    continue;
                }
            }

            var fsw = new FileSystemWatcher(t.Path)
            {
                Filter = "*",
                IncludeSubdirectories = true,
                InternalBufferSize = 64 * 1024,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName |
                               NotifyFilters.LastWrite | NotifyFilters.Size |
                               NotifyFilters.CreationTime
            };

            string tag = t.Tag;
            fsw.Created += (s, e) => OnEvent(e.FullPath, "Created", tag);
            fsw.Changed += (s, e) => OnEvent(e.FullPath, "Changed", tag);
            fsw.Renamed += (s, e) => OnEvent(e.FullPath, "Renamed", tag);
            fsw.Deleted += (s, e) => OnEvent(e.FullPath, "Deleted", tag);
            fsw.Error   += (s, e) => Log("[!] watcher error: " + e.GetException());

            fsw.EnableRaisingEvents = true;
            watchers.Add(fsw);
            Console.WriteLine("[*] watching: {0,-55}  tag={1}", t.Path, tag);
        }

        if (watchers.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[!] no watchers attached - abort");
            Console.ResetColor();
            return;
        }

        Console.WriteLine();
        Console.WriteLine("[*] log:      {0}", LogPath);
        Console.WriteLine("[*] press Ctrl+C to stop");
        Console.WriteLine();

        Console.CancelKeyPress += (s, e) => { e.Cancel = true; Running = false; };
        while (Running) Thread.Sleep(100);

        foreach (var w in watchers) { w.EnableRaisingEvents = false; w.Dispose(); }
        Console.WriteLine();
        Console.WriteLine("[*] watcher stopped.  {0} captures saved.", CaptureCount);
        Log(string.Format("watcher stop  captures={0}", CaptureCount));
    }

    static readonly HashSet<string> InFlight = new HashSet<string>();

    static void OnEvent(string src, string change, string tag)
    {
        var now = DateTime.Now;
        var line = string.Format("{0:HH:mm:ss.fff}  [{1}]  {2,-7}  {3}", now, tag, change, src);

        ConsoleColor color = ConsoleColor.Gray;
        if (change == "Created") color = ConsoleColor.Yellow;
        else if (change == "Deleted") color = ConsoleColor.Red;
        else if (change == "Renamed") color = ConsoleColor.Magenta;

        Console.ForegroundColor = color;
        Console.WriteLine(line);
        Console.ResetColor();
        Log(line);

        if (change == "Deleted") return;
        try { if (Directory.Exists(src)) return; } catch { return; }

        // dedupe rapid-fire Changed events
        lock (InFlight)
        {
            if (InFlight.Contains(src)) return;
            InFlight.Add(src);
        }
        ThreadPool.QueueUserWorkItem(_ =>
        {
            try { CaptureFile(src, change, tag, now); }
            finally { lock (InFlight) { InFlight.Remove(src); } }
        });
    }

    static void CaptureFile(string src, string change, string tag, DateTime evtTime)
    {
        string ts = evtTime.ToString("HHmmss.fff");
        string safe = src;
        // strip drive prefix and replace separators with _
        try
        {
            string root = Path.GetPathRoot(src) ?? "";
            if (safe.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                safe = safe.Substring(root.Length);
        }
        catch { }
        foreach (char bad in Path.GetInvalidFileNameChars()) safe = safe.Replace(bad, '_');
        safe = safe.Replace(' ', '_');

        string dst = Path.Combine(CaptureDir, string.Format("{0}_{1}_{2}_{3}", ts, tag, change, safe));

        // share-mode trick: ReadWrite|Delete = we can keep reading even if the
        // loader has already called DeleteFile - Windows postpones the actual
        // unlink until we close our handle.
        const FileShare share = FileShare.ReadWrite | FileShare.Delete;
        Exception last = null;

        for (int attempt = 0; attempt < 30 && Running; attempt++)
        {
            try
            {
                using (var fs = new FileStream(src, FileMode.Open, FileAccess.Read, share))
                {
                    long len = fs.Length;
                    if (len == 0)
                    {
                        Thread.Sleep(25);
                        continue; // still being written
                    }
                    byte[] buf = new byte[len];
                    int read = 0, total = 0;
                    while (total < buf.Length && (read = fs.Read(buf, total, buf.Length - total)) > 0)
                        total += read;

                    File.WriteAllBytes(dst, buf);

                    bool isPE = total >= 0x40 && buf[0] == 0x4D && buf[1] == 0x5A;
                    string note = isPE ? " *** PE/DLL ***" : "";
                    string ok = string.Format("    -> saved {0} bytes to {1}{2}", total, Path.GetFileName(dst), note);

                    Console.ForegroundColor = isPE ? ConsoleColor.Green : ConsoleColor.DarkGray;
                    Console.WriteLine(ok);
                    Console.ResetColor();
                    Log(ok);
                    Interlocked.Increment(ref CaptureCount);
                    return;
                }
            }
            catch (FileNotFoundException)
            {
                string gone = "    !! vanished before open: " + src;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(gone);
                Console.ResetColor();
                Log(gone);
                return;
            }
            catch (DirectoryNotFoundException)
            {
                return; // race: directory gone
            }
            catch (Exception ex)
            {
                last = ex;
                Thread.Sleep(30);
            }
        }

        string fail = "    !! GAVE UP after retries: " + src + (last != null ? "  (" + last.Message + ")" : "");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(fail);
        Console.ResetColor();
        Log(fail);
    }

    static void Log(string s)
    {
        string line = string.Format("[{0:O}] {1}", DateTime.Now, s);
        lock (LogLock)
        {
            try { File.AppendAllText(LogPath, line + Environment.NewLine); } catch { }
        }
    }
}
