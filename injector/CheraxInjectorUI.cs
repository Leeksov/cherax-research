// CheraxInjectorUI.exe — WinForms UI for the loader-pattern DLL injector.
//
// Same injection core as CheraxInjector.exe but with a GUI:
//   - DLL picker + drag-drop
//   - Target process selector (auto-discovers GTA5_Enhanced / GTA5, or pick from list)
//   - Real-time process status + log
//   - Delay / match-loader / no-wait options
//
// Compile:
//   "%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /optimize+ ^
//      /target:winexe ^
//      /reference:System.dll,System.Drawing.dll,System.Windows.Forms.dll ^
//      /out:CheraxInjectorUI.exe CheraxInjectorUI.cs

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

class MainForm : Form
{
    // ===== Win32 =============================================================
    const uint PROCESS_CREATE_THREAD = 0x0002, PROCESS_VM_OPERATION = 0x0008;
    const uint PROCESS_VM_READ = 0x0010, PROCESS_VM_WRITE = 0x0020;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_ACCESS = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                                 PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION; // 0x43A
    const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, MEM_RELEASE = 0x8000;
    const uint PAGE_READWRITE = 0x04;

    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint a, bool i, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr a, IntPtr s, uint t, uint p);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool VirtualFreeEx(IntPtr h, IntPtr a, IntPtr s, uint t);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool WriteProcessMemory(IntPtr h, IntPtr a, byte[] b, IntPtr s, out IntPtr w);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr at, uint ss, IntPtr sa, IntPtr p, uint f, out uint tid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeThread(IntPtr h, out uint ec);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)] static extern IntPtr GetModuleHandleA(string n);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)] static extern IntPtr GetProcAddress(IntPtr h, string n);

    // ===== Controls ==========================================================
    TextBox txtDll;
    ComboBox cmbProcess;
    NumericUpDown numDelay;
    CheckBox chkMatchLoader, chkNoWait, chkAutoWait;
    RichTextBox txtLog;
    Button btnBrowse, btnRefresh, btnInject, btnCancel;
    Label lblTargetStatus;
    System.Windows.Forms.Timer procTimer;
    CancellationTokenSource cts;
    Task injectTask;

    public MainForm()
    {
        Text = "CheraxInjector — DLL Injector (loader pattern)";
        Width = 700;
        Height = 620;
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9F);
        BackColor = Color.FromArgb(245, 245, 248);
        AllowDrop = true;
        DragEnter += (s, e) => { if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy; };
        DragDrop += MainForm_DragDrop;
        FormClosing += (s, e) => { if (cts != null) cts.Cancel(); };

        var lblDll = MkLabel("DLL to inject:", 12, 12);
        txtDll = new TextBox { Left = 12, Top = 32, Width = 580, ReadOnly = false };
        btnBrowse = MkButton("Browse...", 600, 30, 70, 25, OnBrowse);

        var lblProc = MkLabel("Target process:", 12, 70);
        cmbProcess = new ComboBox { Left = 12, Top = 90, Width = 280, DropDownStyle = ComboBoxStyle.DropDown };
        cmbProcess.Items.AddRange(new object[] { "GTA5_Enhanced", "GTA5" });
        cmbProcess.SelectedIndex = 0;
        btnRefresh = MkButton("Refresh", 300, 88, 70, 25, (s, e) => RefreshProcessList());
        lblTargetStatus = new Label { Left = 380, Top = 92, Width = 290, ForeColor = Color.DimGray, Text = "(scanning...)" };

        var grpOpts = new GroupBox { Text = "Options", Left = 12, Top = 130, Width = 660, Height = 90 };

        var lblDelay = MkLabel("Delay before CreateRemoteThread (sec):", 14, 24);
        lblDelay.Parent = grpOpts;
        numDelay = new NumericUpDown { Left = 270, Top = 22, Width = 60, Minimum = 0, Maximum = 600, Parent = grpOpts };

        chkMatchLoader = new CheckBox { Left = 14, Top = 50, Width = 280, Text = "Match loader behavior (50s anti-AV delay)", Parent = grpOpts };
        chkMatchLoader.CheckedChanged += (s, e) => {
            if (chkMatchLoader.Checked) numDelay.Value = 50;
            numDelay.Enabled = !chkMatchLoader.Checked;
        };

        chkNoWait = new CheckBox { Left = 340, Top = 22, Width = 280, Text = "Don't wait for LoadLibraryA result", Parent = grpOpts };
        chkAutoWait = new CheckBox { Left = 340, Top = 50, Width = 280, Text = "Wait for target to appear (poll mode)", Checked = true, Parent = grpOpts };

        var lblLog = MkLabel("Log:", 12, 230);
        txtLog = new RichTextBox {
            Left = 12, Top = 252, Width = 660, Height = 270,
            Font = new Font("Consolas", 9F), ReadOnly = true,
            BackColor = Color.FromArgb(30, 30, 35), ForeColor = Color.Gainsboro,
            BorderStyle = BorderStyle.FixedSingle
        };

        btnInject = MkButton("Inject Now", 460, 535, 110, 32, OnInject);
        btnInject.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
        btnInject.BackColor = Color.FromArgb(57, 130, 80); btnInject.ForeColor = Color.White;
        btnInject.FlatStyle = FlatStyle.Flat; btnInject.FlatAppearance.BorderSize = 0;

        btnCancel = MkButton("Cancel", 580, 535, 90, 32, OnCancel);
        btnCancel.Enabled = false;
        btnCancel.BackColor = Color.FromArgb(160, 40, 40); btnCancel.ForeColor = Color.White;
        btnCancel.FlatStyle = FlatStyle.Flat; btnCancel.FlatAppearance.BorderSize = 0;

        Controls.AddRange(new Control[] { lblDll, txtDll, btnBrowse, lblProc, cmbProcess, btnRefresh,
                                          lblTargetStatus, grpOpts, lblLog, txtLog, btnInject, btnCancel });

        // Periodic process refresh
        procTimer = new System.Windows.Forms.Timer { Interval = 1500 };
        procTimer.Tick += (s, e) => UpdateTargetStatus();
        procTimer.Start();
        UpdateTargetStatus();

        // Pre-fill common path
        var defaultDll = Path.Combine(Application.StartupPath, "context", "3790447328.dll");
        if (File.Exists(defaultDll)) txtDll.Text = defaultDll;

        Log("CheraxInjector UI ready. Drop a DLL or click Browse to pick.", Color.Cyan);
    }

    Label MkLabel(string text, int x, int y)
    {
        return new Label { Text = text, Left = x, Top = y, AutoSize = true };
    }
    Button MkButton(string text, int x, int y, int w, int h, EventHandler onClick)
    {
        var b = new Button { Text = text, Left = x, Top = y, Width = w, Height = h };
        b.Click += onClick;
        return b;
    }

    void MainForm_DragDrop(object sender, DragEventArgs e)
    {
        var files = (string[])e.Data.GetData(DataFormats.FileDrop);
        if (files.Length > 0) txtDll.Text = files[0];
    }

    void OnBrowse(object sender, EventArgs e)
    {
        using (var ofd = new OpenFileDialog())
        {
            ofd.Filter = "DLL / module files (*.dll;*.dat;*.bin)|*.dll;*.dat;*.bin|All files (*.*)|*.*";
            ofd.InitialDirectory = Application.StartupPath;
            if (ofd.ShowDialog() == DialogResult.OK) txtDll.Text = ofd.FileName;
        }
    }

    void RefreshProcessList()
    {
        var names = Process.GetProcesses().Select(p => p.ProcessName).Distinct().OrderBy(n => n).ToArray();
        var saved = cmbProcess.Text;
        cmbProcess.Items.Clear();
        cmbProcess.Items.AddRange(names);
        cmbProcess.Text = saved;
    }

    void UpdateTargetStatus()
    {
        var target = cmbProcess.Text;
        if (string.IsNullOrWhiteSpace(target)) { lblTargetStatus.Text = ""; return; }
        var procs = Process.GetProcessesByName(target);
        if (procs.Length > 0)
        {
            lblTargetStatus.Text = "● " + target + ".exe pid=" + procs[0].Id;
            lblTargetStatus.ForeColor = Color.ForestGreen;
        }
        else
        {
            lblTargetStatus.Text = "○ " + target + ".exe not running";
            lblTargetStatus.ForeColor = Color.DimGray;
        }
    }

    void OnCancel(object sender, EventArgs e)
    {
        if (cts != null) { cts.Cancel(); Log("[!] Cancel requested", Color.Yellow); }
    }

    async void OnInject(object sender, EventArgs e)
    {
        // Validate
        var dll = (txtDll.Text ?? "").Trim();
        if (string.IsNullOrEmpty(dll) || !File.Exists(dll))
        {
            MessageBox.Show("Pick a valid DLL file first.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        dll = Path.GetFullPath(dll);
        if (!IsValidPE(dll))
        {
            MessageBox.Show("Not a valid PE file (MZ/PE magic missing).", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var target = (cmbProcess.Text ?? "").Trim();
        if (string.IsNullOrEmpty(target))
        {
            MessageBox.Show("Pick a target process name.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        SetBusy(true);
        cts = new CancellationTokenSource();
        var token = cts.Token;

        int delay = (int)numDelay.Value;
        bool waitResult = !chkNoWait.Checked;
        bool poll = chkAutoWait.Checked;

        Log("=========================================", Color.Cyan);
        Log("DLL:    " + dll, Color.Gainsboro);
        Log("Target: " + target + ".exe", Color.Gainsboro);
        Log("Delay:  " + delay + " sec   waitResult=" + waitResult + "   pollForTarget=" + poll, Color.DarkGray);

        injectTask = Task.Run(() => DoInject(dll, target, delay, waitResult, poll, token));
        try { await injectTask; }
        catch (OperationCanceledException) { Log("[!] Cancelled.", Color.Yellow); }
        catch (Exception ex) { Log("[!] Unexpected: " + ex.Message, Color.OrangeRed); }
        finally { SetBusy(false); }
    }

    void SetBusy(bool busy)
    {
        Invoke((MethodInvoker)delegate {
            btnInject.Enabled = !busy;
            btnCancel.Enabled = busy;
            btnBrowse.Enabled = !busy;
            txtDll.Enabled = !busy;
            cmbProcess.Enabled = !busy;
            numDelay.Enabled = !busy && !chkMatchLoader.Checked;
            chkMatchLoader.Enabled = !busy;
            chkNoWait.Enabled = !busy;
            chkAutoWait.Enabled = !busy;
        });
    }

    bool IsValidPE(string path)
    {
        try
        {
            using (var fs = File.OpenRead(path))
            {
                if (fs.Length < 0x40) return false;
                var head = new byte[0x40];
                fs.Read(head, 0, 0x40);
                if (head[0] != 0x4D || head[1] != 0x5A) return false;
                int peOff = BitConverter.ToInt32(head, 0x3C);
                if (peOff <= 0 || peOff + 4 > fs.Length) return false;
                fs.Seek(peOff, SeekOrigin.Begin);
                var sig = new byte[4];
                fs.Read(sig, 0, 4);
                return sig[0] == 'P' && sig[1] == 'E' && sig[2] == 0 && sig[3] == 0;
            }
        }
        catch { return false; }
    }

    void DoInject(string dll, string target, int delay, bool waitResult, bool poll, CancellationToken token)
    {
        // 1. Find target
        Process proc = null;
        if (poll)
        {
            Log("[*] Waiting for " + target + ".exe ...", Color.LightSkyBlue);
            while (!token.IsCancellationRequested)
            {
                var ps = Process.GetProcessesByName(target);
                if (ps.Length > 0) { proc = ps[0]; break; }
                Thread.Sleep(500);
            }
        }
        else
        {
            var ps = Process.GetProcessesByName(target);
            if (ps.Length == 0)
            {
                Log("[!] " + target + ".exe not running.", Color.OrangeRed);
                return;
            }
            proc = ps[0];
        }
        token.ThrowIfCancellationRequested();
        Log("[+] Found " + proc.ProcessName + ".exe pid=" + proc.Id, Color.LimeGreen);

        // 2. OpenProcess
        IntPtr hProc = OpenProcess(PROCESS_ACCESS, false, proc.Id);
        if (hProc == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            Log("[!] OpenProcess failed: 0x" + err.ToString("X") + (err == 5 ? "  (Access denied — run as Administrator?)" : ""), Color.OrangeRed);
            return;
        }
        Log("[*] OpenProcess(access=0x43A, pid=" + proc.Id + ") -> handle=0x" + hProc.ToInt64().ToString("X"), Color.Gainsboro);

        IntPtr remoteBuf = IntPtr.Zero;
        IntPtr hThread = IntPtr.Zero;
        try
        {
            byte[] pathBytes = Encoding.ASCII.GetBytes(dll + "\0");
            remoteBuf = VirtualAllocEx(hProc, IntPtr.Zero, (IntPtr)pathBytes.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (remoteBuf == IntPtr.Zero) { Log("[!] VirtualAllocEx failed: 0x" + Marshal.GetLastWin32Error().ToString("X"), Color.OrangeRed); return; }
            Log("[*] VirtualAllocEx(" + pathBytes.Length + ") -> 0x" + remoteBuf.ToInt64().ToString("X"), Color.Gainsboro);

            IntPtr k32 = GetModuleHandleA("kernel32.dll");
            IntPtr loadLib = GetProcAddress(k32, "LoadLibraryA");
            if (loadLib == IntPtr.Zero) { Log("[!] LoadLibraryA not resolved", Color.OrangeRed); return; }
            Log("[*] LoadLibraryA @ 0x" + loadLib.ToInt64().ToString("X"), Color.Gainsboro);

            IntPtr written;
            if (!WriteProcessMemory(hProc, remoteBuf, pathBytes, (IntPtr)pathBytes.Length, out written))
            { Log("[!] WriteProcessMemory failed: 0x" + Marshal.GetLastWin32Error().ToString("X"), Color.OrangeRed); return; }
            Log("[*] WriteProcessMemory wrote " + written.ToInt64() + " bytes", Color.Gainsboro);

            if (delay > 0)
            {
                Log("[*] Sleeping " + delay + "s (anti-AV delay)...", Color.LightSkyBlue);
                int elapsed = 0;
                while (elapsed < delay && !token.IsCancellationRequested)
                {
                    Thread.Sleep(1000);
                    elapsed++;
                    if (elapsed % 5 == 0) Log("    +" + elapsed + "s / " + delay + "s", Color.DimGray);
                }
            }
            token.ThrowIfCancellationRequested();

            uint tid;
            hThread = CreateRemoteThread(hProc, IntPtr.Zero, 0, loadLib, remoteBuf, 0, out tid);
            if (hThread == IntPtr.Zero) { Log("[!] CreateRemoteThread failed: 0x" + Marshal.GetLastWin32Error().ToString("X"), Color.OrangeRed); return; }
            Log("[*] CreateRemoteThread tid=" + tid, Color.LightSkyBlue);

            if (waitResult)
            {
                Log("[*] Waiting for LoadLibraryA to return...", Color.LightSkyBlue);
                uint rc = WaitForSingleObject(hThread, 30000);
                if (rc != 0) { Log("[!] Thread didn't complete in 30s (rc=" + rc + ")", Color.Yellow); return; }
                uint exit;
                GetExitCodeThread(hThread, out exit);
                if (exit != 0) Log("[+] DLL LOADED  HMODULE=0x" + exit.ToString("X8"), Color.LimeGreen);
                else Log("[!] LoadLibraryA returned NULL — load failed (deps? arch? path?)", Color.Yellow);
            }
            else
            {
                Log("[*] Fire-and-forget mode (not waiting for result)", Color.LightSkyBlue);
            }
        }
        finally
        {
            if (hThread != IntPtr.Zero) CloseHandle(hThread);
            if (remoteBuf != IntPtr.Zero) VirtualFreeEx(hProc, remoteBuf, IntPtr.Zero, MEM_RELEASE);
            CloseHandle(hProc);
            Log("[*] Done. handles cleaned up.", Color.Gainsboro);
        }
    }

    void Log(string text, Color color)
    {
        if (txtLog.InvokeRequired) { txtLog.BeginInvoke((MethodInvoker)(() => Log(text, color))); return; }
        txtLog.SelectionStart = txtLog.TextLength;
        txtLog.SelectionLength = 0;
        txtLog.SelectionColor = color;
        txtLog.AppendText(DateTime.Now.ToString("HH:mm:ss.fff ") + text + Environment.NewLine);
        txtLog.SelectionColor = txtLog.ForeColor;
        txtLog.ScrollToCaret();
    }

    [STAThread]
    static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());
    }
}
