// Cherax HWID Spoofer — WinForms UI (dark + purple theme)
//
// Two-component spoof model (no kernel driver required):
//   1. Volume serial (C:\)  → via Sysinternals VolumeID.exe
//   2. Computer name        → via PowerShell Rename-Computer (effect on reboot)
//
// CPUID(0) sum is NOT spoofed (would require a hypervisor driver and
// TestSigning mode). The cpu_sum component is per-CPU-model anyway and
// doesn't uniquely identify a machine, so the 2/3-component spoof is
// sufficient for Cherax HWID purposes.
//
// Build: build.bat in the same directory.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace CheraxHwidSpoofer
{
    // ============================================================
    // Theme — Cherax-inspired dark + purple
    // ============================================================
    static class Theme
    {
        public static readonly Color Background  = Color.FromArgb(14, 14, 20);     // near-black, slight blue tint
        public static readonly Color Panel       = Color.FromArgb(24, 24, 32);     // card BG
        public static readonly Color PanelHi     = Color.FromArgb(34, 34, 46);     // hover/elevated card
        public static readonly Color Border      = Color.FromArgb(42, 42, 58);
        public static readonly Color Text        = Color.FromArgb(232, 232, 240);
        public static readonly Color SubText     = Color.FromArgb(139, 139, 159);
        public static readonly Color Accent      = Color.FromArgb(139, 92, 246);   // #8B5CF6 purple
        public static readonly Color AccentHi    = Color.FromArgb(167, 139, 250);  // #A78BFA
        public static readonly Color Danger      = Color.FromArgb(239, 68, 68);
        public static readonly Color Success     = Color.FromArgb(16, 185, 129);
        public static readonly Color Warning     = Color.FromArgb(245, 158, 11);
        public static readonly Color LogBg       = Color.FromArgb(10, 10, 16);
        public static readonly Color LogText     = Color.FromArgb(167, 139, 250);

        public static Font UiRegular   = new Font("Segoe UI", 9.5f, FontStyle.Regular);
        public static Font UiSemibold  = new Font("Segoe UI Semibold", 9.5f, FontStyle.Regular);
        public static Font UiTitle     = new Font("Segoe UI Semibold", 18f, FontStyle.Regular);
        public static Font UiSubtitle  = new Font("Segoe UI", 10f, FontStyle.Regular);
        public static Font UiHeader    = new Font("Segoe UI Semibold", 10.5f, FontStyle.Regular);
        public static Font Mono        = new Font("Cascadia Mono", 10f, FontStyle.Regular);
    }


    // ============================================================
    // Custom controls
    // ============================================================
    class RoundedPanel : Panel
    {
        public int CornerRadius = 10;
        public RoundedPanel() { DoubleBuffered = true; BackColor = Theme.Panel; }
        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            var r = ClientRectangle;
            r.Width -= 1; r.Height -= 1;
            using (var path = MakeRoundedPath(r, CornerRadius))
            {
                using (var b = new SolidBrush(BackColor)) e.Graphics.FillPath(b, path);
                using (var p = new Pen(Theme.Border, 1f)) e.Graphics.DrawPath(p, path);
            }
            base.OnPaint(e);
        }
        public static GraphicsPath MakeRoundedPath(Rectangle r, int radius)
        {
            int d = radius * 2;
            var path = new GraphicsPath();
            path.AddArc(r.X, r.Y, d, d, 180, 90);
            path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }
    }

    class AccentButton : Button
    {
        public Color BaseColor = Theme.Accent;
        public Color HoverColor = Theme.AccentHi;
        public Color TextColor = Color.White;
        bool hovering = false, pressed = false;
        public int CornerRadius = 8;

        public AccentButton()
        {
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            BackColor = BaseColor;
            ForeColor = TextColor;
            Font = Theme.UiSemibold;
            Cursor = Cursors.Hand;
            DoubleBuffered = true;
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
            MouseEnter += (s, e) => { hovering = true; Invalidate(); };
            MouseLeave += (s, e) => { hovering = false; pressed = false; Invalidate(); };
            MouseDown  += (s, e) => { pressed = true; Invalidate(); };
            MouseUp    += (s, e) => { pressed = false; Invalidate(); };
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            var r = ClientRectangle;
            r.Width -= 1; r.Height -= 1;
            Color fill = pressed
                ? Color.FromArgb(Math.Max(0, BaseColor.R - 25), Math.Max(0, BaseColor.G - 25), Math.Max(0, BaseColor.B - 25))
                : (hovering ? HoverColor : BaseColor);
            using (var path = RoundedPanel.MakeRoundedPath(r, CornerRadius))
            using (var b = new SolidBrush(fill))
                e.Graphics.FillPath(b, path);

            TextRenderer.DrawText(e.Graphics, Text, Font, ClientRectangle, TextColor,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }
    }

    class GhostButton : AccentButton
    {
        public GhostButton()
        {
            BaseColor = Theme.Panel;
            HoverColor = Theme.PanelHi;
            TextColor = Theme.Text;
            BackColor = BaseColor;
            ForeColor = TextColor;
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            // 1px subtle border
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            var r = ClientRectangle; r.Width -= 1; r.Height -= 1;
            using (var path = RoundedPanel.MakeRoundedPath(r, CornerRadius))
            using (var p = new Pen(Theme.Border, 1f))
                e.Graphics.DrawPath(p, path);
        }
    }

    class DarkTextBox : Panel
    {
        readonly TextBox inner = new TextBox();
        public DarkTextBox()
        {
            BackColor = Theme.Background;
            DoubleBuffered = true;
            Padding = new Padding(8, 6, 8, 6);
            Height = 30;
            inner.BorderStyle = BorderStyle.None;
            inner.BackColor = Theme.Background;
            inner.ForeColor = Theme.Text;
            inner.Font = Theme.Mono;
            inner.Dock = DockStyle.Fill;
            Controls.Add(inner);
        }
        public override string Text { get { return inner.Text; } set { inner.Text = value; } }
        public bool ReadOnly { get { return inner.ReadOnly; } set { inner.ReadOnly = value; } }
        public TextBox Inner { get { return inner; } }
        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            var r = ClientRectangle; r.Width -= 1; r.Height -= 1;
            using (var path = RoundedPanel.MakeRoundedPath(r, 6))
            using (var b = new SolidBrush(BackColor))
                e.Graphics.FillPath(b, path);
            using (var path = RoundedPanel.MakeRoundedPath(r, 6))
            using (var p = new Pen(Theme.Border, 1f))
                e.Graphics.DrawPath(p, path);
        }
    }


    // ============================================================
    // HWID compute (port of compute_hwid.py)
    // ============================================================
    static class HwidCompute
    {
        const uint MEM_COMMIT  = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool GetVolumeInformationA(
            string lpRootPathName, IntPtr lpVolumeNameBuffer, uint nVolumeNameSize,
            out uint lpVolumeSerialNumber, out uint lpMaximumComponentLength,
            out uint lpFileSystemFlags, IntPtr lpFileSystemNameBuffer, uint nFileSystemNameSize);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool GetComputerNameA(StringBuilder lpBuffer, ref uint nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        // Same x64 cpuid stub as compute_hwid.py
        static readonly byte[] CpuidStubBytes = new byte[] {
            0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x89, 0xCE,
            0x31, 0xC0, 0x0F, 0xA2,
            0x89, 0x06, 0x89, 0x5E, 0x04, 0x89, 0x4E, 0x08, 0x89, 0x56, 0x0C,
            0x5B, 0x5D, 0xC3
        };

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate void CpuidStubFn(IntPtr outPtr);

        static IntPtr _stubAddr = IntPtr.Zero;
        static CpuidStubFn _stubFn = null;

        static CpuidStubFn EnsureStub()
        {
            if (_stubFn != null) return _stubFn;
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)CpuidStubBytes.Length,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (addr == IntPtr.Zero) throw new Exception("VirtualAlloc failed");
            Marshal.Copy(CpuidStubBytes, 0, addr, CpuidStubBytes.Length);
            _stubAddr = addr;
            _stubFn = (CpuidStubFn)Marshal.GetDelegateForFunctionPointer(addr, typeof(CpuidStubFn));
            return _stubFn;
        }

        public static uint GetVolumeSerial()
        {
            uint serial, _max, _flags;
            GetVolumeInformationA(@"C:\", IntPtr.Zero, 0,
                                  out serial, out _max, out _flags, IntPtr.Zero, 0);
            return serial;
        }

        public static string GetComputerName()
        {
            StringBuilder buf = new StringBuilder(16);
            uint size = 16;
            if (!GetComputerNameA(buf, ref size))
                return "GetComputerNameA Failed";
            return buf.ToString();
        }

        public static short CpuidLeaf0HsumInt16()
        {
            CpuidStubFn stub = EnsureStub();
            IntPtr outBuf = Marshal.AllocHGlobal(16);
            try
            {
                stub(outBuf);
                byte[] raw = new byte[16];
                Marshal.Copy(outBuf, raw, 0, 16);
                int sum = 0;
                for (int i = 0; i < 16; i += 2)
                    sum += BitConverter.ToUInt16(raw, i);
                return (short)(sum & 0xFFFF);
            }
            finally { Marshal.FreeHGlobal(outBuf); }
        }

        public static string FullHwid()
        {
            uint vol = GetVolumeSerial();
            string name = GetComputerName();
            short cpu = CpuidLeaf0HsumInt16();
            string raw = vol.ToString() + ";" + name + ";" + cpu.ToString();
            byte[] bytes = Encoding.ASCII.GetBytes(raw);
            StringBuilder sb = new StringBuilder(bytes.Length);
            foreach (byte b in bytes) sb.Append(b < 0x80 ? (char)b : '*');
            return sb.ToString();
        }

        public static string CpuVendor()
        {
            CpuidStubFn stub = EnsureStub();
            IntPtr outBuf = Marshal.AllocHGlobal(16);
            try
            {
                stub(outBuf);
                byte[] raw = new byte[16];
                Marshal.Copy(outBuf, raw, 0, 16);
                byte[] vendor = new byte[12];
                Array.Copy(raw, 4, vendor, 0, 4);
                Array.Copy(raw, 12, vendor, 4, 4);
                Array.Copy(raw, 8, vendor, 8, 4);
                return Encoding.ASCII.GetString(vendor);
            }
            finally { Marshal.FreeHGlobal(outBuf); }
        }
    }


    // ============================================================
    // Embedded volume-serial changer
    //
    // Direct on-disk write of the NTFS / FAT32 BPB to change the
    // volume serial number returned by GetVolumeInformationA. No
    // dependency on Sysinternals VolumeID.exe.
    //
    // For NTFS the serial DWORD reported by GetVolumeInformation
    // is `low32(qword) XOR high32(qword)` of the 8-byte field at
    // BPB offset 0x48. We write `low32 = new`, `high32 = 0` so the
    // XOR equals the new serial exactly.
    //
    // For FAT32 the serial is a single 4-byte field at BPB offset
    // 0x43.
    //
    // exFAT requires recomputing a boot-region checksum that spans
    // 11 sectors — not supported here. Not a problem in practice
    // since C: is almost always NTFS.
    // ============================================================
    static class VolumeSerialChanger
    {
        const uint GENERIC_READ        = 0x80000000;
        const uint GENERIC_WRITE       = 0x40000000;
        const uint FILE_SHARE_READ     = 0x00000001;
        const uint FILE_SHARE_WRITE    = 0x00000002;
        const uint OPEN_EXISTING       = 3;
        const uint FSCTL_LOCK_VOLUME   = 0x00090018;
        const uint FSCTL_UNLOCK_VOLUME = 0x0009001C;
        const uint FSCTL_DISMOUNT_VOLUME = 0x00090020;
        const int  INVALID_HANDLE      = -1;
        const int  SECTOR_SIZE         = 512;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess,
            uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetFilePointerEx(IntPtr hFile, long liDistanceToMove,
            out long lpNewFilePointer, uint dwMoveMethod);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode,
            IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        public enum FsType { Unknown, NTFS, FAT32, ExFAT }

        public static FsType DetectFs(byte[] bootSector)
        {
            if (bootSector.Length < 0x60) return FsType.Unknown;
            // NTFS: "NTFS    " at offset 3 (8 bytes)
            string sig0 = Encoding.ASCII.GetString(bootSector, 3, 8);
            if (sig0.StartsWith("NTFS")) return FsType.NTFS;
            if (sig0.StartsWith("EXFAT")) return FsType.ExFAT;
            // FAT32: "FAT32   " at offset 0x52
            if (bootSector.Length >= 0x5A)
            {
                string sigF32 = Encoding.ASCII.GetString(bootSector, 0x52, 5);
                if (sigF32.StartsWith("FAT32")) return FsType.FAT32;
            }
            return FsType.Unknown;
        }

        public static uint ReadCurrentSerial(byte[] bootSector, FsType fs)
        {
            switch (fs)
            {
                case FsType.NTFS:
                    uint lo = BitConverter.ToUInt32(bootSector, 0x48);
                    uint hi = BitConverter.ToUInt32(bootSector, 0x4C);
                    return lo ^ hi;
                case FsType.FAT32:
                    return BitConverter.ToUInt32(bootSector, 0x43);
                case FsType.ExFAT:
                    return BitConverter.ToUInt32(bootSector, 0x64);
                default:
                    return 0;
            }
        }

        public static void PatchSerial(byte[] bootSector, FsType fs, uint newSerial)
        {
            byte[] newLo = BitConverter.GetBytes(newSerial);
            switch (fs)
            {
                case FsType.NTFS:
                    // Set low32 = newSerial, high32 = 0 → XOR == newSerial
                    Array.Copy(newLo, 0, bootSector, 0x48, 4);
                    Array.Clear(bootSector, 0x4C, 4);
                    break;
                case FsType.FAT32:
                    Array.Copy(newLo, 0, bootSector, 0x43, 4);
                    break;
                case FsType.ExFAT:
                    throw new NotSupportedException(
                        "exFAT requires boot-checksum recomputation across 11 sectors — not supported");
                default:
                    throw new InvalidOperationException("Unknown filesystem on target volume");
            }
        }

        public class ChangeResult
        {
            public FsType Fs;
            public uint   OldSerial;
            public uint   NewSerial;
            public bool   LockSucceeded;
        }

        public static ChangeResult Change(char driveLetter, uint newSerial)
        {
            string path = @"\\.\" + driveLetter + ":";
            IntPtr h = CreateFileW(path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (h == new IntPtr(INVALID_HANDLE))
                throw new Exception("CreateFile " + path + " failed: " + Marshal.GetLastWin32Error()
                    + " (run as Administrator)");

            ChangeResult result = new ChangeResult();
            try
            {
                // Attempt to lock volume — usually fails on system drive (C:),
                // but raw on-disk write still works without the lock.
                uint dummy;
                result.LockSucceeded = DeviceIoControl(h, FSCTL_LOCK_VOLUME,
                    IntPtr.Zero, 0, IntPtr.Zero, 0, out dummy, IntPtr.Zero);

                // Read boot sector
                long ptr;
                if (!SetFilePointerEx(h, 0, out ptr, 0))
                    throw new Exception("SetFilePointer (read) failed: " + Marshal.GetLastWin32Error());
                byte[] sector = new byte[SECTOR_SIZE];
                uint nRead;
                if (!ReadFile(h, sector, SECTOR_SIZE, out nRead, IntPtr.Zero) || nRead != SECTOR_SIZE)
                    throw new Exception("ReadFile boot sector failed: " + Marshal.GetLastWin32Error());

                FsType fs = DetectFs(sector);
                result.Fs = fs;
                result.OldSerial = ReadCurrentSerial(sector, fs);

                // Patch in memory
                PatchSerial(sector, fs, newSerial);
                result.NewSerial = newSerial;

                // Write back
                if (!SetFilePointerEx(h, 0, out ptr, 0))
                    throw new Exception("SetFilePointer (write) failed: " + Marshal.GetLastWin32Error());
                uint nWritten;
                if (!WriteFile(h, sector, SECTOR_SIZE, out nWritten, IntPtr.Zero) || nWritten != SECTOR_SIZE)
                    throw new Exception("WriteFile boot sector failed: " + Marshal.GetLastWin32Error()
                        + " (BPB write blocked — try elevating, or check Secure Boot policy)");

                if (result.LockSucceeded)
                    DeviceIoControl(h, FSCTL_UNLOCK_VOLUME, IntPtr.Zero, 0,
                        IntPtr.Zero, 0, out dummy, IntPtr.Zero);
            }
            finally { CloseHandle(h); }
            return result;
        }
    }


    // ============================================================
    // Shell helpers
    // ============================================================
    static class Sh
    {
        public class Result { public int ExitCode; public string StdOut; public string StdErr; }

        public static Result Run(string exe, string args)
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = exe; psi.Arguments = args;
            psi.UseShellExecute = false; psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true; psi.RedirectStandardError = true;
            using (Process p = Process.Start(psi))
            {
                string so = p.StandardOutput.ReadToEnd();
                string se = p.StandardError.ReadToEnd();
                p.WaitForExit();
                Result r = new Result();
                r.ExitCode = p.ExitCode; r.StdOut = so; r.StdErr = se;
                return r;
            }
        }

        public static bool ToolInPath(string exe)
        {
            try { return Run("where", exe).ExitCode == 0; }
            catch { return false; }
        }
    }


    // ============================================================
    // Pre-flight checks
    // ============================================================
    static class PreFlight
    {
        public class Check { public string Name; public bool Ok; public string Detail; }

        public static List<Check> Run()
        {
            List<Check> list = new List<Check>();

            bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent())
                            .IsInRole(WindowsBuiltInRole.Administrator);
            list.Add(new Check {
                Name = "Running as Administrator", Ok = admin,
                Detail = admin ? "OK" : "Restart this app as Administrator"
            });

            list.Add(new Check {
                Name = "Embedded NTFS BPB writer", Ok = true,
                Detail = "Native — no Sysinternals VolumeID dependency"
            });

            // PowerShell + Rename-Computer (always available on Windows 10+)
            Sh.Result ps = Sh.Run("powershell", "-Command Get-Command Rename-Computer");
            bool psOk = ps.ExitCode == 0;
            list.Add(new Check {
                Name = "PowerShell + Rename-Computer cmdlet", Ok = psOk,
                Detail = psOk ? "OK" : "Built into Windows 10/11 — should not fail"
            });

            return list;

            return list;
        }
    }


    // ============================================================
    // Main form
    // ============================================================
    public class MainForm : Form
    {
        Label lblHwidValue, lblVendorInfo, lblTitle, lblSubtitle;
        DarkTextBox txtTargetVol, txtTargetName;
        TextBox txtLog;
        AccentButton btnApply;
        GhostButton btnRefresh, btnRandom, btnDryRun, btnRevert, btnReboot;
        FlowLayoutPanel pnlChecks;

        string originalHwidSnapshot;

        public MainForm()
        {
            Text = "Cherax HWID Spoofer";
            ClientSize = new Size(880, 760);
            MinimumSize = new Size(880, 760);
            BackColor = Theme.Background;
            Font = Theme.UiRegular;
            ForeColor = Theme.Text;
            StartPosition = FormStartPosition.CenterScreen;

            BuildUi();
            RefreshCurrent();
            RefreshPreflight();
        }

        // ──────────────────────────────────────────────────────────
        // UI build
        // ──────────────────────────────────────────────────────────
        void BuildUi()
        {
            int padding = 24;
            int colW = ClientSize.Width - padding * 2;

            // === Header ===
            lblTitle = new Label();
            lblTitle.Text = "Cherax HWID Spoofer";
            lblTitle.Font = Theme.UiTitle;
            lblTitle.ForeColor = Theme.Text;
            lblTitle.AutoSize = true;
            lblTitle.Location = new Point(padding, 22);
            Controls.Add(lblTitle);

            lblSubtitle = new Label();
            lblSubtitle.Text = "Volume serial + computer name spoof  •  no driver, no TestSigning";
            lblSubtitle.Font = Theme.UiSubtitle;
            lblSubtitle.ForeColor = Theme.SubText;
            lblSubtitle.AutoSize = true;
            lblSubtitle.Location = new Point(padding, 56);
            Controls.Add(lblSubtitle);

            // Accent bar
            Panel accentBar = new Panel();
            accentBar.BackColor = Theme.Accent;
            accentBar.Location = new Point(padding, 50);
            accentBar.Size = new Size(3, 26);
            Controls.Add(accentBar);
            lblTitle.Location = new Point(padding + 12, 22);
            lblSubtitle.Location = new Point(padding + 12, 56);

            int y = 92;

            // === Current HWID card ===
            RoundedPanel card1 = NewCard(padding, y, colW, 100);
            Controls.Add(card1);
            AddSectionHeader(card1, "CURRENT MACHINE FINGERPRINT");
            lblHwidValue = new Label();
            lblHwidValue.Font = new Font("Cascadia Mono", 13f);
            lblHwidValue.ForeColor = Theme.Accent;
            lblHwidValue.AutoSize = false;
            lblHwidValue.Location = new Point(18, 42);
            lblHwidValue.Size = new Size(colW - 140, 24);
            card1.Controls.Add(lblHwidValue);

            btnRefresh = new GhostButton();
            btnRefresh.Text = "Refresh";
            btnRefresh.Size = new Size(96, 30);
            btnRefresh.Location = new Point(colW - 116, 38);
            btnRefresh.Click += delegate { RefreshCurrent(); RefreshPreflight(); };
            card1.Controls.Add(btnRefresh);

            lblVendorInfo = new Label();
            lblVendorInfo.Font = Theme.UiRegular;
            lblVendorInfo.ForeColor = Theme.SubText;
            lblVendorInfo.AutoSize = false;
            lblVendorInfo.Location = new Point(18, 70);
            lblVendorInfo.Size = new Size(colW - 36, 22);
            card1.Controls.Add(lblVendorInfo);
            y += 116;

            // === Target HWID card ===
            RoundedPanel card2 = NewCard(padding, y, colW, 154);
            Controls.Add(card2);
            AddSectionHeader(card2, "TARGET HWID");

            // labels + fields
            Label lblVol = new Label();
            lblVol.Text = "Volume serial (decimal):";
            lblVol.ForeColor = Theme.SubText; lblVol.Font = Theme.UiRegular;
            lblVol.Location = new Point(18, 50); lblVol.AutoSize = true;
            card2.Controls.Add(lblVol);
            txtTargetVol = new DarkTextBox();
            txtTargetVol.Location = new Point(18, 70);
            txtTargetVol.Size = new Size(280, 32);
            card2.Controls.Add(txtTargetVol);

            Label lblName = new Label();
            lblName.Text = "Computer name (≤15 chars, A-Z/0-9/-):";
            lblName.ForeColor = Theme.SubText; lblName.Font = Theme.UiRegular;
            lblName.Location = new Point(322, 50); lblName.AutoSize = true;
            card2.Controls.Add(lblName);
            txtTargetName = new DarkTextBox();
            txtTargetName.Location = new Point(322, 70);
            txtTargetName.Size = new Size(280, 32);
            card2.Controls.Add(txtTargetName);

            btnRandom = new GhostButton();
            btnRandom.Text = "🎲  Randomize";
            btnRandom.Size = new Size(180, 32);
            btnRandom.Location = new Point(18, 112);
            btnRandom.Click += delegate { GenerateRandom(); };
            card2.Controls.Add(btnRandom);

            Label lblNote = new Label();
            lblNote.Text = "CPU sum stays at real value (per-CPU-model, not unique per machine)";
            lblNote.ForeColor = Theme.SubText;
            lblNote.Font = new Font("Segoe UI", 8.5f, FontStyle.Italic);
            lblNote.Location = new Point(208, 119); lblNote.AutoSize = true;
            card2.Controls.Add(lblNote);
            y += 170;

            // === Pre-flight checks card ===
            RoundedPanel card3 = NewCard(padding, y, colW, 150);
            Controls.Add(card3);
            AddSectionHeader(card3, "PRE-FLIGHT CHECKS");
            pnlChecks = new FlowLayoutPanel();
            pnlChecks.FlowDirection = FlowDirection.TopDown;
            pnlChecks.WrapContents = false;
            pnlChecks.Location = new Point(18, 38);
            pnlChecks.Size = new Size(colW - 36, 104);
            pnlChecks.BackColor = Theme.Panel;
            card3.Controls.Add(pnlChecks);
            y += 166;

            // === Action buttons row ===
            btnDryRun = new GhostButton();
            btnDryRun.Text = "Dry-run plan";
            btnDryRun.Size = new Size(150, 36);
            btnDryRun.Location = new Point(padding, y);
            btnDryRun.Click += delegate { RunSpoof(false); };
            Controls.Add(btnDryRun);

            btnApply = new AccentButton();
            btnApply.Text = "⚡  Apply spoof";
            btnApply.Size = new Size(180, 36);
            btnApply.Location = new Point(padding + 160, y);
            btnApply.Click += delegate { RunSpoof(true); };
            Controls.Add(btnApply);

            btnRevert = new GhostButton();
            btnRevert.Text = "↶  Revert to snapshot";
            btnRevert.Size = new Size(180, 36);
            btnRevert.Location = new Point(padding + 350, y);
            btnRevert.Click += delegate { Revert(); };
            Controls.Add(btnRevert);

            btnReboot = new GhostButton();
            btnReboot.Text = "⟲  Reboot now";
            btnReboot.Size = new Size(140, 36);
            btnReboot.Location = new Point(padding + 540, y);
            btnReboot.BaseColor = Color.FromArgb(60, 30, 80);
            btnReboot.HoverColor = Color.FromArgb(90, 50, 110);
            btnReboot.BackColor = btnReboot.BaseColor;
            btnReboot.Click += delegate { RebootPrompt(); };
            Controls.Add(btnReboot);
            y += 50;

            // === Log ===
            txtLog = new TextBox();
            txtLog.Multiline = true;
            txtLog.ScrollBars = ScrollBars.Vertical;
            txtLog.ReadOnly = true;
            txtLog.BackColor = Theme.LogBg;
            txtLog.ForeColor = Theme.LogText;
            txtLog.Font = Theme.Mono;
            txtLog.BorderStyle = BorderStyle.None;
            txtLog.Location = new Point(padding, y);
            txtLog.Size = new Size(colW, ClientSize.Height - y - padding);
            txtLog.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            // Wrap log in a rounded panel for consistent visual
            RoundedPanel logFrame = new RoundedPanel();
            logFrame.BackColor = Theme.LogBg;
            logFrame.Location = new Point(padding - 1, y - 1);
            logFrame.Size = new Size(colW + 2, ClientSize.Height - y - padding + 2);
            logFrame.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            logFrame.Padding = new Padding(10);
            Controls.Add(logFrame);
            txtLog.Parent = logFrame;
            txtLog.Dock = DockStyle.Fill;
        }

        RoundedPanel NewCard(int x, int y, int w, int h)
        {
            RoundedPanel p = new RoundedPanel();
            p.BackColor = Theme.Panel;
            p.Location = new Point(x, y);
            p.Size = new Size(w, h);
            p.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            return p;
        }

        void AddSectionHeader(Control parent, string text)
        {
            Label lbl = new Label();
            lbl.Text = text;
            lbl.Font = new Font("Segoe UI", 8.5f, FontStyle.Bold);
            lbl.ForeColor = Theme.Accent;
            lbl.Location = new Point(18, 14);
            lbl.AutoSize = true;
            parent.Controls.Add(lbl);
        }

        // ──────────────────────────────────────────────────────────
        // Logic
        // ──────────────────────────────────────────────────────────
        void Log(string s)
        {
            if (InvokeRequired) { Invoke(new Action<string>(Log), new object[] { s }); return; }
            txtLog.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + s + "\r\n");
        }

        void RefreshCurrent()
        {
            try
            {
                string hwid = HwidCompute.FullHwid();
                lblHwidValue.Text = hwid;
                if (originalHwidSnapshot == null) originalHwidSnapshot = hwid;
                string vendor = HwidCompute.CpuVendor();
                lblVendorInfo.Text = "CPU vendor: " + vendor + "    •    snapshot stored: " + originalHwidSnapshot;
            }
            catch (Exception ex) { Log("refresh failed: " + ex.Message); }
        }

        void RefreshPreflight()
        {
            pnlChecks.Controls.Clear();
            foreach (PreFlight.Check c in PreFlight.Run())
            {
                Panel row = new Panel();
                row.Size = new Size(pnlChecks.Width - 2, 24);
                row.Margin = new Padding(0, 0, 0, 4);
                row.BackColor = Theme.Panel;
                Label dot = new Label();
                dot.Text = c.Ok ? "●" : "●";
                dot.ForeColor = c.Ok ? Theme.Success : Theme.Danger;
                dot.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
                dot.Location = new Point(0, 1); dot.AutoSize = true;
                row.Controls.Add(dot);
                Label name = new Label();
                name.Text = c.Name;
                name.ForeColor = Theme.Text;
                name.Font = Theme.UiRegular;
                name.Location = new Point(18, 1); name.AutoSize = true;
                row.Controls.Add(name);
                Label detail = new Label();
                detail.Text = c.Detail;
                detail.ForeColor = Theme.SubText;
                detail.Font = Theme.UiRegular;
                detail.Location = new Point(280, 1); detail.AutoSize = true;
                row.Controls.Add(detail);
                pnlChecks.Controls.Add(row);
            }
        }

        void GenerateRandom()
        {
            Random rnd = new Random();
            byte[] vb = new byte[4]; rnd.NextBytes(vb);
            txtTargetVol.Text = BitConverter.ToUInt32(vb, 0).ToString();
            string alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
            StringBuilder sb = new StringBuilder("DESKTOP-");
            for (int i = 0; i < 7; i++) sb.Append(alpha[rnd.Next(alpha.Length)]);
            txtTargetName.Text = sb.ToString();
            Log("Generated random target: " + txtTargetVol.Text + " / " + txtTargetName.Text);
        }

        void SetButtonsEnabled(bool en)
        {
            btnApply.Enabled = btnDryRun.Enabled = btnRevert.Enabled = btnRandom.Enabled = en;
            btnReboot.Enabled = en;
        }

        void RebootPrompt()
        {
            DialogResult r = MessageBox.Show(this,
                "Reboot now to activate computer-name change?\r\n\r\nUnsaved work in other apps will be lost.",
                "Reboot confirmation",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (r != DialogResult.Yes) { Log("Reboot cancelled."); return; }
            Log("Issuing: shutdown /r /t 5  (5-second delay to flush logs)");
            try
            {
                Sh.Run("shutdown", "/r /t 5 /c \"Cherax HWID Spoofer requested reboot\"");
                Log("Reboot scheduled. Save other work — system goes down in 5s.");
            }
            catch (Exception ex) { Log("Reboot failed: " + ex.Message); }
        }

        void RunSpoof(bool apply)
        {
            uint vol;
            if (!uint.TryParse(txtTargetVol.Text, out vol)) { Log("ERROR: bad vol_serial"); return; }
            string name = txtTargetName.Text == null ? "" : txtTargetName.Text.Trim();
            if (name.Length == 0 || name.Length > 15) { Log("ERROR: bad computer name (max 15)"); return; }

            Log("");
            Log("=== " + (apply ? "APPLY" : "DRY-RUN") + " ===");
            string targetHwid = vol + ";" + name + ";<unchanged>";
            Log("Target:  " + targetHwid);

            SetButtonsEnabled(false);
            ThreadPool.QueueUserWorkItem(delegate {
                try { ExecuteSpoof(vol, name, apply); }
                catch (Exception ex) { Log("ERROR: " + ex.Message); }
                finally
                {
                    Invoke(new Action(delegate {
                        SetButtonsEnabled(true);
                        RefreshPreflight();
                        if (apply) RefreshCurrent();
                    }));
                }
            });
        }

        void ExecuteSpoof(uint vol, string name, bool apply)
        {
            // Step 1: vol serial (embedded BPB writer — no external dependency)
            string vsnHex = string.Format("{0:X4}-{1:X4}", (vol >> 16) & 0xFFFF, vol & 0xFFFF);
            Log("[1/2] Volume serial → " + vol + "  (0x" + vol.ToString("X8") + " == " + vsnHex + ")");
            Log("      method: embedded NTFS/FAT32 BPB write on \\\\.\\C:");
            if (apply)
            {
                try
                {
                    var r = VolumeSerialChanger.Change('C', vol);
                    Log("      filesystem: " + r.Fs
                        + "    lock acquired: " + (r.LockSucceeded ? "yes" : "no (raw write OK on system drive)"));
                    Log("      old serial: 0x" + r.OldSerial.ToString("X8") + " (" + r.OldSerial + ")");
                    Log("      new serial: 0x" + r.NewSerial.ToString("X8") + " (" + r.NewSerial + ")");
                    Log("      ✓ BPB updated. GetVolumeInformationA will return new value on next call.");
                }
                catch (Exception ex)
                {
                    Log("      ✗ FAILED: " + ex.Message);
                }
            }

            // Step 2: computer name
            Log("[2/2] Computer name → " + name);
            Log("      cmd: Rename-Computer -NewName " + name + " -Force");
            if (apply)
            {
                Sh.Result r = Sh.Run("powershell",
                    "-NoProfile -NonInteractive -Command \"Rename-Computer -NewName '" + name + "' -Force\"");
                string err = r.StdErr == null ? "" : r.StdErr.Trim();
                Log("      exit=" + r.ExitCode + (err.Length > 0 ? "  err=" + err : ""));
                Log("      (takes effect on next reboot)");
            }

            Log("");
            Log(apply
                ? "APPLY complete. Reboot to activate computer-name change."
                : "DRY-RUN complete. Run Apply when ready.");
        }

        void Revert()
        {
            if (string.IsNullOrEmpty(originalHwidSnapshot))
            { Log("No snapshot stored — restart the app from the original system first."); return; }
            string[] parts = originalHwidSnapshot.Split(';');
            if (parts.Length != 3) { Log("Bad snapshot format"); return; }
            uint vol;
            if (!uint.TryParse(parts[0], out vol)) { Log("Snapshot vol parse failed"); return; }
            string name = parts[1];

            Log("");
            Log("=== REVERT to snapshot: " + originalHwidSnapshot + " ===");
            SetButtonsEnabled(false);
            ThreadPool.QueueUserWorkItem(delegate {
                try { ExecuteSpoof(vol, name, true); }
                catch (Exception ex) { Log("ERROR: " + ex.Message); }
                finally
                {
                    Invoke(new Action(delegate {
                        SetButtonsEnabled(true);
                        RefreshPreflight();
                        RefreshCurrent();
                    }));
                }
            });
        }
    }


    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
