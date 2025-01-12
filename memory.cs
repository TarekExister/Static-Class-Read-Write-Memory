using System;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace MemoryManagements.Memory
{
    public static class mem
    {
        public static IntPtr hProcess = IntPtr.Zero;
        public static int pid = 0;

        [Flags]
        private enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [Flags]
        private enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        private enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        public enum VirtualKeys
        : ushort
        {
            LeftButton = 0x01,
            RightButton = 0x02,
            Cancel = 0x03,
            MiddleButton = 0x04,
            ExtraButton1 = 0x05,
            ExtraButton2 = 0x06,
            Back = 0x08,
            Tab = 0x09,
            Clear = 0x0C,
            Return = 0x0D,
            Shift = 0x10,
            Control = 0x11,
            /// <summary></summary>
            Menu = 0x12,
            /// <summary></summary>
            Pause = 0x13,
            /// <summary></summary>
            CapsLock = 0x14,
            /// <summary></summary>
            Kana = 0x15,
            /// <summary></summary>
            Hangeul = 0x15,
            /// <summary></summary>
            Hangul = 0x15,
            /// <summary></summary>
            Junja = 0x17,
            /// <summary></summary>
            Final = 0x18,
            /// <summary></summary>
            Hanja = 0x19,
            /// <summary></summary>
            Kanji = 0x19,
            /// <summary></summary>
            Escape = 0x1B,
            /// <summary></summary>
            Convert = 0x1C,
            /// <summary></summary>
            NonConvert = 0x1D,
            /// <summary></summary>
            Accept = 0x1E,
            /// <summary></summary>
            ModeChange = 0x1F,
            /// <summary></summary>
            Space = 0x20,
            /// <summary></summary>
            Prior = 0x21,
            /// <summary></summary>
            Next = 0x22,
            /// <summary></summary>
            End = 0x23,
            /// <summary></summary>
            Home = 0x24,
            /// <summary></summary>
            Left = 0x25,
            /// <summary></summary>
            Up = 0x26,
            /// <summary></summary>
            Right = 0x27,
            /// <summary></summary>
            Down = 0x28,
            /// <summary></summary>
            Select = 0x29,
            /// <summary></summary>
            Print = 0x2A,
            /// <summary></summary>
            Execute = 0x2B,
            /// <summary></summary>
            Snapshot = 0x2C,
            /// <summary></summary>
            Insert = 0x2D,
            /// <summary></summary>
            Delete = 0x2E,
            /// <summary></summary>
            Help = 0x2F,
            /// <summary></summary>
            N0 = 0x30,
            /// <summary></summary>
            N1 = 0x31,
            /// <summary></summary>
            N2 = 0x32,
            /// <summary></summary>
            N3 = 0x33,
            /// <summary></summary>
            N4 = 0x34,
            /// <summary></summary>
            N5 = 0x35,
            /// <summary></summary>
            N6 = 0x36,
            /// <summary></summary>
            N7 = 0x37,
            /// <summary></summary>
            N8 = 0x38,
            /// <summary></summary>
            N9 = 0x39,
            /// <summary></summary>
            A = 0x41,
            /// <summary></summary>
            B = 0x42,
            /// <summary></summary>
            C = 0x43,
            /// <summary></summary>
            D = 0x44,
            /// <summary></summary>
            E = 0x45,
            /// <summary></summary>
            F = 0x46,
            /// <summary></summary>
            G = 0x47,
            /// <summary></summary>
            H = 0x48,
            /// <summary></summary>
            I = 0x49,
            /// <summary></summary>
            J = 0x4A,
            /// <summary></summary>
            K = 0x4B,
            /// <summary></summary>
            L = 0x4C,
            /// <summary></summary>
            M = 0x4D,
            /// <summary></summary>
            N = 0x4E,
            /// <summary></summary>
            O = 0x4F,
            /// <summary></summary>
            P = 0x50,
            /// <summary></summary>
            Q = 0x51,
            /// <summary></summary>
            R = 0x52,
            /// <summary></summary>
            S = 0x53,
            /// <summary></summary>
            T = 0x54,
            /// <summary></summary>
            U = 0x55,
            /// <summary></summary>
            V = 0x56,
            /// <summary></summary>
            W = 0x57,
            /// <summary></summary>
            X = 0x58,
            /// <summary></summary>
            Y = 0x59,
            /// <summary></summary>
            Z = 0x5A,
            /// <summary></summary>
            LeftWindows = 0x5B,
            /// <summary></summary>
            RightWindows = 0x5C,
            /// <summary></summary>
            Application = 0x5D,
            /// <summary></summary>
            Sleep = 0x5F,
            /// <summary></summary>
            Numpad0 = 0x60,
            /// <summary></summary>
            Numpad1 = 0x61,
            /// <summary></summary>
            Numpad2 = 0x62,
            /// <summary></summary>
            Numpad3 = 0x63,
            /// <summary></summary>
            Numpad4 = 0x64,
            /// <summary></summary>
            Numpad5 = 0x65,
            /// <summary></summary>
            Numpad6 = 0x66,
            /// <summary></summary>
            Numpad7 = 0x67,
            /// <summary></summary>
            Numpad8 = 0x68,
            /// <summary></summary>
            Numpad9 = 0x69,
            /// <summary></summary>
            Multiply = 0x6A,
            /// <summary></summary>
            Add = 0x6B,
            /// <summary></summary>
            Separator = 0x6C,
            /// <summary></summary>
            Subtract = 0x6D,
            /// <summary></summary>
            Decimal = 0x6E,
            /// <summary></summary>
            Divide = 0x6F,
            /// <summary></summary>
            F1 = 0x70,
            /// <summary></summary>
            F2 = 0x71,
            /// <summary></summary>
            F3 = 0x72,
            /// <summary></summary>
            F4 = 0x73,
            /// <summary></summary>
            F5 = 0x74,
            /// <summary></summary>
            F6 = 0x75,
            /// <summary></summary>
            F7 = 0x76,
            /// <summary></summary>
            F8 = 0x77,
            /// <summary></summary>
            F9 = 0x78,
            /// <summary></summary>
            F10 = 0x79,
            /// <summary></summary>
            F11 = 0x7A,
            /// <summary></summary>
            F12 = 0x7B,
            /// <summary></summary>
            F13 = 0x7C,
            /// <summary></summary>
            F14 = 0x7D,
            /// <summary></summary>
            F15 = 0x7E,
            /// <summary></summary>
            F16 = 0x7F,
            /// <summary></summary>
            F17 = 0x80,
            /// <summary></summary>
            F18 = 0x81,
            /// <summary></summary>
            F19 = 0x82,
            /// <summary></summary>
            F20 = 0x83,
            /// <summary></summary>
            F21 = 0x84,
            /// <summary></summary>
            F22 = 0x85,
            /// <summary></summary>
            F23 = 0x86,
            /// <summary></summary>
            F24 = 0x87,
            /// <summary></summary>
            NumLock = 0x90,
            /// <summary></summary>
            ScrollLock = 0x91,
            /// <summary></summary>
            NEC_Equal = 0x92,
            /// <summary></summary>
            Fujitsu_Jisho = 0x92,
            /// <summary></summary>
            Fujitsu_Masshou = 0x93,
            /// <summary></summary>
            Fujitsu_Touroku = 0x94,
            /// <summary></summary>
            Fujitsu_Loya = 0x95,
            /// <summary></summary>
            Fujitsu_Roya = 0x96,
            /// <summary></summary>
            LeftShift = 0xA0,
            /// <summary></summary>
            RightShift = 0xA1,
            /// <summary></summary>
            LeftControl = 0xA2,
            /// <summary></summary>
            RightControl = 0xA3,
            /// <summary></summary>
            LeftMenu = 0xA4,
            /// <summary></summary>
            RightMenu = 0xA5,
            /// <summary></summary>
            BrowserBack = 0xA6,
            /// <summary></summary>
            BrowserForward = 0xA7,
            /// <summary></summary>
            BrowserRefresh = 0xA8,
            /// <summary></summary>
            BrowserStop = 0xA9,
            /// <summary></summary>
            BrowserSearch = 0xAA,
            /// <summary></summary>
            BrowserFavorites = 0xAB,
            /// <summary></summary>
            BrowserHome = 0xAC,
            /// <summary></summary>
            VolumeMute = 0xAD,
            /// <summary></summary>
            VolumeDown = 0xAE,
            /// <summary></summary>
            VolumeUp = 0xAF,
            /// <summary></summary>
            MediaNextTrack = 0xB0,
            /// <summary></summary>
            MediaPrevTrack = 0xB1,
            /// <summary></summary>
            MediaStop = 0xB2,
            /// <summary></summary>
            MediaPlayPause = 0xB3,
            /// <summary></summary>
            LaunchMail = 0xB4,
            /// <summary></summary>
            LaunchMediaSelect = 0xB5,
            /// <summary></summary>
            LaunchApplication1 = 0xB6,
            /// <summary></summary>
            LaunchApplication2 = 0xB7,
            /// <summary></summary>
            OEM1 = 0xBA,
            /// <summary></summary>
            OEMPlus = 0xBB,
            /// <summary></summary>
            OEMComma = 0xBC,
            /// <summary></summary>
            OEMMinus = 0xBD,
            /// <summary></summary>
            OEMPeriod = 0xBE,
            /// <summary></summary>
            OEM2 = 0xBF,
            /// <summary></summary>
            OEM3 = 0xC0,
            /// <summary></summary>
            OEM4 = 0xDB,
            /// <summary></summary>
            OEM5 = 0xDC,
            /// <summary></summary>
            OEM6 = 0xDD,
            /// <summary></summary>
            OEM7 = 0xDE,
            /// <summary></summary>
            OEM8 = 0xDF,
            /// <summary></summary>
            OEMAX = 0xE1,
            /// <summary></summary>
            OEM102 = 0xE2,
            /// <summary></summary>
            ICOHelp = 0xE3,
            /// <summary></summary>
            ICO00 = 0xE4,
            /// <summary></summary>
            ProcessKey = 0xE5,
            /// <summary></summary>
            ICOClear = 0xE6,
            /// <summary></summary>
            Packet = 0xE7,
            /// <summary></summary>
            OEMReset = 0xE9,
            /// <summary></summary>
            OEMJump = 0xEA,
            /// <summary></summary>
            OEMPA1 = 0xEB,
            /// <summary></summary>
            OEMPA2 = 0xEC,
            /// <summary></summary>
            OEMPA3 = 0xED,
            /// <summary></summary>
            OEMWSCtrl = 0xEE,
            /// <summary></summary>
            OEMCUSel = 0xEF,
            /// <summary></summary>
            OEMATTN = 0xF0,
            /// <summary></summary>
            OEMFinish = 0xF1,
            /// <summary></summary>
            OEMCopy = 0xF2,
            /// <summary></summary>
            OEMAuto = 0xF3,
            /// <summary></summary>
            OEMENLW = 0xF4,
            /// <summary></summary>
            OEMBackTab = 0xF5,
            /// <summary></summary>
            ATTN = 0xF6,
            /// <summary></summary>
            CRSel = 0xF7,
            /// <summary></summary>
            EXSel = 0xF8,
            /// <summary></summary>
            EREOF = 0xF9,
            /// <summary></summary>
            Play = 0xFA,
            /// <summary></summary>
            Zoom = 0xFB,
            /// <summary></summary>
            Noname = 0xFC,
            /// <summary></summary>
            PA1 = 0xFD,
            /// <summary></summary>
            OEMClear = 0xFE
        }


        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);


        [DllImport("User32.dll")]
        public static extern short GetAsyncKeyState(ushort _key);
        [DllImport("user32.dll", EntryPoint = "GetWindowLong")]
        private static extern IntPtr GetWindowLong(IntPtr hWnd, int nIndex);
        [DllImport("user32.dll", EntryPoint = "SetWindowLong")]
        private static extern int SetWindowLong32(IntPtr hWnd, int nIndex, int dwNewLong);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left;        // x position of upper-left corner
            public int Top;         // y position of upper-left corner
            public int Right;       // x position of lower-right corner
            public int Bottom;      // y position of lower-right corner
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
        private const uint MEM_FREE = 0x10000;
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        public static bool AttachProcess(string processName)
        {

            Process[] processList = Process.GetProcesses();
            foreach (Process p in processList)
            {
                if (p.ProcessName.Equals(processName))
                {
                    pid = p.Id;
                    hProcess = OpenProcess(ProcessAccessFlags.All, false, pid);
                    return true;
                }
            }


            return false;
        }

        public static int GetProcessID(string ProcessName)
        {
            Process[] ProcessList = Process.GetProcesses();
            int ProcessID = 0;
            foreach (Process _this_process in ProcessList)
            {
                if (ProcessName == _this_process.ProcessName) { ProcessID = _this_process.Id; }
            }
            return ProcessID;
        }

        public static IntPtr GetModuleAddress(string processName, string moduleName)
        {
            IntPtr modAddress = IntPtr.Zero;
            Process[] procList = Process.GetProcessesByName(processName);
            Process pModule = procList[0];
            foreach (ProcessModule module in pModule.Modules)
            {
                if (module.ModuleName.Equals(moduleName.Insert(moduleName.Length, ".exe")))
                {
                    modAddress = module.BaseAddress;
                }
            }
            return modAddress;
        }


        public static IntPtr GetDllsModuleAddress(string processName, string moduleName)
        {
            IntPtr modAddress = IntPtr.Zero;
            Process[] procList = Process.GetProcessesByName(processName);
            Process pModule = procList[0];
            foreach (ProcessModule module in pModule.Modules)
            {
                if (module.ModuleName.Equals(moduleName.Insert(moduleName.Length, ".dll")))
                {
                    modAddress = module.BaseAddress;
                }
            }
            return modAddress;
        }


        public static IntPtr GetUWPWindowHandle()
        {
            Process[] procs = Process.GetProcessesByName("ApplicationFrameHost");
            return procs[0].MainWindowHandle;
        }

        public static byte[] ReadBytes(IntPtr address, int size)
        {
            byte[] bts = new byte[size];
            IntPtr readbts = IntPtr.Zero;
            ReadProcessMemory(hProcess, address, bts, size, out readbts);
            return bts;
        }

        public static void WriteBytes(IntPtr address, byte[] buffer, int size)
        {
            IntPtr readbts = IntPtr.Zero;
            WriteProcessMemory(hProcess, address, buffer, size, out readbts);
        }

        unsafe public static IntPtr GetPointerAddress32Bit(IntPtr BaseAddress, int[] offsets, int PointerLevel)
        {
            IntPtr address = BaseAddress;
            IntPtr tmp = IntPtr.Zero;

            for (int x = 0; x < PointerLevel; x++)
            {
                byte[] buffer = ReadBytes(address, sizeof(IntPtr));
                tmp = (IntPtr)(BitConverter.ToInt32(buffer, 0));
                address = tmp + offsets[x];
            }
            return address;
        }

        unsafe public static IntPtr GetPointerAddress64Bit(IntPtr BaseAddress, int[] offsets, int PointerLevel)
        {
            IntPtr address = BaseAddress;
            IntPtr tmp = IntPtr.Zero;

            for (int x = 0; x < PointerLevel; x++)
            {
                byte[] buffer = ReadBytes(address, sizeof(IntPtr));
                tmp = (IntPtr)(BitConverter.ToInt64(buffer, 0));
                address = tmp + offsets[x];
            }
            return address;
        }


        private static IntPtr FindNearestFreePage( IntPtr address)
        {
            IntPtr currentAddress = address;
            const long MaxSearchDistance = 0xF00000; // 1 MB search range
            const long PageSize = 0x1000; // 4 KB page size

            // Search forward and backward within range
            for (long offset = 0; offset < MaxSearchDistance; offset += PageSize)
            {
                IntPtr forwardAddress = AlignToPageBoundary(IntPtr.Add(currentAddress, (int)offset));
                IntPtr backwardAddress = AlignToPageBoundary(IntPtr.Subtract(currentAddress, (int)offset));

                if (IsPageFree(hProcess, forwardAddress))
                    return forwardAddress;

                if (IsPageFree(hProcess, backwardAddress))
                    return backwardAddress;
            }

            return IntPtr.Zero;
        }

        private static IntPtr AlignToPageBoundary(IntPtr address)
        {
            const long PageSize = 0x1000; // 4 KB page size
            long addr = address.ToInt64();
            return (IntPtr)(addr & ~(PageSize - 1)); // Align to nearest lower page boundary
        }

        private static bool IsPageFree(IntPtr hProcess, IntPtr address)
        {
            MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
            if (VirtualQueryEx(hProcess, address, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != false)
            {
                return mbi.State == MEM_FREE;
            }
            return false;
        }

        public static IntPtr AllocateMemory(IntPtr Address)
        {
            IntPtr _NearestFreePage = FindNearestFreePage(Address);
            if (_NearestFreePage != IntPtr.Zero) 
            {
               return VirtualAllocEx(hProcess, _NearestFreePage, 0x1000, (uint)(AllocationType.Commit | AllocationType.Reserve), (uint)MemoryProtection.ExecuteReadWrite);
            }
            else return IntPtr.Zero;
        }


        unsafe public static T Read<T>(IntPtr address)
        {
            object val = 0;

            if (typeof(T) == typeof(int))
            {
                val = BitConverter.ToInt32(ReadBytes(address, sizeof(int)), 0);
            }
            else if (typeof(T) == typeof(uint))
            {
                val = BitConverter.ToUInt32(ReadBytes(address, sizeof(uint)), 0);
            }
            else if (typeof(T) == typeof(long))
            {
                val = BitConverter.ToInt64(ReadBytes(address, sizeof(long)), 0);
            }
            else if (typeof(T) == typeof(byte))
            {
                val = ReadBytes(address, sizeof(byte))[0];
            }
            else if (typeof(T) == typeof(IntPtr))
            {
                val = BitConverter.ToUInt32(ReadBytes(address, sizeof(IntPtr)), 0);
            }
            else if (typeof(T) == typeof(UIntPtr))
            {
                val = BitConverter.ToUInt64(ReadBytes(address, sizeof(UIntPtr)), 0);
            }
            else if (typeof(T) == typeof(float))
            {
                val = BitConverter.ToSingle(ReadBytes(address, sizeof(float)), 0);
            }
            else if (typeof(T) == typeof(double))
            {
                val = BitConverter.ToDouble(ReadBytes(address, sizeof(double)), 0);
            }

            return (T)Convert.ChangeType(val, typeof(T));
        }


        unsafe public static void Write<T>(IntPtr address, T value)
        {

            if (typeof(T) == typeof(int))
            {
                int val = (int)Convert.ChangeType(value, typeof(int));
                byte[] buffer = BitConverter.GetBytes(val);
                WriteBytes(address, buffer, sizeof(int));

            }
            else if (typeof(T) == typeof(uint))
            {
                uint val = (uint)Convert.ChangeType(value, typeof(uint));
                byte[] buffer = BitConverter.GetBytes(val);
                WriteBytes(address, buffer, sizeof(uint));
            }
            else if (typeof(T) == typeof(long))
            {
                long val = (long)Convert.ChangeType(value, typeof(long));
                byte[] buffer = BitConverter.GetBytes(val);
                WriteBytes(address, buffer, sizeof(long));
            }
            else if (typeof(T) == typeof(float))
            {
                float val = (float)Convert.ChangeType(value, typeof(float));
                byte[] buffer = BitConverter.GetBytes(val);
                WriteBytes(address, buffer, sizeof(float));
            }
            else if (typeof(T) == typeof(double))
            {
                double val = (double)Convert.ChangeType(value, typeof(double));
                byte[] buffer = BitConverter.GetBytes(val);
                WriteBytes(address, buffer, sizeof(double));
            }
            else if (typeof(T) == typeof(byte))
            {
                byte val = (byte)Convert.ChangeType(value, typeof(byte));
                byte[] buffer = BitConverter.GetBytes(val);
                WriteBytes(address, buffer, sizeof(byte));
            }
            else if (typeof(T) == typeof(IntPtr))
            {
                IntPtr val = (IntPtr)Convert.ChangeType(value, typeof(IntPtr));
                byte[] buffer = BitConverter.GetBytes((uint)val);
                WriteBytes(address, buffer, sizeof(IntPtr));
            }
            else if (typeof(T) == typeof(UIntPtr))
            {
                UIntPtr val = (UIntPtr)Convert.ChangeType(value, typeof(UIntPtr));
                byte[] buffer = BitConverter.GetBytes((uint)val);
                WriteBytes(address, buffer, sizeof(UIntPtr));
            }
        }
    }
}
