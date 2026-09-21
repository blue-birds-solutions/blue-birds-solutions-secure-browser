# scripts/keyboard-lock.ps1 - Bluebirds Secure Browser Low-Level OS Keyboard Hook
# Intercepts and completely suppresses Windows Key, Alt+Tab, Alt+Esc, Ctrl+Esc, Alt+Space,
# Alt+R (AMD ReLive), Alt+Z (Nvidia GeForce Overlay), Win+G (Xbox Game Bar),
# and Win+Arrow / Win+D / Win+M (window snap/minimize) at the Windows OS kernel level.

$signature = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class LowLevelKeyboardHook
{
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;
    private const int WM_KEYUP = 0x0101;
    private const int WM_SYSKEYDOWN = 0x0104;
    private const int WM_SYSKEYUP = 0x0105;

    private const int VK_TAB = 0x09;
    private const int VK_ESCAPE = 0x1B;
    private const int VK_SPACE = 0x20;
    private const int VK_LWIN = 0x5B;
    private const int VK_RWIN = 0x5C;
    private const int VK_CONTROL = 0x11;
    private const int LLKHF_ALTDOWN = 0x20;
    // Additional keys to block for GPU overlay and window-snap bypass prevention
    private const int VK_R = 0x52;     // Alt+R = AMD Adrenalin ReLive record
    private const int VK_Z = 0x5A;     // Alt+Z = Nvidia GeForce Experience overlay
    private const int VK_G = 0x47;     // Win+G = Xbox Game Bar
    private const int VK_D = 0x44;     // Win+D = Show Desktop
    private const int VK_M = 0x4D;     // Win+M = Minimize All
    private const int VK_LEFT = 0x25;  // Win+Left = Snap Left
    private const int VK_RIGHT = 0x27; // Win+Right = Snap Right
    private const int VK_UP = 0x26;    // Win+Up = Maximize
    private const int VK_DOWN = 0x28;  // Win+Down = Minimize / Snap Down
    private const int VK_HOME = 0x24;  // Win+Home = Minimize Others

    [StructLayout(LayoutKind.Sequential)]
    public struct KBDLLHOOKSTRUCT
    {
        public int vkCode;
        public int scanCode;
        public int flags;
        public int time;
        public IntPtr dwExtraInfo;
    }

    public delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("user32.dll")]
    public static extern short GetKeyState(int nVirtKey);

    [DllImport("user32.dll")]
    public static extern int GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [DllImport("user32.dll")]
    public static extern bool TranslateMessage([In] ref MSG lpMsg);

    [DllImport("user32.dll")]
    public static extern IntPtr DispatchMessage([In] ref MSG lpMsg);

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT
    {
        public int x;
        public int y;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public POINT pt;
    }

    private static HookProc _proc = HookCallback;
    private static IntPtr _hookID = IntPtr.Zero;

    public static void SetHook()
    {
        using (Process curProcess = Process.GetCurrentProcess())
        using (ProcessModule curModule = curProcess.MainModule)
        {
            _hookID = SetWindowsHookEx(WH_KEYBOARD_LL, _proc, GetModuleHandle(curModule.ModuleName), 0);
        }
    }

    public static void ReleaseHook()
    {
        if (_hookID != IntPtr.Zero)
        {
            UnhookWindowsHookEx(_hookID);
            _hookID = IntPtr.Zero;
        }
    }

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0)
        {
            KBDLLHOOKSTRUCT hookStruct = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));
            int vkCode = hookStruct.vkCode;
            bool isAltDown = (hookStruct.flags & LLKHF_ALTDOWN) != 0;
            bool isWinDown = (GetKeyState(VK_LWIN) & 0x8000) != 0 ||
                             (GetKeyState(VK_RWIN) & 0x8000) != 0;

            // 1. Block Windows Keys (Left and Right WinKey)
            if (vkCode == VK_LWIN || vkCode == VK_RWIN)
            {
                return (IntPtr)1;
            }

            // 2. Block Alt+Tab, Alt+Esc, Alt+Space
            if (isAltDown && (vkCode == VK_TAB || vkCode == VK_ESCAPE || vkCode == VK_SPACE))
            {
                return (IntPtr)1;
            }

            // 3. Block Ctrl+Esc
            if (vkCode == VK_ESCAPE)
            {
                short ctrlState = GetKeyState(VK_CONTROL);
                if ((ctrlState & 0x8000) != 0)
                {
                    return (IntPtr)1;
                }
            }

            // 4. Block Alt+R (AMD Adrenalin ReLive / recording toggle)
            if (isAltDown && vkCode == VK_R)
            {
                return (IntPtr)1;
            }

            // 5. Block Alt+Z (Nvidia GeForce Experience overlay toggle)
            if (isAltDown && vkCode == VK_Z)
            {
                return (IntPtr)1;
            }

            // 6. Block Win+G (Xbox Game Bar)
            //    Win+D (Show Desktop), Win+M (Minimize All)
            //    Win+Left/Right/Up/Down (window snap), Win+Home (minimize others)
            if (isWinDown && (
                vkCode == VK_G ||
                vkCode == VK_D ||
                vkCode == VK_M ||
                vkCode == VK_LEFT ||
                vkCode == VK_RIGHT ||
                vkCode == VK_UP ||
                vkCode == VK_DOWN ||
                vkCode == VK_HOME
            ))
            {
                return (IntPtr)1;
            }
        }
        return CallNextHookEx(_hookID, nCode, wParam, lParam);
    }

    public static void RunMessagePump()
    {
        MSG msg;
        while (GetMessage(out msg, IntPtr.Zero, 0, 0) > 0)
        {
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }
    }
}
"@

Add-Type -TypeDefinition $signature

[LowLevelKeyboardHook]::SetHook()

[System.AppDomain]::CurrentDomain.add_ProcessExit({
    [LowLevelKeyboardHook]::ReleaseHook()
})

[LowLevelKeyboardHook]::RunMessagePump()
