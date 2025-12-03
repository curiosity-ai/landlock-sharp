namespace Sandbox;


using System;
using System.Runtime.InteropServices;
using System.Text;

/// <summary>
/// Minimal C# wrapper for the Linux Landlock syscalls (x86_64 syscall numbers).
/// </summary>
public sealed class Landlock
{
    public static bool IsSupported() => OperatingSystem.IsLinux() && RuntimeInformation.ProcessArchitecture == Architecture.X64;

    //Reference: https://man7.org/linux/man-pages/man7/landlock.7.html
    //           https://github.com/torvalds/linux/blob/master/security/landlock/ruleset.h

    // --- x86_64 syscall numbers (update if you target a different arch) ---
    private const long SYS_landlock_create_ruleset = 444;
    private const long SYS_landlock_add_rule = 445;
    private const long SYS_landlock_restrict_self = 446;

    // --- landlock query version flags ---
    private const uint LANDLOCK_CREATE_RULESET_VERSION = 1u << 0;

    // --- rule types ---
    private const uint LANDLOCK_RULE_PATH_BENEATH = 1;

    public enum FileSystem
    {
        CORE,
        EXECUTE,
        WRITE_FILE,
        READ_FILE,
        READ_DIR,
        REMOVE_DIR,
        REMOVE_FILE,
        MAKE_CHAR,
        MAKE_DIR,
        MAKE_REG,
        MAKE_SOCK,
        MAKE_FIFO,
        MAKE_BLOCK,
        MAKE_SYM,
        REFER,
        TRUNCATE,
        IOCTL_DEV,
    }
    public enum Network
    {
        BIND_TCP,
        CONNECT_TCP,
    }

    public enum Scope
    {
        ABSTRACT_UNIX_SOCKET,
        SIGNAL,
    }

    private static IEnumerable<Network> Filter(IEnumerable<Network> restrictions)
    {
        var abi = GetAbiVersion();

        foreach (var r in restrictions)
        {
            var minAbi = -1;

            switch (r)
            {
                case Network.BIND_TCP:
                case Network.CONNECT_TCP: minAbi = 4; break;
            }
            if (abi >= minAbi) yield return r;
        }
    }


    private static IEnumerable<Scope> Filter(IEnumerable<Scope> restrictions)
    {
        var abi = GetAbiVersion();

        foreach (var r in restrictions)
        {
            var minAbi = -1;

            switch (r)
            {
                case Scope.ABSTRACT_UNIX_SOCKET:
                case Scope.SIGNAL: minAbi = 6; break;
            }
            if (abi >= minAbi) yield return r;
        }
    }
    private static IEnumerable<FileSystem> Filter(IEnumerable<FileSystem> restrictions)
    {
        var abi = GetAbiVersion();

        foreach(var r in restrictions)
        {
            if (r == FileSystem.CORE)
            {
                foreach(var r2 in Filter([
                    FileSystem.EXECUTE,
                    FileSystem.WRITE_FILE,
                    FileSystem.READ_FILE,
                    FileSystem.READ_DIR,
                    FileSystem.REMOVE_DIR,
                    FileSystem.REMOVE_FILE,
                    FileSystem.MAKE_CHAR,
                    FileSystem.MAKE_DIR,
                    FileSystem.MAKE_REG,
                    FileSystem.MAKE_BLOCK,
                    FileSystem.MAKE_SYM,
                    FileSystem.REFER,
                    FileSystem.TRUNCATE]))
                {
                    yield return r2;
                }
            }
            else
            {
                var minAbi = -1;

                switch (r)
                {
                    case FileSystem.EXECUTE:
                    case FileSystem.WRITE_FILE:
                    case FileSystem.READ_FILE:
                    case FileSystem.READ_DIR:
                    case FileSystem.REMOVE_DIR:
                    case FileSystem.REMOVE_FILE:
                    case FileSystem.MAKE_CHAR:
                    case FileSystem.MAKE_DIR:
                    case FileSystem.MAKE_REG:
                    case FileSystem.MAKE_SOCK:
                    case FileSystem.MAKE_FIFO:
                    case FileSystem.MAKE_BLOCK:
                    case FileSystem.MAKE_SYM: minAbi = 1; break;
                    case FileSystem.REFER: minAbi = 2; break;
                    case FileSystem.TRUNCATE: minAbi = 3; break;
                    case FileSystem.IOCTL_DEV: minAbi = 5; break;

                    default: minAbi = int.MaxValue; break;
                }

                if (abi >= minAbi) yield return r;
            }
        }

        // Table from https://man7.org/linux/man-pages/man7/landlock.7.html
        //┌─────┬────────┬─────────────────────────────────────────────────┐
        //│ ABI │ Kernel │ Newly introduced access rights                  │
        //├─────┼────────┼─────────────────────────────────────────────────┤
        //│  1  │  5.13  │ LANDLOCK_ACCESS_FS_EXECUTE                      │
        //│     │        │ LANDLOCK_ACCESS_FS_WRITE_FILE                   │
        //│     │        │ LANDLOCK_ACCESS_FS_READ_FILE                    │
        //│     │        │ LANDLOCK_ACCESS_FS_READ_DIR                     │
        //│     │        │ LANDLOCK_ACCESS_FS_REMOVE_DIR                   │
        //│     │        │ LANDLOCK_ACCESS_FS_REMOVE_FILE                  │
        //│     │        │ LANDLOCK_ACCESS_FS_MAKE_CHAR                    │
        //│     │        │ LANDLOCK_ACCESS_FS_MAKE_DIR                     │
        //│     │        │ LANDLOCK_ACCESS_FS_MAKE_REG                     │
        //│     │        │ LANDLOCK_ACCESS_FS_MAKE_SOCK                    │
        //│     │        │ LANDLOCK_ACCESS_FS_MAKE_FIFO                    │
        //│     │        │ LANDLOCK_ACCESS_FS_MAKE_BLOCK                   │
        //│     │        │ LANDLOCK_ACCESS_FS_MAKE_SYM                     │
        //├─────┼────────┼─────────────────────────────────────────────────┤
        //│  2  │  5.19  │ LANDLOCK_ACCESS_FS_REFER                        │
        //├─────┼────────┼─────────────────────────────────────────────────┤
        //│  3  │  6.2   │ LANDLOCK_ACCESS_FS_TRUNCATE                     │
        //├─────┼────────┼─────────────────────────────────────────────────┤
        //│  4  │  6.7   │ LANDLOCK_ACCESS_NET_BIND_TCP                    │
        //│     │        │ LANDLOCK_ACCESS_NET_CONNECT_TCP                 │
        //├─────┼────────┼─────────────────────────────────────────────────┤
        //│  5  │  6.10  │ LANDLOCK_ACCESS_FS_IOCTL_DEV                    │
        //├─────┼────────┼─────────────────────────────────────────────────┤
        //│  6  │  6.12  │ LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET             │
        //│     │        │ LANDLOCK_SCOPE_SIGNAL                           │
        //└─────┴────────┴─────────────────────────────────────────────────┘
    }

    private static ulong Merge(IEnumerable<FileSystem> restrictions)
    {
        ulong ret = 0;

        foreach(var r in restrictions)
        {
            switch (r)
            {
                case FileSystem.EXECUTE              :ret |= LANDLOCK_ACCESS_FS_EXECUTE;      break;
                case FileSystem.WRITE_FILE           :ret |= LANDLOCK_ACCESS_FS_WRITE_FILE;   break;
                case FileSystem.READ_FILE            :ret |= LANDLOCK_ACCESS_FS_READ_FILE;    break;
                case FileSystem.READ_DIR             :ret |= LANDLOCK_ACCESS_FS_READ_DIR;     break;
                case FileSystem.REMOVE_DIR           :ret |= LANDLOCK_ACCESS_FS_REMOVE_DIR;   break;
                case FileSystem.REMOVE_FILE          :ret |= LANDLOCK_ACCESS_FS_REMOVE_FILE;  break;
                case FileSystem.MAKE_CHAR            :ret |= LANDLOCK_ACCESS_FS_MAKE_CHAR;    break;
                case FileSystem.MAKE_DIR             :ret |= LANDLOCK_ACCESS_FS_MAKE_DIR;     break;
                case FileSystem.MAKE_REG             :ret |= LANDLOCK_ACCESS_FS_MAKE_REG;     break;
                case FileSystem.MAKE_SOCK            :ret |= LANDLOCK_ACCESS_FS_MAKE_SOCK;    break;
                case FileSystem.MAKE_FIFO            :ret |= LANDLOCK_ACCESS_FS_MAKE_FIFO;    break;
                case FileSystem.MAKE_BLOCK           :ret |= LANDLOCK_ACCESS_FS_MAKE_BLOCK;   break;
                case FileSystem.MAKE_SYM             :ret |= LANDLOCK_ACCESS_FS_MAKE_SYM;     break;
                case FileSystem.REFER                :ret |= LANDLOCK_ACCESS_FS_REFER;        break;
                case FileSystem.TRUNCATE             :ret |= LANDLOCK_ACCESS_FS_TRUNCATE;     break;
                case FileSystem.IOCTL_DEV            :ret |= LANDLOCK_ACCESS_FS_IOCTL_DEV;    break;
            }
        }

        return ret;
    }
    private static ulong Merge(IEnumerable<Network> restrictions)
    {
        ulong ret = 0;

        foreach(var r in restrictions)
        {
            switch (r)
            {
                case Network.CONNECT_TCP                 :ret |= LANDLOCK_ACCESS_NET_CONNECT_TCP;      break;
                case Network.BIND_TCP                    :ret |= LANDLOCK_ACCESS_NET_BIND_TCP;   break;
            }
        }

        return ret;
    }

    private static ulong Merge(IEnumerable<Scope> restrictions)
    {
        ulong ret = 0;

        foreach(var r in restrictions)
        {
            switch (r)
            {
                case Scope.SIGNAL                    :ret |= LANDLOCK_SCOPE_SIGNAL;      break;
                case Scope.ABSTRACT_UNIX_SOCKET      :ret |= LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET;   break;
            }
        }

        return ret;
    }

    // --- filesystem access masks  ---
    private const ulong LANDLOCK_ACCESS_FS_EXECUTE           = (1UL << 0);
    private const ulong LANDLOCK_ACCESS_FS_WRITE_FILE        = (1UL << 1);
    private const ulong LANDLOCK_ACCESS_FS_READ_FILE         = (1UL << 2);
    private const ulong LANDLOCK_ACCESS_FS_READ_DIR          = (1UL << 3);
    private const ulong LANDLOCK_ACCESS_FS_REMOVE_DIR        = (1UL << 4);
    private const ulong LANDLOCK_ACCESS_FS_REMOVE_FILE       = (1UL << 5);
    private const ulong LANDLOCK_ACCESS_FS_MAKE_CHAR         = (1UL << 6);
    private const ulong LANDLOCK_ACCESS_FS_MAKE_DIR          = (1UL << 7);
    private const ulong LANDLOCK_ACCESS_FS_MAKE_REG          = (1UL << 8);
    private const ulong LANDLOCK_ACCESS_FS_MAKE_SOCK         = (1UL << 9);
    private const ulong LANDLOCK_ACCESS_FS_MAKE_FIFO         = (1UL << 10);
    private const ulong LANDLOCK_ACCESS_FS_MAKE_BLOCK        = (1UL << 11);
    private const ulong LANDLOCK_ACCESS_FS_MAKE_SYM          = (1UL << 12);
    private const ulong LANDLOCK_ACCESS_FS_REFER             = (1UL << 13);
    private const ulong LANDLOCK_ACCESS_FS_TRUNCATE          = (1UL << 14);
    private const ulong LANDLOCK_ACCESS_FS_IOCTL_DEV         = (1UL << 15);

    private const ulong LANDLOCK_ACCESS_NET_BIND_TCP         = (1UL << 0);
    private const ulong LANDLOCK_ACCESS_NET_CONNECT_TCP      = (1UL << 1);

    private const ulong LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET = (1UL << 0);
    private const ulong LANDLOCK_SCOPE_SIGNAL               = (1UL << 1);

    //Not yet available: private const ulong LANDLOCK_RESTRICT_SELF_TSYNC = (1UL << 0);

    // --- helpers for opening directories for rules (O_PATH) ---
    private const int O_PATH = 0x200000; // Linux O_PATH flag (open(2)). Confirm on target platform.
    private int _ruleSetHandle;
    private bool _alreadyEnforced;

    // --- P/Invoke signatures ---
    [DllImport("libc", SetLastError = true)]
    private static extern nint syscall(long number, int arg1, uint arg2);

    [DllImport("libc", SetLastError = true)]
    private static extern nint syscall(long number, nint arg1, nint arg2);

    [DllImport("libc", SetLastError = true)]
    private static extern nint syscall(long number, int arg1, nint arg2, uint arg3);
    [DllImport("libc", SetLastError = true)]
    private static extern nint syscall(long number, nint arg1, nint arg2, uint arg3);

    [DllImport("libc", SetLastError = true)]
    private static extern nint syscall(long number, int arg1, uint arg2, nint arg3, nint arg4);

    [DllImport("libc", SetLastError = true)]
    private static extern nint syscall(long number, int arg1, uint arg2, uint arg3);

    [DllImport("libc", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int open([MarshalAs(UnmanagedType.LPStr)] string pathname, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    const int PR_SET_NO_NEW_PRIVS = 38; // value from <linux/prctl.h>

    [DllImport("libc", SetLastError = true)]
    private static extern int prctl(int option, ulong arg2, ulong arg3, ulong arg4, ulong arg5);


    // --- user-space ABI structs (packed to match kernel UAPI) ---
    // struct landlock_ruleset_attr { __u64 handled_access_fs; };
    [StructLayout(LayoutKind.Sequential)]
    private struct landlock_ruleset_attr
    {
        public ulong handled_access_fs;
        public ulong handled_access_net;
        public ulong scoped;
    }

    // struct landlock_path_beneath_attr { __u64 allowed_access; __s32 parent_fd; /* padding */ };
    [StructLayout(LayoutKind.Sequential)]
    private struct landlock_path_beneath_attr
    {
        public ulong allowed_access;
        public int parent_fd;
        private int _padding; // ensure same size/align as kernel ABI
    }

    /// <summary>
    /// Query the highest supported Landlock ABI version.
    /// Returns ABI version (>= 1) on success, or throws on error.
    /// </summary>
    public static int GetAbiVersion()
    {
        // Per manpage: call landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
        long ret = syscall(SYS_landlock_create_ruleset, 0, 0, LANDLOCK_CREATE_RULESET_VERSION);
        if (ret < 0)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "landlock_create_ruleset (version query) failed");
        return (int)ret;
    }


    private Landlock(int handle)
    {
        _ruleSetHandle = handle;
    }

    /// <summary>
    /// Create a Landlock ruleset describing which file system access will be handled.
    /// <paramref name="fileSystem">File system restrictions that will be denied by default unless explicitly allowed. Use <seealso cref="FileSystem.CORE"/> for a default set covering standard file system restrictions.</paramref>
    /// </summary>
    public static Landlock CreateRuleset(params FileSystem[] fileSystem) => CreateRuleset(fileSystem, null, null);

    /// <summary>
    /// Create a Landlock ruleset describing which file system access will be handled.
    /// <paramref name="network">Network restrictions that will be denied by default unless explicitly allowed</paramref>
    /// </summary>
    public static Landlock CreateRuleset(params Network[] network) => CreateRuleset(null, network, null);

    /// <summary>
    /// Create a Landlock ruleset describing which file system access will be handled.
    /// <paramref name="fileSystem">File system restrictions that will be denied by default unless explicitly allowed. Use <seealso cref="FileSystem.CORE"/> for a default set covering standard file system restrictions.</paramref>
    /// <paramref name="network">Network restrictions that will be denied by default unless explicitly allowed</paramref>
    /// <paramref name="scope">Enable isolating a sandboxed process from a set of IPC actions. Setting a scope flag for a ruleset will isolate the Landlock domain to forbid connections to resources outside the domain.</paramref>
    /// </summary>
    public static Landlock CreateRuleset(FileSystem[] fileSystem, Network[] network, Scope[] scope = null)
    {
        var attr = new landlock_ruleset_attr
        {
            handled_access_fs  = fileSystem is object ? Merge(Filter(fileSystem)) : 0,
            handled_access_net =    network is object ? Merge(Filter(network)) : 0,
            scoped             =      scope is object ? Merge(Filter(scope)) : 0
        };

        var p = Marshal.AllocHGlobal(Marshal.SizeOf<landlock_ruleset_attr>());
        try
        {
            Marshal.StructureToPtr(attr, p, false);
            int fd = (int)syscall(SYS_landlock_create_ruleset, p, Marshal.SizeOf<landlock_ruleset_attr>(), 0);
            if (fd < 0)
            {
                var errno = Marshal.GetLastWin32Error();
                throw new System.ComponentModel.Win32Exception(errno, $"Call to landlock_create_ruleset failed with error {errno}");
            }
            return new (fd);
        }
        finally
        {
            Marshal.FreeHGlobal(p);
        }
    }

    /// <summary>
    /// Add a PATH_BENEATH rule to the ruleset. parentPath should be a directory path.
    /// <paramref name="parentPath"/>Path to directory to have access restricted</paramref>
    /// <paramref name="allowedActions">Which operations should be allowed in this directory</paramref>
    /// </summary>
    public Landlock AddPathBeneathRule(string parentPath, params FileSystem[] allowedActions)
    {
        if (_alreadyEnforced) throw new Exception("Cannot modify an already enforced landlock");
        // open the directory with O_PATH for parent_fd
        int parentFd = open(parentPath, O_PATH);
        if (parentFd < 0)
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), $"open O_PATH(\"{parentPath}\") failed");
        }

        try
        {
            var attr = new landlock_path_beneath_attr 
            { 
                allowed_access = Merge(Filter(allowedActions)),
                parent_fd = parentFd 
            };

            IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf<landlock_path_beneath_attr>());
            try
            {
                Marshal.StructureToPtr(attr, p, false);
                long ret = syscall(SYS_landlock_add_rule, _ruleSetHandle, LANDLOCK_RULE_PATH_BENEATH, p, 0);
                if (ret < 0)
                {
                    var errno = Marshal.GetLastWin32Error();
                    throw new System.ComponentModel.Win32Exception(errno, $"Call to landlock_add_rule failed with error {errno}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(p);
            }
        }
        finally
        {
            close(parentFd);
        }
        return this;
    }

    /// <summary>
    /// Enforce a populated ruleset on the current thread.
    /// </summary>
    public void Enforce()
    {
        if (_alreadyEnforced) return;

        long ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); // forbid from getting new privileges

        if (ret < 0)
        {
            var errno = Marshal.GetLastWin32Error();
            throw new System.ComponentModel.Win32Exception(errno, $"Call to PR_SET_NO_NEW_PRIVS failed with error {errno}");
        }

        ret = syscall(SYS_landlock_restrict_self, _ruleSetHandle, (uint)0);
        if (ret < 0)
        {
            var errno = Marshal.GetLastWin32Error();
            throw new System.ComponentModel.Win32Exception(errno, $"Call to landlock_restrict_self failed with error {errno}");
        }

        close(_ruleSetHandle);

        _alreadyEnforced = true;
    }

    //// AllThreadsLandlockRestrictSelf enforces the given ruleset on all OS
    //// threads belonging to the current process.
    //func AllThreadsLandlockRestrictSelf(rulesetFd int, flags int) (err error) {
    //	_, _, e1 := psx.Syscall3(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFd), uintptr(flags), 0)
    //	if e1 != 0 {
    //		err = syscall.Errno(e1)
    //	}
    //	return
    //}

    //// AllThreadsPrctl is like unix.Prctl, but gets applied on all OS threads at the same time.
    //func AllThreadsPrctl(option int, arg2, arg3, arg4, arg5 uintptr) (err error) {
    //	_, _, e1 := psx.Syscall6(syscall.SYS_PRCTL, uintptr(option), uintptr(arg2), uintptr(arg3), uintptr(arg4), uintptr(arg5), 0)
    //	if e1 != 0 {
    //		err = syscall.Errno(e1)
    //	}
    //	return
    //}
}
