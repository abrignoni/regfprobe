# Build known data for regfprobe on a Windows machine, through the Win32 registry API.
#
#   powershell -ExecutionPolicy Bypass -File make_known_hive.ps1 -Out C:\rk
#
# Creates HKCU\Software\regfprobe_known with keys and values of shapes a reader must handle
# (UTF-16 and Latin-1 names, a key with 2000 subkeys, a class name, every value type, odd and
# unterminated strings, sizes around the 16344-byte big data threshold, type numbers outside
# REG_*), then writes four files to -Out:
#
#   known.hiv      reg save of that key: a hive whose root is regfprobe_known (format 1.3,
#                  what reg.exe writes, which has no big data records)
#   known15.hiv    the same key saved by RegSaveKeyEx with REG_LATEST_FORMAT (format 1.5,
#                  where values over 16344 bytes are stored as big data)
#   known.reg      reg export of the same key (regedit's text format, UTF-16)
#   known.tsv      what Windows itself enumerates: every key with its last-write FILETIME and
#                  class name, and every value with its type number and data bytes (base64)
#
# known.tsv is the oracle tools/known-data/compare_known.py checks regfprobe against.
# Run it again and the key is deleted and rebuilt first. Nothing outside that key is touched.
param([string]$Out = 'C:\rk')

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Out | Out-Null

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class RegKnown {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegCreateKeyEx(UIntPtr hKey, string sub, int reserved, string cls, int options,
                                     int sam, IntPtr sa, out UIntPtr result, out int disposition);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegSetValueEx(UIntPtr hKey, string name, int reserved, uint type, byte[] data, int cb);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegOpenKeyEx(UIntPtr hKey, string sub, int options, int sam, out UIntPtr result);
    [DllImport("advapi32.dll")]
    static extern int RegCloseKey(UIntPtr hKey);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegDeleteTree(UIntPtr hKey, string sub);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegEnumKeyEx(UIntPtr hKey, int index, StringBuilder name, ref int cch, IntPtr reserved,
                                   IntPtr cls, IntPtr cchCls, out long lastWrite);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegEnumValue(UIntPtr hKey, int index, StringBuilder name, ref int cch, IntPtr reserved,
                                   out uint type, byte[] data, ref int cb);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegQueryInfoKey(UIntPtr hKey, StringBuilder cls, ref int cchCls, IntPtr reserved,
                                      out int subkeys, out int maxSub, out int maxCls, out int values,
                                      out int maxValueName, out int maxValueLen, out int sd, out long lastWrite);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegSaveKeyEx(UIntPtr hKey, string file, IntPtr sa, int flags);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string system, string name, out long luid);
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    struct TokenPrivileges { public int Count; public long Luid; public int Attributes; }
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges state,
                                             int length, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    // RegSaveKeyEx needs SeBackupPrivilege enabled; REG_LATEST_FORMAT is 2.
    public static void SaveLatest(string root, string file) {
        IntPtr token; long luid;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) throw new Exception("OpenProcessToken");
        if (!LookupPrivilegeValue(null, "SeBackupPrivilege", out luid)) throw new Exception("LookupPrivilegeValue");
        var state = new TokenPrivileges { Count = 1, Luid = luid, Attributes = 2 };
        if (!AdjustTokenPrivileges(token, false, ref state, 0, IntPtr.Zero, IntPtr.Zero)) throw new Exception("AdjustTokenPrivileges");
        UIntPtr key;
        Check(RegOpenKeyEx(HKCU, root, 0, KEY_READ, out key), "open " + root);
        Check(RegSaveKeyEx(key, file, IntPtr.Zero, 2), "RegSaveKeyEx");
        RegCloseKey(key);
    }

    public static readonly UIntPtr HKCU = new UIntPtr(0x80000001u);
    const int KEY_ALL = 0xF003F, KEY_READ = 0x20019;

    static void Check(int rc, string what) {
        if (rc != 0) throw new Exception(what + " failed: " + rc);
    }

    public static void DeleteTree(string path) {
        RegDeleteTree(HKCU, path);
    }

    public static UIntPtr Create(UIntPtr parent, string name, string cls) {
        UIntPtr key; int disposition;
        Check(RegCreateKeyEx(parent, name, 0, cls, 0, KEY_ALL, IntPtr.Zero, out key, out disposition), "create " + name);
        return key;
    }

    public static void Set(UIntPtr key, string name, uint type, byte[] data) {
        Check(RegSetValueEx(key, name, 0, type, data, data == null ? 0 : data.Length), "set " + name);
    }

    public static void Close(UIntPtr key) { RegCloseKey(key); }

    static string B64(string text) { return Convert.ToBase64String(Encoding.Unicode.GetBytes(text)); }

    public static void Dump(string root, string file) {
        UIntPtr key;
        Check(RegOpenKeyEx(HKCU, root, 0, KEY_READ, out key), "open " + root);
        using (var writer = new StreamWriter(file, false, new UTF8Encoding(false))) {
            writer.NewLine = "\n";
            Walk(key, "", writer);
        }
        RegCloseKey(key);
    }

    static void Walk(UIntPtr key, string path, StreamWriter writer) {
        var cls = new StringBuilder(1024); int cchCls = 1024;
        int subkeys, maxSub, maxCls, values, maxValueName, maxValueLen, sd; long lastWrite;
        Check(RegQueryInfoKey(key, cls, ref cchCls, IntPtr.Zero, out subkeys, out maxSub, out maxCls, out values,
                              out maxValueName, out maxValueLen, out sd, out lastWrite), "query " + path);
        writer.WriteLine("K\t" + B64(path) + "\t" + lastWrite + "\t" + B64(cls.ToString()) + "\t" + subkeys + "\t" + values);
        for (int i = 0; i < values; i++) {
            var name = new StringBuilder(maxValueName + 2); int cch = maxValueName + 2;
            var data = new byte[maxValueLen + 2]; int cb = data.Length; uint type;
            Check(RegEnumValue(key, i, name, ref cch, IntPtr.Zero, out type, data, ref cb), "enum value");
            var bytes = new byte[cb]; Array.Copy(data, bytes, cb);
            writer.WriteLine("V\t" + B64(path) + "\t" + B64(name.ToString(0, cch)) + "\t" + type + "\t" + Convert.ToBase64String(bytes));
        }
        for (int i = 0; i < subkeys; i++) {
            var name = new StringBuilder(maxSub + 2); int cch = maxSub + 2; long ft;
            Check(RegEnumKeyEx(key, i, name, ref cch, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ft), "enum key");
            string sub = name.ToString(0, cch);
            UIntPtr child;
            Check(RegOpenKeyEx(key, sub, 0, KEY_READ, out child), "open " + sub);
            Walk(child, path.Length == 0 ? sub : path + "\\" + sub, writer);
            RegCloseKey(child);
        }
    }
}
'@

$rootPath = 'Software\regfprobe_known'
[RegKnown]::DeleteTree($rootPath)
$root = [RegKnown]::Create([RegKnown]::HKCU, $rootPath, $null)

function U16([string]$s) { [Text.Encoding]::Unicode.GetBytes($s) }
function Z([string]$s) { U16 ($s + [char]0) }
function Pattern([int]$n) { $b = New-Object byte[] $n; for ($i = 0; $i -lt $n; $i++) { $b[$i] = $i % 251 }; ,$b }

# names
$k = [RegKnown]::Create($root, 'Café Größe', $null); [RegKnown]::Set($k, 'Ñame', 1, (Z 'latin-1 name')); [RegKnown]::Close($k)
$k = [RegKnown]::Create($root, 'Ключ 日本 🔑', $null); [RegKnown]::Set($k, 'Значение 値', 1, (Z 'utf-16 name')); [RegKnown]::Close($k)
$k = [RegKnown]::Create($root, 'WithClass', 'MyClassName'); [RegKnown]::Close($k)
$k = [RegKnown]::Create($root, 'Deep\A\B\C\D\E\F\G\H', $null); [RegKnown]::Close($k)
$many = [RegKnown]::Create($root, 'Many', $null)
for ($i = 0; $i -lt 2000; $i++) { $c = [RegKnown]::Create($many, ('Sub{0:D4}' -f $i), $null); [RegKnown]::Close($c) }
[RegKnown]::Close($many)

# values
$v = [RegKnown]::Create($root, 'Values', $null)
[RegKnown]::Set($v, '', 1, (Z 'the default value'))
[RegKnown]::Set($v, 'Sz', 1, (Z 'hello'))
[RegKnown]::Set($v, 'SzEmpty', 1, (Z ''))
[RegKnown]::Set($v, 'SzZeroBytes', 1, (New-Object byte[] 0))
[RegKnown]::Set($v, 'SzOneChar', 1, (Z 'A'))
[RegKnown]::Set($v, 'SzNoTerminator', 1, (U16 'abc'))
[RegKnown]::Set($v, 'SzOddLength', 1, ((Z 'abc') + [byte[]]@(0x41)))
[RegKnown]::Set($v, 'SzAfterNul', 1, ((Z 'abc') + (Z 'junk')))
[RegKnown]::Set($v, 'ExpandSz', 2, (Z '%SystemRoot%\system32'))
[RegKnown]::Set($v, 'MultiSz', 7, ((Z 'one') + (Z 'two') + (U16 ([string][char]0))))
[RegKnown]::Set($v, 'MultiSzEmptyInside', 7, ((Z 'one') + (Z '') + (Z 'three') + (U16 ([string][char]0))))
[RegKnown]::Set($v, 'Dword', 4, [BitConverter]::GetBytes([uint32]3735928559))
[RegKnown]::Set($v, 'DwordShort', 4, [byte[]]@(1, 2))
[RegKnown]::Set($v, 'DwordLong', 4, [byte[]]@(1, 2, 3, 4, 5, 6, 7, 8))
[RegKnown]::Set($v, 'DwordBigEndian', 5, [byte[]]@(1, 2, 3, 4))
[RegKnown]::Set($v, 'Qword', 11, [BitConverter]::GetBytes([uint64]72623859790382856))
[RegKnown]::Set($v, 'Link', 6, (U16 '\Registry\Machine\Software'))
[RegKnown]::Set($v, 'NoneEmpty', 0, (New-Object byte[] 0))
[RegKnown]::Set($v, 'NoneData', 0, [byte[]]@(9, 8, 7))
[RegKnown]::Set($v, 'ResourceList', 8, (Pattern 24))
foreach ($n in 0, 1, 3, 4, 5, 16343, 16344, 16345, 40000, 100000) {
    [RegKnown]::Set($v, ('Binary{0}' -f $n), 3, (Pattern $n))
}
[RegKnown]::Set($v, 'SzBig', 1, (Z ('x' * 30000)))
[RegKnown]::Set($v, 'TypeHighWord', 0x20004, [BitConverter]::GetBytes([uint32]5))
[RegKnown]::Set($v, 'TypeDevprop', [uint32]4294901778, (Z 'devprop string'))
[RegKnown]::Set($v, 'TypeLarge', 100000012, [byte[]]@(1, 2, 3))
[RegKnown]::Set($v, ('N' * 16383), 4, [BitConverter]::GetBytes([uint32]1))
[RegKnown]::Close($v)
[RegKnown]::Close($root)

[RegKnown]::Dump($rootPath, (Join-Path $Out 'known.tsv'))
& reg.exe save "HKCU\$rootPath" (Join-Path $Out 'known.hiv') /y | Out-Null
if ($LASTEXITCODE -ne 0) { throw "reg save failed: $LASTEXITCODE" }
$latest = Join-Path $Out 'known15.hiv'
if (Test-Path $latest) { Remove-Item $latest }
[RegKnown]::SaveLatest($rootPath, $latest)
& reg.exe export "HKCU\$rootPath" (Join-Path $Out 'known.reg') /y | Out-Null
if ($LASTEXITCODE -ne 0) { throw "reg export failed: $LASTEXITCODE" }
Get-ChildItem $Out | Select-Object Name, Length | Format-Table -AutoSize
