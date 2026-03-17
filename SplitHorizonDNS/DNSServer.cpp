#include "DNSServer.h"
#include <algorithm>
#include <cctype>
#include <cstring>

// ── helpers ─────────────────────────────────────────────────────────────────

static std::wstring ToLowerW(std::wstring s) {
    for (wchar_t& c : s) c = towlower(c);
    return s;
}

static std::string ToLowerA(std::string s) {
    for (char& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

// ── DNSServer ────────────────────────────────────────────────────────────────

DNSServer::DNSServer()
    : m_running(false), m_socket(INVALID_SOCKET)
{
    InitializeCriticalSection(&m_cs);
}

DNSServer::~DNSServer() {
    Stop();
    DeleteCriticalSection(&m_cs);
}

// ── public API ───────────────────────────────────────────────────────────────

bool DNSServer::Start(const std::wstring& upstreamDNS) {
    if (m_running.load()) return false;

    {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }

    EnterCriticalSection(&m_cs);
    m_upstreamDNS = upstreamDNS;
    LeaveCriticalSection(&m_cs);

    m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (m_socket == INVALID_SOCKET) {
        Log(L"Failed to create socket (WSA error " + std::to_wstring(WSAGetLastError()) + L")");
        return false;
    }

    // 1-second receive timeout so the thread can check m_running periodically
    DWORD rcvTimeout = 1000;
    setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&rcvTimeout, sizeof(rcvTimeout));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(53);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(m_socket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        Log(L"Failed to bind to port 53 (WSA error " + std::to_wstring(err) +
            L"). Make sure you are running as Administrator.");
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        return false;
    }

    m_running = true;
    m_thread  = std::thread(&DNSServer::ServerThread, this);
    Log(L"DNS server started on UDP port 53  (upstream: " + upstreamDNS + L")");
    return true;
}

void DNSServer::Stop() {
    if (!m_running.load()) return;
    m_running = false;

    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
    if (m_thread.joinable())
        m_thread.join();

    Log(L"DNS server stopped");
}

void DNSServer::SetRecords(const std::vector<DNSRecord>& records) {
    EnterCriticalSection(&m_cs);
    m_records = records;
    LeaveCriticalSection(&m_cs);
}

std::vector<DNSRecord> DNSServer::GetRecords() const {
    EnterCriticalSection(&m_cs);
    auto copy = m_records;
    LeaveCriticalSection(&m_cs);
    return copy;
}

void DNSServer::AddRecord(const DNSRecord& record) {
    EnterCriticalSection(&m_cs);
    m_records.push_back(record);
    LeaveCriticalSection(&m_cs);
}

void DNSServer::RemoveRecord(size_t index) {
    EnterCriticalSection(&m_cs);
    if (index < m_records.size())
        m_records.erase(m_records.begin() + (ptrdiff_t)index);
    LeaveCriticalSection(&m_cs);
}

std::wstring DNSServer::GetUpstreamDNS() const {
    EnterCriticalSection(&m_cs);
    auto s = m_upstreamDNS;
    LeaveCriticalSection(&m_cs);
    return s;
}

void DNSServer::SetUpstreamDNS(const std::wstring& dns) {
    EnterCriticalSection(&m_cs);
    m_upstreamDNS = dns;
    LeaveCriticalSection(&m_cs);
}

void DNSServer::SetLogCallback(LogCallback cb) {
    EnterCriticalSection(&m_cs);
    m_logCallback = std::move(cb);
    LeaveCriticalSection(&m_cs);
}

// ── private helpers ──────────────────────────────────────────────────────────

void DNSServer::Log(const std::wstring& msg) {
    EnterCriticalSection(&m_cs);
    auto cb = m_logCallback;
    LeaveCriticalSection(&m_cs);
    if (cb) cb(msg);
}

// Parse a DNS label-encoded name starting at data[offset].
// Updates offset to point just past the name (and pointer bytes if used).
std::string DNSServer::ParseQueryName(const uint8_t* data, int len, int& offset) {
    std::string name;
    int savedOffset = -1;
    int jumps = 0;
    int pos = offset;

    while (pos < len) {
        uint8_t labelLen = data[pos];

        if (labelLen == 0) {
            ++pos;
            break;
        }

        if ((labelLen & 0xC0) == 0xC0) {
            // Pointer – save continuation point first time
            if (pos + 1 >= len) { pos += 2; break; }
            if (savedOffset < 0) savedOffset = pos + 2;
            pos = ((labelLen & 0x3F) << 8) | data[pos + 1];
            if (++jumps > 10) break;
            continue;
        }

        ++pos;
        if (!name.empty()) name += '.';
        for (int i = 0; i < labelLen && pos < len; ++i)
            name += (char)data[pos++];
    }

    offset = (savedOffset >= 0) ? savedOffset : pos;
    return name;
}

// Build a minimal A-record response into `response`.
// questionEnd: offset in queryData just past QNAME+QTYPE+QCLASS.
bool DNSServer::BuildAResponse(
    const uint8_t* queryData, int queryLen,
    int questionEnd,
    uint16_t id, uint32_t ipNetOrder, bool rd,
    uint8_t* response, int& responseLen)
{
    // Sanity
    if (questionEnd < 12 || questionEnd > queryLen) return false;
    int qSectionLen = questionEnd - 12;
    if (12 + qSectionLen + 16 > 512) return false;  // overflow guard

    // Header
    response[0] = (id >> 8) & 0xFF;
    response[1] =  id       & 0xFF;

    // Flags: QR=1, AA=1, RD=copy from query, RA=1, RCODE=0
    uint16_t flags = 0x8400;
    if (rd) flags |= 0x0100;
    flags |= 0x0080;
    response[2] = (flags >> 8) & 0xFF;
    response[3] =  flags       & 0xFF;

    // Counts
    response[4] = 0; response[5] = 1; // QDCOUNT
    response[6] = 0; response[7] = 1; // ANCOUNT
    response[8] = 0; response[9] = 0; // NSCOUNT
    response[10]= 0; response[11]= 0; // ARCOUNT

    // Question section (copied verbatim from the query)
    memcpy(response + 12, queryData + 12, qSectionLen);
    int pos = 12 + qSectionLen;

    // Answer section
    // Name: pointer to offset 12 (0xC00C)
    response[pos++] = 0xC0;
    response[pos++] = 0x0C;
    // Type A
    response[pos++] = 0x00; response[pos++] = 0x01;
    // Class IN
    response[pos++] = 0x00; response[pos++] = 0x01;
    // TTL = 300 s
    response[pos++] = 0x00; response[pos++] = 0x00;
    response[pos++] = 0x01; response[pos++] = 0x2C;
    // RDLENGTH = 4
    response[pos++] = 0x00; response[pos++] = 0x04;
    // RDATA – IPv4 (already in network byte order)
    memcpy(response + pos, &ipNetOrder, 4);
    pos += 4;

    responseLen = pos;
    return true;
}

// Forward the raw query to the configured upstream DNS server and return its response.
bool DNSServer::ForwardQuery(const uint8_t* data, int len, uint8_t* response, int& responseLen) {
    EnterCriticalSection(&m_cs);
    std::wstring upstream = m_upstreamDNS;
    LeaveCriticalSection(&m_cs);

    if (upstream.empty()) return false;

    SOCKET fwd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fwd == INVALID_SOCKET) return false;

    DWORD timeout = 5000;
    setsockopt(fwd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(53);

    std::string upstreamA = WtoA(upstream.c_str());
    if (inet_pton(AF_INET, upstreamA.c_str(), &srv.sin_addr) != 1) {
        // Treat as hostname
        addrinfo hints{}, *result = nullptr;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(upstreamA.c_str(), "53", &hints, &result) != 0 || !result) {
            closesocket(fwd);
            return false;
        }
        srv = *reinterpret_cast<sockaddr_in*>(result->ai_addr);
        freeaddrinfo(result);
    }

    if (sendto(fwd, (const char*)data, len, 0, (sockaddr*)&srv, sizeof(srv)) == SOCKET_ERROR) {
        closesocket(fwd);
        return false;
    }

    int r = recvfrom(fwd, (char*)response, 4096, 0, nullptr, nullptr);
    closesocket(fwd);

    if (r <= 0) return false;
    responseLen = r;
    return true;
}

// Process one DNS query packet.
void DNSServer::ProcessQuery(const uint8_t* data, int len, const sockaddr_in& clientAddr) {
    if (len < 12) return;

    uint16_t id     = (uint16_t)((data[0] << 8) | data[1]);
    uint16_t flags  = (uint16_t)((data[2] << 8) | data[3]);
    uint16_t qdcount = (uint16_t)((data[4] << 8) | data[5]);

    // Only handle standard queries (QR=0, Opcode=0)
    if (flags & 0x8000) return;
    if (qdcount == 0)   return;

    int offset = 12;
    std::string queryName = ParseQueryName(data, len, offset);
    if (offset + 4 > len) return;

    uint16_t qtype  = (uint16_t)((data[offset] << 8) | data[offset + 1]);
    uint16_t qclass = (uint16_t)((data[offset + 2] << 8) | data[offset + 3]);
    offset += 4;
    int questionEnd = offset; // byte after the first question

    bool rd = (flags & 0x0100) != 0;

    // --- Check local records (A queries only) ---
    if (qtype == 1 /* A */ || qtype == 255 /* ANY */) {
        std::string nameLower = ToLowerA(queryName);
        std::wstring wName(nameLower.begin(), nameLower.end());

        EnterCriticalSection(&m_cs);
        auto records = m_records;          // snapshot
        LeaveCriticalSection(&m_cs);

        for (auto& rec : records) {
            if (ToLowerW(rec.hostname) == wName) {
                struct in_addr addr{};
                std::string ipA = WtoA(rec.ipAddress.c_str());
                if (inet_pton(AF_INET, ipA.c_str(), &addr) == 1) {
                    uint8_t response[512];
                    int responseLen = 0;
                    if (BuildAResponse(data, len, questionEnd, id, addr.s_addr, rd, response, responseLen)) {
                        sendto(m_socket, (char*)response, responseLen, 0,
                               (const sockaddr*)&clientAddr, sizeof(clientAddr));
                        Log(L"Local: " + std::wstring(queryName.begin(), queryName.end())
                            + L"  ->  " + rec.ipAddress);
                    }
                    return;
                }
            }
        }
    }

    // --- Forward to upstream ---
    uint8_t response[4096];
    int responseLen = 0;
    if (ForwardQuery(data, len, response, responseLen)) {
        sendto(m_socket, (char*)response, responseLen, 0,
               (const sockaddr*)&clientAddr, sizeof(clientAddr));
        Log(L"Forwarded: " + std::wstring(queryName.begin(), queryName.end()));
    } else {
        Log(L"Forward failed: " + std::wstring(queryName.begin(), queryName.end()));
    }

    (void)qclass;
}

// Main server loop – runs on a background thread.
void DNSServer::ServerThread() {
    uint8_t buf[4096];

    while (m_running.load()) {
        sockaddr_in clientAddr{};
        int clientAddrLen = sizeof(clientAddr);

        int r = recvfrom(m_socket, (char*)buf, sizeof(buf), 0,
                         (sockaddr*)&clientAddr, &clientAddrLen);

        if (r == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT || err == WSAEINTR) continue;
            if (m_running.load())
                Log(L"recvfrom error: " + std::to_wstring(err));
            break;
        }

        if (r > 0)
            ProcessQuery(buf, r, clientAddr);
    }
}
