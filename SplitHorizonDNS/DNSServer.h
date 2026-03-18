#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>
#include <unordered_map>

#pragma comment(lib, "ws2_32.lib")

// Narrow a wide string that is known to contain only ASCII characters
// (DNS names, IPv4 literals) without triggering C4244.
inline std::string WtoA(const wchar_t* ws) {
    std::string result;
    result.reserve(wcslen(ws));
    for (; *ws; ++ws) result += static_cast<char>(*ws);
    return result;
}

struct DNSRecord {
    std::wstring hostname;   // e.g. "myserver.local"
    std::wstring ipAddress;  // e.g. "192.168.1.50"
};

// One cached upstream DNS response keyed on "lowercaseName:qtype"
struct DNSCacheEntry {
    std::vector<uint8_t> response;  // Raw DNS response bytes
    ULONGLONG            expiryTick; // GetTickCount64() value at expiry
};

class DNSServer {
public:
    DNSServer();
    ~DNSServer();

    // Start listening on port 53, forwarding unknown queries to upstreamDNS
    // upstreamDNS2 is optional; used as fallback if upstreamDNS is unreachable
    bool Start(const std::wstring& upstreamDNS, const std::wstring& upstreamDNS2 = L"");
    void Stop();
    bool IsRunning() const { return m_running.load(); }

    // Record management (thread-safe)
    void SetRecords(const std::vector<DNSRecord>& records);
    std::vector<DNSRecord> GetRecords() const;
    void AddRecord(const DNSRecord& record);
    void RemoveRecord(size_t index);

    std::wstring GetUpstreamDNS() const;
    void SetUpstreamDNS(const std::wstring& dns);

    std::wstring GetUpstreamDNS2() const;
    void SetUpstreamDNS2(const std::wstring& dns);

    // DNS response cache management
    void   ClearCache();
    size_t GetCacheSize() const;

    using LogCallback = std::function<void(const std::wstring&)>;
    void SetLogCallback(LogCallback cb);

private:
    void ServerThread();

    // Parse a DNS label-encoded name starting at `offset`; advances offset past the name
    std::string ParseQueryName(const uint8_t* data, int len, int& offset);

    // Build an A-record DNS response into `response` buffer
    bool BuildAResponse(
        const uint8_t* queryData, int queryLen,
        int questionEnd,
        uint16_t id, uint32_t ipNetOrder, bool rd,
        uint8_t* response, int& responseLen);

    // Forward the original query to the given upstream DNS server and return its response
    bool TryForwardTo(const std::wstring& upstream, const uint8_t* data, int len,
                      uint8_t* response, int& responseLen);

    // Forward the original query to upstream and return the response
    bool ForwardQuery(const uint8_t* data, int len, uint8_t* response, int& responseLen);

    void ProcessQuery(const uint8_t* data, int len, const sockaddr_in& clientAddr);
    void Log(const std::wstring& msg);

    std::atomic<bool> m_running;
    SOCKET m_socket;
    std::thread m_thread;

    mutable CRITICAL_SECTION m_cs;
    std::wstring m_upstreamDNS;
    std::wstring m_upstreamDNS2;
    std::vector<DNSRecord> m_records;

    // Maximum number of entries kept in the cache at one time
    static const size_t   kMaxCacheEntries  = 500;
    // TTL (seconds) used when the upstream response contains no answer records
    static const uint32_t kNegativeCacheTTL = 30;
    std::unordered_map<std::string, DNSCacheEntry> m_dnsCache;

    LogCallback m_logCallback;
};
