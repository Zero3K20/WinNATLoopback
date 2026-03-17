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

#pragma comment(lib, "ws2_32.lib")

struct DNSRecord {
    std::wstring hostname;   // e.g. "myserver.local"
    std::wstring ipAddress;  // e.g. "192.168.1.50"
};

class DNSServer {
public:
    DNSServer();
    ~DNSServer();

    // Start listening on port 53, forwarding unknown queries to upstreamDNS
    bool Start(const std::wstring& upstreamDNS);
    void Stop();
    bool IsRunning() const { return m_running.load(); }

    // Record management (thread-safe)
    void SetRecords(const std::vector<DNSRecord>& records);
    std::vector<DNSRecord> GetRecords() const;
    void AddRecord(const DNSRecord& record);
    void RemoveRecord(size_t index);

    std::wstring GetUpstreamDNS() const;
    void SetUpstreamDNS(const std::wstring& dns);

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

    // Forward the original query to upstream and return the response
    bool ForwardQuery(const uint8_t* data, int len, uint8_t* response, int& responseLen);

    void ProcessQuery(const uint8_t* data, int len, const sockaddr_in& clientAddr);
    void Log(const std::wstring& msg);

    std::atomic<bool> m_running;
    SOCKET m_socket;
    std::thread m_thread;

    mutable CRITICAL_SECTION m_cs;
    std::wstring m_upstreamDNS;
    std::vector<DNSRecord> m_records;

    LogCallback m_logCallback;
};
