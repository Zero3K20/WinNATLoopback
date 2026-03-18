// Split-Horizon DNS Server – main UI (Win32 dialog application)
// Requires Administrator rights to bind UDP port 53.

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <commctrl.h>
#include <windowsx.h>
#include <shellapi.h>
#include <strsafe.h>

#include <string>
#include <vector>
#include <algorithm>

#include "resource.h"
#include "DNSServer.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ── globals ──────────────────────────────────────────────────────────────────

static DNSServer  g_server;
static HWND       g_hDlg = nullptr;

#define WM_APP_LOG (WM_APP + 1)

// Path to the INI config file (same directory as the exe)
static wchar_t g_configPath[MAX_PATH];

// ── service constants ─────────────────────────────────────────────────────────

static const wchar_t* const SERVICE_NAME         = L"SplitHorizonDNS";
static const wchar_t* const SERVICE_DISPLAY_NAME = L"Split-Horizon DNS Server";

// ── service state ─────────────────────────────────────────────────────────────

static SERVICE_STATUS        g_svcStatus{};
static SERVICE_STATUS_HANDLE g_hSvcStatus  = nullptr;
static HANDLE                g_hStopEvent  = nullptr;

// ── persistence ───────────────────────────────────────────────────────────────

static void SaveConfig() {
    std::vector<DNSRecord> records = g_server.GetRecords();

    WritePrivateProfileString(L"Config", L"UpstreamDNS",
        g_server.GetUpstreamDNS().c_str(), g_configPath);
    WritePrivateProfileString(L"Config", L"UpstreamDNS2",
        g_server.GetUpstreamDNS2().c_str(), g_configPath);

    // Clear old records
    WritePrivateProfileString(L"Records", nullptr, nullptr, g_configPath);

    wchar_t key[32];
    DWORD idx = 0;
    for (auto& r : records) {
        StringCchPrintf(key, 32, L"Host%u", idx);
        WritePrivateProfileString(L"Records", key, r.hostname.c_str(), g_configPath);
        StringCchPrintf(key, 32, L"IP%u", idx);
        WritePrivateProfileString(L"Records", key, r.ipAddress.c_str(), g_configPath);
        ++idx;
    }
    WritePrivateProfileString(L"Records", L"Count",
        std::to_wstring(idx).c_str(), g_configPath);
}

static void LoadConfig() {
    wchar_t buf[256];

    GetPrivateProfileString(L"Config", L"UpstreamDNS", L"8.8.8.8",
        buf, 256, g_configPath);
    g_server.SetUpstreamDNS(buf);
    if (g_hDlg)
        SetDlgItemText(g_hDlg, IDC_EDIT_DNSSERVER, buf);

    GetPrivateProfileString(L"Config", L"UpstreamDNS2", L"",
        buf, 256, g_configPath);
    g_server.SetUpstreamDNS2(buf);
    if (g_hDlg)
        SetDlgItemText(g_hDlg, IDC_EDIT_DNSSERVER2, buf);

    DWORD count = GetPrivateProfileInt(L"Records", L"Count", 0, g_configPath);
    std::vector<DNSRecord> records;
    wchar_t kHost[32], kIP[32];
    for (DWORD i = 0; i < count; ++i) {
        wchar_t host[256] = {}, ip[64] = {};
        StringCchPrintf(kHost, 32, L"Host%u", i);
        StringCchPrintf(kIP,   32, L"IP%u",   i);
        GetPrivateProfileString(L"Records", kHost, L"", host, 256, g_configPath);
        GetPrivateProfileString(L"Records", kIP,   L"", ip,   64,  g_configPath);
        if (host[0] && ip[0])
            records.push_back({host, ip});
    }
    g_server.SetRecords(records);
}

// ── ListView helpers ──────────────────────────────────────────────────────────

static void LV_RefreshAll(HWND hLV) {
    ListView_DeleteAllItems(hLV);
    auto records = g_server.GetRecords();
    for (size_t i = 0; i < records.size(); ++i) {
        LVITEM lvi{};
        lvi.mask    = LVIF_TEXT;
        lvi.iItem   = (int)i;
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(records[i].hostname.c_str());
        int row = ListView_InsertItem(hLV, &lvi);
        ListView_SetItemText(hLV, row, 1,
            const_cast<LPWSTR>(records[i].ipAddress.c_str()));
    }
}

// ── log callback (may be called from worker thread) ───────────────────────────

static void AppendLog(const std::wstring& msg) {
    // Thread-safe: post to the UI thread.
    // Guard against the window being destroyed (e.g. during shutdown).
    HWND hDlg = g_hDlg;
    if (!hDlg) return;
    wchar_t* p = new wchar_t[msg.length() + 1];
    wcscpy_s(p, msg.length() + 1, msg.c_str());
    if (!PostMessage(hDlg, WM_APP_LOG, 0, (LPARAM)p))
        delete[] p; // PostMessage failed – free immediately
}

// ── update status label ───────────────────────────────────────────────────────

static void UpdateStatus(bool running) {
    SetDlgItemText(g_hDlg, IDC_STATIC_STATUS,
        running ? L"Status: Running on UDP port 53"
                : L"Status: Stopped");
    EnableWindow(GetDlgItem(g_hDlg, IDC_BTN_START), !running);
    EnableWindow(GetDlgItem(g_hDlg, IDC_BTN_STOP),   running);
}

// ── service helpers ───────────────────────────────────────────────────────────

// Build the path used to set up the config and cache files.
static void BuildConfigAndCachePaths(wchar_t configPath[MAX_PATH],
                                     wchar_t cachePath[MAX_PATH]) {
    GetModuleFileName(nullptr, configPath, MAX_PATH);
    wchar_t* ls = wcsrchr(configPath, L'\\');
    if (ls) {
        *(ls + 1) = L'\0';
        StringCchCopy(cachePath, MAX_PATH, configPath);
        StringCchCat(configPath, MAX_PATH, L"dns_config.ini");
        StringCchCat(cachePath,  MAX_PATH, L"dns_cache.bin");
    } else {
        StringCchCopy(configPath, MAX_PATH, L"dns_config.ini");
        StringCchCopy(cachePath,  MAX_PATH, L"dns_cache.bin");
    }
}

// Install the service (auto-start, runs as LocalSystem).
static bool InstallService(HWND hParent) {
    wchar_t exePath[MAX_PATH];
    GetModuleFileName(nullptr, exePath, MAX_PATH);

    SC_HANDLE hScm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hScm) {
        MessageBox(hParent,
            L"Could not open the Service Control Manager.\n"
            L"Ensure you are running as Administrator.",
            L"Install Service", MB_ICONERROR);
        return false;
    }

    SC_HANDLE hSvc = CreateService(
        hScm,
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        exePath,
        nullptr, nullptr, nullptr,
        // Run as LocalSystem: required to bind the privileged UDP port 53
        // and to access the config file placed next to the executable.
        nullptr, nullptr);

    bool ok = (hSvc != nullptr);
    DWORD err = GetLastError();
    if (hSvc) CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);

    if (ok) {
        MessageBox(hParent,
            L"Service installed successfully.\n"
            L"It will start automatically at the next system boot,\n"
            L"or you can start it now from the Services snap-in.",
            L"Install Service", MB_ICONINFORMATION);
    } else if (err == ERROR_SERVICE_EXISTS) {
        MessageBox(hParent,
            L"The service is already installed.",
            L"Install Service", MB_ICONINFORMATION);
    } else {
        MessageBox(hParent,
            L"Failed to install the service.",
            L"Install Service", MB_ICONERROR);
    }
    return ok;
}

// Stop (if running) and delete the service.
static bool UninstallService(HWND hParent) {
    SC_HANDLE hScm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) {
        MessageBox(hParent,
            L"Could not open the Service Control Manager.\n"
            L"Ensure you are running as Administrator.",
            L"Uninstall Service", MB_ICONERROR);
        return false;
    }

    SC_HANDLE hSvc = OpenService(hScm, SERVICE_NAME,
                                 SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        DWORD err = GetLastError();
        CloseServiceHandle(hScm);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            MessageBox(hParent, L"The service is not installed.",
                       L"Uninstall Service", MB_ICONINFORMATION);
        } else {
            MessageBox(hParent,
                L"Failed to open the service. Ensure you are running as Administrator.",
                L"Uninstall Service", MB_ICONERROR);
        }
        return false;
    }

    // Attempt to stop the service before deleting it.
    // ControlService may fail if the service is already stopped or in a
    // transient state; that is acceptable – DeleteService marks the service
    // for deletion and the SCM will complete the removal once the service
    // process exits.
    SERVICE_STATUS ss{};
    ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);

    bool ok = (DeleteService(hSvc) != FALSE);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);

    if (ok) {
        MessageBox(hParent, L"Service uninstalled successfully.",
                   L"Uninstall Service", MB_ICONINFORMATION);
    } else {
        MessageBox(hParent, L"Failed to uninstall the service.",
                   L"Uninstall Service", MB_ICONERROR);
    }
    return ok;
}

// ── Windows Service entry point ───────────────────────────────────────────────

static void WINAPI ServiceCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        g_svcStatus.dwCurrentState  = SERVICE_STOP_PENDING;
        g_svcStatus.dwControlsAccepted = 0;
        SetServiceStatus(g_hSvcStatus, &g_svcStatus);
        if (g_hStopEvent) SetEvent(g_hStopEvent);
    }
}

static void WINAPI ServiceMain(DWORD /*argc*/, LPWSTR* /*argv*/) {
    g_hSvcStatus = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_hSvcStatus) return;

    g_svcStatus.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_svcStatus.dwCurrentState     = SERVICE_START_PENDING;
    g_svcStatus.dwControlsAccepted = 0;
    SetServiceStatus(g_hSvcStatus, &g_svcStatus);

    // Set up file paths
    wchar_t cachePath[MAX_PATH];
    BuildConfigAndCachePaths(g_configPath, cachePath);
    g_server.SetCacheFilePath(cachePath);

    // Load persisted DNS records and upstream servers
    LoadConfig();

    g_hStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!g_hStopEvent) {
        g_svcStatus.dwCurrentState  = SERVICE_STOPPED;
        g_svcStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_hSvcStatus, &g_svcStatus);
        return;
    }

    if (!g_server.Start(g_server.GetUpstreamDNS(), g_server.GetUpstreamDNS2())) {
        CloseHandle(g_hStopEvent);
        g_hStopEvent = nullptr;
        g_svcStatus.dwCurrentState          = SERVICE_STOPPED;
        g_svcStatus.dwWin32ExitCode         = ERROR_SERVICE_SPECIFIC_ERROR;
        g_svcStatus.dwServiceSpecificExitCode = 1;
        SetServiceStatus(g_hSvcStatus, &g_svcStatus);
        return;
    }

    g_svcStatus.dwCurrentState     = SERVICE_RUNNING;
    g_svcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_hSvcStatus, &g_svcStatus);

    WaitForSingleObject(g_hStopEvent, INFINITE);

    g_server.Stop();
    CloseHandle(g_hStopEvent);
    g_hStopEvent = nullptr;

    g_svcStatus.dwCurrentState     = SERVICE_STOPPED;
    g_svcStatus.dwControlsAccepted = 0;
    SetServiceStatus(g_hSvcStatus, &g_svcStatus);
}

// ── dialog procedure ─────────────────────────────────────────────────────────

static INT_PTR CALLBACK DlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG: {
        g_hDlg = hDlg;

        // Set up ListView columns
        HWND hLV = GetDlgItem(hDlg, IDC_LIST_RECORDS);
        LVCOLUMN col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.cx   = 260;
        col.pszText = const_cast<LPWSTR>(L"Hostname");
        ListView_InsertColumn(hLV, 0, &col);
        col.cx      = 150;
        col.pszText = const_cast<LPWSTR>(L"IP Address");
        ListView_InsertColumn(hLV, 1, &col);
        ListView_SetExtendedListViewStyle(hLV, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        // Register log callback
        g_server.SetLogCallback(AppendLog);

        // Load persisted settings
        LoadConfig();
        LV_RefreshAll(hLV);

        // Populate DNS server edit boxes
        SetDlgItemText(hDlg, IDC_EDIT_DNSSERVER,
            g_server.GetUpstreamDNS().c_str());
        SetDlgItemText(hDlg, IDC_EDIT_DNSSERVER2,
            g_server.GetUpstreamDNS2().c_str());

        UpdateStatus(false);
        return TRUE;
    }

    case WM_APP_LOG: {
        wchar_t* p = reinterpret_cast<wchar_t*>(lParam);
        HWND hLB = GetDlgItem(hDlg, IDC_LIST_LOG);

        // Cap log at 500 entries
        int count = (int)SendMessage(hLB, LB_GETCOUNT, 0, 0);
        if (count > 500)
            SendMessage(hLB, LB_DELETESTRING, 0, 0);

        int idx = (int)SendMessage(hLB, LB_ADDSTRING, 0, (LPARAM)p);
        SendMessage(hLB, LB_SETTOPINDEX, idx, 0);
        delete[] p;
        return TRUE;
    }

    case WM_COMMAND: {
        switch (LOWORD(wParam)) {

        case IDC_BTN_ADD: {
            wchar_t host[256]{}, ip[64]{};
            GetDlgItemText(hDlg, IDC_EDIT_HOSTNAME,  host, 256);
            GetDlgItemText(hDlg, IDC_EDIT_IPADDRESS, ip,   64);

            // Basic validation
            if (host[0] == L'\0') {
                MessageBox(hDlg, L"Please enter a hostname.", L"Validation", MB_ICONWARNING);
                break;
            }
            if (ip[0] == L'\0') {
                MessageBox(hDlg, L"Please enter an IP address.", L"Validation", MB_ICONWARNING);
                break;
            }
            // Validate IP
            {
                struct in_addr testAddr{};
                std::string aip = WtoA(ip);
                if (inet_pton(AF_INET, aip.c_str(), &testAddr) != 1) {
                    MessageBox(hDlg, L"Invalid IPv4 address.", L"Validation", MB_ICONWARNING);
                    break;
                }
            }

            DNSRecord rec{ host, ip };
            g_server.AddRecord(rec);
            LV_RefreshAll(GetDlgItem(hDlg, IDC_LIST_RECORDS));
            SaveConfig();
            SetDlgItemText(hDlg, IDC_EDIT_HOSTNAME,  L"");
            SetDlgItemText(hDlg, IDC_EDIT_IPADDRESS, L"");
            break;
        }

        case IDC_BTN_REMOVE: {
            HWND hLV = GetDlgItem(hDlg, IDC_LIST_RECORDS);
            int sel = ListView_GetNextItem(hLV, -1, LVNI_SELECTED);
            if (sel < 0) {
                MessageBox(hDlg, L"Please select a record to remove.", L"Remove", MB_ICONINFORMATION);
                break;
            }
            g_server.RemoveRecord((size_t)sel);
            LV_RefreshAll(hLV);
            SaveConfig();
            break;
        }

        case IDC_BTN_START: {
            // Save / apply the DNS server fields before starting
            wchar_t dnsServer[256]{};
            GetDlgItemText(hDlg, IDC_EDIT_DNSSERVER, dnsServer, 256);
            if (dnsServer[0] == L'\0') {
                MessageBox(hDlg, L"Please enter a primary upstream DNS server address.", L"Validation", MB_ICONWARNING);
                break;
            }
            wchar_t dnsServer2[256]{};
            GetDlgItemText(hDlg, IDC_EDIT_DNSSERVER2, dnsServer2, 256);

            g_server.SetUpstreamDNS(dnsServer);
            g_server.SetUpstreamDNS2(dnsServer2);
            SaveConfig();

            if (g_server.Start(dnsServer, dnsServer2))
                UpdateStatus(true);
            else
                MessageBox(hDlg, L"Failed to start the DNS server.\n\n"
                    L"Ensure you are running this program as Administrator\n"
                    L"and that port 53 is not in use.", L"Error", MB_ICONERROR);
            break;
        }

        case IDC_BTN_STOP:
            g_server.Stop();
            UpdateStatus(false);
            break;

        case IDC_BTN_CLEAR_CACHE:
            g_server.ClearCache();
            break;

        case IDC_BTN_INSTALL_SVC:
            InstallService(hDlg);
            break;

        case IDC_BTN_UNINSTALL_SVC:
            UninstallService(hDlg);
            break;

        case IDCANCEL:
        case IDOK:
            SendMessage(hDlg, WM_CLOSE, 0, 0);
            break;
        }
        return TRUE;
    }

    case WM_CLOSE:
        g_server.Stop();
        SaveConfig();
        DestroyWindow(hDlg);
        return TRUE;

    case WM_DESTROY:
        g_hDlg = nullptr;
        PostQuitMessage(0);
        return TRUE;
    }
    return FALSE;
}

// ── WinMain ───────────────────────────────────────────────────────────────────

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    // Attempt to run as a service first.
    // If the process was started by the SCM, StartServiceCtrlDispatcher
    // will not return until the service has stopped.
    SERVICE_TABLE_ENTRY serviceTable[] = {
        { const_cast<LPWSTR>(SERVICE_NAME), ServiceMain },
        { nullptr, nullptr }
    };
    if (StartServiceCtrlDispatcher(serviceTable)) {
        return 0;
    }
    // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT means we were launched
    // interactively (not by the SCM) – fall through to the GUI.

    // Compute the config file path (same dir as exe)
    wchar_t cachePath[MAX_PATH];
    BuildConfigAndCachePaths(g_configPath, cachePath);
    g_server.SetCacheFilePath(cachePath);

    // Initialize common controls (required for ListView)
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    HWND hDlg = CreateDialog(hInstance, MAKEINTRESOURCE(IDD_MAIN), nullptr, DlgProc);
    if (!hDlg) {
        MessageBox(nullptr, L"Failed to create dialog.", L"Error", MB_ICONERROR);
        return 1;
    }
    ShowWindow(hDlg, SW_SHOW);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessage(hDlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    return (int)msg.wParam;
}
