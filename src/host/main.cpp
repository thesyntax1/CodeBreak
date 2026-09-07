#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <WebView2.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <sstream>
#include <chrono>
#include <cstring>

#include "../formats.h"
#include "../jsonw.h"
#include "../jsonr.h"
#include "../util.h"
#include "../hashes.h"
#include "../pe.h"
#include "../report.h"

#ifdef __MINGW32__
__CRT_UUID_DECL(ICoreWebView2WebMessageReceivedEventHandler, 0x57213f19, 0x00e6, 0x49fa, 0x8e, 0x07, 0x89, 0x8e, 0xa0, 0x1e, 0xcb, 0xd2)
__CRT_UUID_DECL(ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler, 0x4e8a3389, 0xc9d8, 0x4bd2, 0xb6, 0xb5, 0x12, 0x4f, 0xee, 0x6c, 0xc1, 0x4d)
__CRT_UUID_DECL(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler, 0x6c4819f3, 0xc9b7, 0x4260, 0x81, 0x27, 0xc9, 0xf5, 0xbd, 0xe7, 0xf6, 0x8c)
__CRT_UUID_DECL(ICoreWebView2Controller4, 0x97d418d5, 0xa426, 0x4e49, 0xa1, 0x51, 0xe1, 0xa1, 0x0f, 0x32, 0x7d, 0x9e)
#endif

#ifdef _MSC_VER
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "advapi32.lib")
#endif

using namespace cb;

#define WM_APP_ANALYSIS (WM_APP + 1)
#define IDR_APP_HTML 101

static const wchar_t* WND_CLASS = L"CodeBreakMainWindow";
static const wchar_t* WND_TITLE = L"CodeBreak — Binary Analysis Suite";

static HWND g_hwnd = nullptr;
static ICoreWebView2* g_webview = nullptr;
static ICoreWebView2Controller* g_controller = nullptr;

typedef HRESULT(STDMETHODCALLTYPE* PFN_CreateWv2EnvWithOptions)(
    PCWSTR browserExecutableFolder, PCWSTR userDataFolder,
    ICoreWebView2EnvironmentOptions* options,
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler* handler);
typedef HRESULT(STDMETHODCALLTYPE* PFN_GetWv2Version)(
    PCWSTR browserExecutableFolder, LPWSTR* version);

static HMODULE g_loader = nullptr;
static PFN_CreateWv2EnvWithOptions g_createEnv = nullptr;
static PFN_GetWv2Version g_getVersion = nullptr;

struct FileCtx {
    std::string path;
    std::vector<uint8_t> bytes;
    StringsIndex si;
    std::string fullAnalysis;
};
static FileCtx g_ctx;
static std::mutex g_ctxMutex;

struct PendingResult {
    uint64_t id;
    std::string json;
};

static std::string wideToUtf8(const wchar_t* w) {
    if (!w || !*w) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return std::string();
    std::string s((size_t)n - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    return s;
}

static void postToUi(uint64_t id, const std::string& fullJson) {
    PendingResult* pr = new PendingResult{ id, fullJson };
    PostMessageW(g_hwnd, WM_APP_ANALYSIS, 0, (LPARAM)pr);
}

static void respondError(uint64_t id, const std::string& msg) {
    std::string j;
    Builder b(j);
    b.beginObj();
    b.kv("id", id);
    b.kv("ok", false);
    b.kv("error", msg);
    b.endObj();
    postToUi(id, j);
}

static std::string loadHtmlResource() {
    HRSRC rs = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_APP_HTML), RT_RCDATA);
    if (rs) {
        HGLOBAL g = LoadResource(nullptr, rs);
        if (g) {
            const char* p = (const char*)LockResource(g);
            DWORD sz = SizeofResource(nullptr, rs);
            if (p && sz) return std::string(p, sz);
        }
    }
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileNameW(nullptr, exePath, MAX_PATH)) {
        wchar_t* slash = wcsrchr(exePath, L'\\');
        if (slash) {
            *slash = 0;
            std::wstring file = std::wstring(exePath) + L"\\app.html";
            HANDLE f = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
            if (f != INVALID_HANDLE_VALUE) {
                std::string out;
                char buf[65536];
                DWORD rd = 0;
                while (ReadFile(f, buf, sizeof(buf), &rd, nullptr) && rd) out.append(buf, rd);
                CloseHandle(f);
                if (!out.empty()) return out;
            }
        }
    }
    return "<html><body style='background:#0b0e14;color:#d7e0f0;font-family:Consolas'>UI resource missing.</body></html>";
}

static void runAnalysis(uint64_t id, const std::string& pathUtf8) {
    std::vector<uint8_t> data;
    std::string err;
    if (!readFileBytes(pathUtf8, data, err)) {
        respondError(id, "Cannot open file: " + err);
        return;
    }
    FileInfo fi = queryFileInfo(pathUtf8);
    auto t0 = std::chrono::steady_clock::now();
    AnalysisOutput ao = analyzeFile(data.data(), data.size(), pathUtf8, fi);
    auto t1 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    std::string j = ao.json;
    char msb[48];
    snprintf(msb, sizeof(msb), "%.1f", ms);
    j.insert(j.size() - 1, ", \"analysisMs\": " + std::string(msb));

    {
        std::lock_guard<std::mutex> lk(g_ctxMutex);
        g_ctx.path = pathUtf8;
        g_ctx.bytes = std::move(data);
        g_ctx.si.build(g_ctx.bytes.data(), g_ctx.bytes.size(), 4, 2000000);
        g_ctx.fullAnalysis = j;
    }

    std::string full;
    Builder b(full);
    b.beginObj();
    b.kv("id", id);
    b.kv("ok", true);
    b.key("data");
    b.raw(j.c_str());
    b.endObj();
    postToUi(id, full);
}

static void runStrings(uint64_t id, uint64_t offset, uint32_t count, uint32_t minLen, int kind, const std::string& filter) {
    std::string full;
    Builder b(full);
    b.beginObj();
    b.kv("id", id);
    b.kv("ok", true);
    b.obj("data");
    {
        std::lock_guard<std::mutex> lk(g_ctxMutex);
        uint64_t total = 0;
        b.key("items");
        g_ctx.si.query(b, offset, count, minLen, kind, filter, total);
        b.kv("total", total);
    }
    b.endObj();
    b.endObj();
    postToUi(id, full);
}

static void serveHex(uint64_t id, uint64_t off, uint64_t len) {
    std::string full;
    Builder b(full);
    b.beginObj();
    b.kv("id", id);
    b.kv("ok", true);
    b.obj("data");
    {
        std::lock_guard<std::mutex> lk(g_ctxMutex);
        uint64_t size = g_ctx.bytes.size();
        uint64_t start = off > size ? size : off;
        uint64_t end = start + len < size ? start + len : size;
        b.kv("offset", start);
        b.kv("length", end - start);
        b.arr("bytes");
        for (uint64_t i = start; i < end; i++) b.valU(g_ctx.bytes[(size_t)i]);
        b.endArr();
    }
    b.endObj();
    b.endObj();
    postToUi(id, full);
}

static bool writeUtf8File(const wchar_t* pathW, const std::string& content) {
    HANDLE h = CreateFileW(pathW, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    WriteFile(h, content.data(), (DWORD)content.size(), &written, nullptr);
    CloseHandle(h);
    return written == (DWORD)content.size();
}

static void cmdExportReport(uint64_t id) {
    std::string analysis, path;
    {
        std::lock_guard<std::mutex> lk(g_ctxMutex);
        if (g_ctx.fullAnalysis.empty()) { respondError(id, "no analysis to export"); return; }
        analysis = g_ctx.fullAnalysis;
        path = g_ctx.path;
    }
    wchar_t fileBuf[4096];
    fileBuf[0] = 0;
    OPENFILENAMEW ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"HTML report\\0*.html;*.htm\\0All files\\0*.*\\0\\0";
    ofn.lpstrDefExt = L"html";
    ofn.lpstrFile = fileBuf;
    ofn.nMaxFile = 4096;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER | OFN_HIDEREADONLY;
    bool cancelled = false;
    if (GetSaveFileNameW(&ofn)) {
        std::string html = buildHtmlReport(analysis, path);
        if (!writeUtf8File(fileBuf, html)) {
            std::string full;
            Builder b(full);
            b.beginObj(); b.kv("id", id); b.kv("ok", false);
            b.kv("error", "failed to write report file"); b.endObj();
            postToUi(id, full);
            return;
        }
    } else {
        cancelled = true;
    }
    std::string full;
    Builder b(full);
    b.beginObj(); b.kv("id", id); b.kv("ok", true);
    b.obj("data");
    b.kv("exported", !cancelled);
    b.kv("path", cancelled ? std::string() : wideToUtf8(fileBuf));
    b.endObj();
    b.endObj();
    postToUi(id, full);
}

static void cmdOpenDialog(uint64_t id) {
    wchar_t fileBuf[4096];
    fileBuf[0] = 0;
    OPENFILENAMEW ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"Supported binaries\0*.exe;*.dll;*.sys;*.scr;*.cpl;*.ocx;*.ax;*.pyd;*.efi;*.apk;*.apks;*.xapk;*.jar;*.zip;*.dex;*.odex;*.so;*.a;*.o;*.class;*.bin;*.msi\0Executables (PE)\0*.exe;*.dll;*.sys\0Android packages\0*.apk;*.apks;*.xapk;*.jar\0ELF binaries\0*.so;*.bin;*.o;*.a\0All files\0*.*\0\0";
    ofn.lpstrFile = fileBuf;
    ofn.nMaxFile = 4096;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER | OFN_HIDEREADONLY;
    if (GetOpenFileNameW(&ofn)) {
        std::string p = wideToUtf8(fileBuf);
        std::string full;
        Builder b(full);
        b.beginObj();
        b.kv("id", id);
        b.kv("ok", true);
        b.obj("data");
        b.kv("path", p);
        b.endObj();
        b.endObj();
        postToUi(id, full);
    } else {
        std::string full;
        Builder b(full);
        b.beginObj();
        b.kv("id", id);
        b.kv("ok", true);
        b.obj("data");
        b.kv("path", "");
        b.endObj();
        b.endObj();
        postToUi(id, full);
    }
}

static void handleMessage(const JVal& m) {
    if (m.type != JVal::OBJ) return;
    uint64_t id = (uint64_t)m.getNum("id", 0);
    const JVal* cmdV = m.get("cmd");
    std::string cmd = cmdV ? cmdV->str : "";
    if (cmd == "open") {
        cmdOpenDialog(id);
    } else if (cmd == "export") {
        cmdExportReport(id);
    } else if (cmd == "analyze") {
        std::string path = m.getStr("path");
        if (path.empty()) { respondError(id, "no path"); return; }
        std::thread([id, path]() { runAnalysis(id, path); }).detach();
    } else if (cmd == "strings") {
        uint64_t offset = (uint64_t)m.getNum("offset", 0);
        uint32_t count = (uint32_t)m.getNum("count", 300);
        uint32_t minLen = (uint32_t)m.getNum("minLen", 4);
        int kind = m.getInt("kind", 0);
        std::string filter = m.getStr("filter");
        std::thread([id, offset, count, minLen, kind, filter]() {
            runStrings(id, offset, count, minLen, kind, filter);
        }).detach();
    } else if (cmd == "hex") {
        uint64_t off = (uint64_t)m.getNum("offset", 0);
        uint64_t len = (uint64_t)m.getNum("length", 256);
        if (len > 65536) len = 65536;
        serveHex(id, off, len);
    } else {
        respondError(id, "unknown command: " + cmd);
    }
}

class WebMessageHandler : public ICoreWebView2WebMessageReceivedEventHandler {
public:
    LONG refCount = 1;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (IsEqualIID(riid, __uuidof(IUnknown)) ||
            IsEqualIID(riid, __uuidof(ICoreWebView2WebMessageReceivedEventHandler))) {
            *ppv = static_cast<ICoreWebView2WebMessageReceivedEventHandler*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refCount); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG c = InterlockedDecrement(&refCount);
        if (!c) delete this;
        return (ULONG)c;
    }
    HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2* sender, ICoreWebView2WebMessageReceivedEventArgs* args) override {
        (void)sender;
        LPWSTR msg = nullptr;
        if (SUCCEEDED(args->get_WebMessageAsJson(&msg)) && msg) {
            std::string utf8 = wideToUtf8(msg);
            CoTaskMemFree(msg);
            JVal v;
            if (jsonParse(utf8, v)) handleMessage(v);
        }
        return S_OK;
    }
};

class ControllerCreatedHandler : public ICoreWebView2CreateCoreWebView2ControllerCompletedHandler {
public:
    std::string html;
    LONG refCount = 1;
    explicit ControllerCreatedHandler(const std::string& h) : html(h) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (IsEqualIID(riid, __uuidof(IUnknown)) ||
            IsEqualIID(riid, __uuidof(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler))) {
            *ppv = static_cast<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refCount); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG c = InterlockedDecrement(&refCount);
        if (!c) delete this;
        return (ULONG)c;
    }
    HRESULT STDMETHODCALLTYPE Invoke(HRESULT errorCode, ICoreWebView2Controller* result) override {
        if (FAILED(errorCode) || !result) {
            MessageBoxW(g_hwnd, L"Failed to create the WebView2 controller.", L"CodeBreak", MB_ICONERROR);
            return S_OK;
        }
        g_controller = result;
        g_controller->AddRef();
        ICoreWebView2* wv = nullptr;
        if (SUCCEEDED(result->get_CoreWebView2(&wv)) && wv) {
            g_webview = wv;
            ICoreWebView2Settings* settings = nullptr;
            if (SUCCEEDED(wv->get_Settings(&settings)) && settings) {
                settings->put_AreDefaultContextMenusEnabled(TRUE);
                settings->put_IsZoomControlEnabled(TRUE);
                settings->put_IsStatusBarEnabled(FALSE);
                settings->Release();
            }
            ICoreWebView2Controller4* c4 = nullptr;
            if (SUCCEEDED(result->QueryInterface(__uuidof(ICoreWebView2Controller4), (void**)&c4)) && c4) {
                c4->put_AllowExternalDrop(FALSE);
                c4->Release();
            }
            EventRegistrationToken tok;
            wv->add_WebMessageReceived(new WebMessageHandler(), &tok);
            wv->NavigateToString(utf8ToWide(html).c_str());
        }
        RECT rc;
        GetClientRect(g_hwnd, &rc);
        g_controller->put_Bounds(rc);
        return S_OK;
    }
};

class EnvironmentCreatedHandler : public ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler {
public:
    std::string html;
    LONG refCount = 1;
    explicit EnvironmentCreatedHandler(const std::string& h) : html(h) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (IsEqualIID(riid, __uuidof(IUnknown)) ||
            IsEqualIID(riid, __uuidof(ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler))) {
            *ppv = static_cast<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refCount); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG c = InterlockedDecrement(&refCount);
        if (!c) delete this;
        return (ULONG)c;
    }
    HRESULT STDMETHODCALLTYPE Invoke(HRESULT errorCode, ICoreWebView2Environment* env) override {
        if (FAILED(errorCode) || !env) {
            MessageBoxW(g_hwnd,
                L"The WebView2 Runtime could not be initialized.\n\n"
                L"Install the Microsoft Edge WebView2 Runtime from:\n"
                L"https://developer.microsoft.com/microsoft-edge/webview2/",
                L"CodeBreak", MB_ICONERROR);
            PostQuitMessage(1);
            return S_OK;
        }
        env->CreateCoreWebView2Controller(g_hwnd, new ControllerCreatedHandler(html));
        env->Release();
        return S_OK;
    }
};

static bool loadWebView2Loader() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    wchar_t* slash = wcsrchr(exePath, L'\\');
    if (slash) {
        *slash = 0;
        std::wstring dll = std::wstring(exePath) + L"\\WebView2Loader.dll";
        g_loader = LoadLibraryW(dll.c_str());
    }
    if (!g_loader) g_loader = LoadLibraryW(L"WebView2Loader.dll");
    if (!g_loader) return false;
    g_createEnv = (PFN_CreateWv2EnvWithOptions)GetProcAddress(g_loader, "CreateCoreWebView2EnvironmentWithOptions");
    g_getVersion = (PFN_GetWv2Version)GetProcAddress(g_loader, "GetAvailableCoreWebView2BrowserVersionString");
    return g_createEnv && g_getVersion;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        g_hwnd = hwnd;
        DragAcceptFiles(hwnd, TRUE);
        return 0;
    case WM_SIZE: {
        if (g_controller) {
            RECT rc;
            GetClientRect(hwnd, &rc);
            g_controller->put_Bounds(rc);
        }
        return 0;
    }
    case WM_APP_ANALYSIS: {
        PendingResult* pr = (PendingResult*)lParam;
        if (pr) {
            if (g_webview) g_webview->PostWebMessageAsJson(utf8ToWide(pr->json).c_str());
            delete pr;
        }
        return 0;
    }
    case WM_DROPFILES: {
        HDROP drop = (HDROP)wParam;
        UINT n = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
        std::string j;
        Builder b(j);
        b.beginObj();
        b.kv("event", "drop");
        b.arr("paths");
        for (UINT i = 0; i < n && i < 8; i++) {
            wchar_t buf[4096];
            if (DragQueryFileW(drop, i, buf, 4096)) b.valStr(wideToUtf8(buf));
        }
        b.endArr();
        b.endObj();
        DragFinish(drop);
        if (g_webview) g_webview->PostWebMessageAsJson(utf8ToWide(j).c_str());
        return 0;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize.x = 940;
        mmi->ptMinTrackSize.y = 560;
        return 0;
    }
    case WM_DESTROY:
        if (g_webview) { g_webview->Release(); g_webview = nullptr; }
        if (g_controller) { g_controller->Release(); g_controller = nullptr; }
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        MessageBoxW(nullptr, L"COM initialization failed.", L"CodeBreak", MB_ICONERROR);
        return 1;
    }

    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(102));
    wc.hIconSm = wc.hIcon;
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszClassName = WND_CLASS;
    RegisterClassExW(&wc);

    RECT wr = { 0, 0, 1280, 820 };
    AdjustWindowRect(&wr, WS_OVERLAPPEDWINDOW, FALSE);
    HWND hwnd = CreateWindowExW(
        0, WND_CLASS, WND_TITLE,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        wr.right - wr.left, wr.bottom - wr.top,
        nullptr, nullptr, hInstance, nullptr);
    if (!hwnd) {
        CoUninitialize();
        return 1;
    }
    g_hwnd = hwnd;

    BOOL dark = TRUE;
    DwmSetWindowAttribute(hwnd, 20, &dark, sizeof(dark));

    if (!loadWebView2Loader()) {
        MessageBoxW(hwnd,
            L"WebView2Loader.dll was not found.\n\n"
            L"Keep WebView2Loader.dll next to CodeBreak.exe "
            L"(it ships with this application).",
            L"CodeBreak", MB_ICONERROR);
        DestroyWindow(hwnd);
        CoUninitialize();
        return 1;
    }

    LPWSTR version = nullptr;
    if (FAILED(g_getVersion(nullptr, &version)) || !version) {
        MessageBoxW(hwnd,
            L"The Microsoft Edge WebView2 Runtime is not installed.\n\n"
            L"Download it from:\n"
            L"https://developer.microsoft.com/microsoft-edge/webview2/",
            L"CodeBreak", MB_ICONERROR);
        DestroyWindow(hwnd);
        CoUninitialize();
        return 1;
    }
    if (version) CoTaskMemFree(version);

    std::string html = loadHtmlResource();

    wchar_t dataDir[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, dataDir))) {
        CreateDirectoryW((std::wstring(dataDir) + L"\\CodeBreak").c_str(), nullptr);
        std::wstring ud = std::wstring(dataDir) + L"\\CodeBreak\\WebView2Data";
        CreateDirectoryW(ud.c_str(), nullptr);
        hr = g_createEnv(nullptr, ud.c_str(), nullptr, new EnvironmentCreatedHandler(html));
    } else {
        hr = g_createEnv(nullptr, nullptr, nullptr, new EnvironmentCreatedHandler(html));
    }
    if (FAILED(hr)) {
        MessageBoxW(hwnd, L"Failed to start the WebView2 environment.", L"CodeBreak", MB_ICONERROR);
        DestroyWindow(hwnd);
        CoUninitialize();
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CoUninitialize();
    return (int)msg.wParam;
}
