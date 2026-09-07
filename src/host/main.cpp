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
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <thread>
#include <memory>
#include <algorithm>
#include <cstdio>

#include "../formats.h"
#include "../hashes.h"
#include "../jsonr.h"
#include "../report.h"
#include "../util.h"

#ifdef _MSC_VER
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "dwmapi.lib")
#endif

using namespace cb;

#define IDM_OPEN 101
#define IDM_EXPORT 102
#define IDM_EXIT 103
#define IDM_FIND 104
#define IDM_EXPAND 105
#define IDM_COLLAPSE 106
#define IDM_ABOUT 107

#define ID_BTN_OPEN 201
#define ID_STAT_TITLE 202
#define ID_STAT_SUMMARY 203
#define ID_STAT_RISK 204
#define ID_STAT_FINDLBL 205
#define ID_EDIT_FIND 206
#define ID_TREE 207
#define ID_VAL 208
#define ID_STAT_STATUS 209

#define WM_APP_RESULT (WM_APP + 1)
#define WM_APP_RECENT (WM_APP + 2)

static const wchar_t* WND_CLASS = L"CodeBreakMainWindow";
static const wchar_t* WND_TITLE = L"CodeBreak - Binary Analysis Suite";

struct ResultMsg {
    std::string path;
    std::string json;
    std::string hash;
    double ms = 0;
    bool ok = false;
    std::string error;
};

static HWND g_hwnd = nullptr;
static HWND g_btnOpen, g_lblTitle, g_lblSummary, g_lblRisk, g_lblFindLbl;
static HWND g_editFind, g_tree, g_val, g_lblStatus;
static HMENU g_menu = nullptr;
static HACCEL g_accel = nullptr;

static HFONT g_fontTitle, g_fontUI, g_fontMono;
static HBRUSH g_brushBg;
static COLORREF g_clrSummary = RGB(225, 232, 242);
static COLORREF g_clrRisk = RGB(120, 210, 160);
static std::string g_riskLevel;

static JVal* g_root = nullptr;
static std::string g_path;
static std::string g_analysisJson;
static std::vector<std::string> g_recent;
static bool g_recentEnabled = false;

static std::string wideToUtf8(const wchar_t* w) {
    if (!w || !*w) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return std::string();
    std::string s((size_t)n - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    return s;
}

static void lowerAscii(std::string& s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
}

static COLORREF riskColor(const std::string& level) {
    std::string l = level;
    lowerAscii(l);
    if (l == "critical") return RGB(255, 90, 90);
    if (l == "high") return RGB(255, 140, 70);
    if (l == "medium") return RGB(255, 200, 80);
    if (l == "low") return RGB(180, 220, 120);
    if (l == "clean") return RGB(110, 210, 160);
    return RGB(160, 175, 195);
}

static std::string scalarText(const JVal& v) {
    switch (v.type) {
    case JVal::NUL: return "null";
    case JVal::BOOL: return v.b ? "true" : "false";
    case JVal::NUM: {
        double d = v.num;
        if (d == (double)(long long)d && d > -9.2e15 && d < 9.2e15) return std::to_string((long long)d);
        return std::to_string(d);
    }
    case JVal::STR: return v.str;
    default: return "";
    }
}

static std::string describeValue(const JVal& v, size_t depth, size_t& budget) {
    std::string out;
    std::string pad;
    for (size_t i = 0; i < depth; i++) pad += "  ";
    if (v.type == JVal::OBJ) {
        out += pad + "{\n";
        for (auto& p : v.props) {
            if (budget == 0) { out += pad + "  ... (truncated)\n"; break; }
            budget--;
            const JVal& c = p.second;
            out += pad + "  " + p.first + ": ";
            if (c.type == JVal::OBJ) out += "{ " + std::to_string(c.props.size()) + " fields }\n";
            else if (c.type == JVal::ARR) out += "[ " + std::to_string(c.arr.size()) + " items ]\n";
            else out += scalarText(c) + "\n";
        }
        out += pad + "}";
    } else if (v.type == JVal::ARR) {
        out += pad + "[\n";
        for (size_t i = 0; i < v.arr.size(); i++) {
            if (budget == 0) { out += pad + "  ... (truncated)\n"; break; }
            budget--;
            const JVal& c = v.arr[i];
            if (c.type == JVal::OBJ) {
                out += pad + "  [" + std::to_string(i) + "] { ";
                bool first = true;
                for (auto& q : c.props) {
                    if (!first) out += ", ";
                    first = false;
                    if (q.second.type == JVal::OBJ) out += q.first + "={obj}";
                    else if (q.second.type == JVal::ARR) out += q.first + "=[arr]";
                    else out += q.first + "=" + scalarText(q.second);
                }
                out += " }\n";
            } else if (c.type == JVal::ARR) {
                out += pad + "  [" + std::to_string(i) + "] [ " + std::to_string(c.arr.size()) + " items ]\n";
            } else {
                out += pad + "  [" + std::to_string(i) + "] " + scalarText(c) + "\n";
            }
        }
        out += pad + "]";
    } else {
        out = scalarText(v);
    }
    return out;
}

static HTREEITEM addNode(HWND tree, HTREEITEM parent, const std::string& text, const JVal* v) {
    TVINSERTSTRUCTW ins;
    memset(&ins, 0, sizeof(ins));
    ins.hParent = parent;
    ins.hInsertAfter = TVI_LAST;
    ins.item.mask = TVIF_TEXT | TVIF_PARAM;
    std::wstring w = cb::utf8ToWide(text);
    ins.item.pszText = const_cast<wchar_t*>(w.c_str());
    ins.item.lParam = (LPARAM)v;
    return (HTREEITEM)SendMessageW(tree, TVM_INSERTITEMW, 0, (LPARAM)&ins);
}

static void addChildren(HWND tree, HTREEITEM parent, const JVal& v) {
    if (v.type == JVal::OBJ) {
        for (auto& p : v.props) {
            const JVal& c = p.second;
            bool container = c.type == JVal::OBJ || c.type == JVal::ARR;
            HTREEITEM it = addNode(tree, parent, p.first, &c);
            if (container) addChildren(tree, it, c);
        }
    } else if (v.type == JVal::ARR) {
        for (size_t i = 0; i < v.arr.size(); i++) {
            const JVal& c = v.arr[i];
            bool container = c.type == JVal::OBJ || c.type == JVal::ARR;
            HTREEITEM it = addNode(tree, parent, "[" + std::to_string(i) + "]", &c);
            if (container) addChildren(tree, it, c);
        }
    }
}

static void addFiltered(HWND tree, const JVal& v, const std::string& path, const std::string& ql) {
    for (auto& p : v.props) {
        const JVal& c = p.second;
        std::string p2 = path.empty() ? p.first : path + "." + p.first;
        std::string kl = p.first;
        lowerAscii(kl);
        if (kl.find(ql) != std::string::npos) addNode(tree, nullptr, p2, &c);
        if (c.type == JVal::OBJ) addFiltered(tree, c, p2, ql);
        else if (c.type == JVal::ARR) {
            for (size_t i = 0; i < c.arr.size(); i++)
                if (c.arr[i].type == JVal::OBJ) addFiltered(tree, c.arr[i], p2 + "[" + std::to_string(i) + "]", ql);
        }
    }
}

static void populateTree(HWND tree, const JVal& root) {
    TreeView_DeleteAllItems(tree);
    wchar_t q[512];
    GetWindowTextW(g_editFind, q, 512);
    std::string ql = wideToUtf8(q);
    if (!ql.empty()) {
        lowerAscii(ql);
        addFiltered(tree, root, "", ql);
        return;
    }
    addChildren(tree, nullptr, root);
    /* expand first level so sections are visible */
    HTREEITEM child = TreeView_GetRoot(tree);
    while (child) {
        SendMessageW(tree, TVM_EXPAND, TVE_EXPAND, (LPARAM)child);
        child = TreeView_GetNextSibling(tree, child);
    }
}

static void setSummaryTexts(const JVal& root) {
    const JVal* file = root.get("file");
    const JVal* fmt = root.get("format");
    const JVal* risk = root.get("risk");
    std::string txt = "Drop a file here or use File > Open...";
    if (file || fmt || risk) {
        txt.clear();
        if (file) txt += file->getStr("name");
        if (file) txt += "  \u00b7  " + file->getStr("sizeHuman");
        if (fmt) txt += "  \u00b7  " + fmt->getStr("label");
        const JVal* inds = root.get("indicators");
        if (inds && inds->type == JVal::ARR)
            txt += "  \u00b7  " + std::to_string(inds->arr.size()) + (inds->arr.size() == 1 ? " indicator" : " indicators");
    }
    SetWindowTextW(g_lblSummary, cb::utf8ToWide(txt).c_str());

    if (risk) {
        std::string level = risk->getStr("level");
        std::string score = std::to_string((long long)risk->getNum("score", 0));
        g_riskLevel = level;
        g_clrRisk = riskColor(level);
        std::string lvl = level.empty() ? "" : level;
        if (!lvl.empty()) lvl[0] = (char)((lvl[0] >= 'a' && lvl[0] <= 'z') ? lvl[0] - 32 : lvl[0]);
        SetWindowTextW(g_lblRisk, cb::utf8ToWide("RISK  " + lvl + "   " + score + "/100").c_str());
    } else {
        g_riskLevel.clear();
        g_clrRisk = RGB(160, 175, 195);
        SetWindowTextW(g_lblRisk, cb::utf8ToWide("RISK  -").c_str());
    }
    InvalidateRect(g_lblSummary, nullptr, TRUE);
    InvalidateRect(g_lblRisk, nullptr, TRUE);
}

static void showValue(JVal* v) {
    if (!v) { SetWindowTextW(g_val, L""); return; }
    size_t budget = 600;
    SetWindowTextW(g_val, cb::utf8ToWide(describeValue(*v, 0, budget)).c_str());
}

static void addRecent(const std::string& p) {
    for (auto it = g_recent.begin(); it != g_recent.end(); ++it)
        if (*it == p) { g_recent.erase(it); break; }
    g_recent.insert(g_recent.begin(), p);
    if (g_recent.size() > 10) g_recent.pop_back();
    g_recentEnabled = true;
}

static void refreshRecentMenu() {
    HMENU m = GetSubMenu(g_menu, 0);
    while (GetMenuItemCount(m) > 4) RemoveMenu(m, 4, MF_BYPOSITION);
    UINT base = IDM_OPEN + 100;
    for (size_t i = 0; i < g_recent.size(); i++) {
        std::wstring label = L"&" + std::to_wstring(i + 1) + L"  " + cb::utf8ToWide(g_recent[i]);
        AppendMenuW(m, MF_STRING, base + (UINT)i, label.c_str());
    }
}

static void loadFile(const std::string& pathUtf8) {
    addRecent(pathUtf8);
    SetWindowTextW(g_lblStatus, cb::utf8ToWide("Analyzing " + pathUtf8 + " ...").c_str());
    std::thread([pathUtf8]() {
        ResultMsg* r = new ResultMsg();
        r->path = pathUtf8;
        std::vector<uint8_t> data;
        std::string err;
        if (!readFileBytes(pathUtf8, data, err)) {
            r->ok = false;
            r->error = err;
            PostMessageW(g_hwnd, WM_APP_RESULT, 0, (LPARAM)r);
            return;
        }
        FileInfo fi = queryFileInfo(pathUtf8);
        r->hash = sha256Hex(data.data(), data.size());
        auto t0 = std::chrono::steady_clock::now();
        AnalysisOutput ao = analyzeFile(data.data(), data.size(), pathUtf8, fi);
        auto t1 = std::chrono::steady_clock::now();
        r->ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        r->ok = ao.ok;
        if (ao.ok) r->json = ao.json;
        else r->error = "analysis failed";
        PostMessageW(g_hwnd, WM_APP_RESULT, 0, (LPARAM)r);
    }).detach();
}

static void applyResult(ResultMsg* r) {
    if (!r) return;
    std::string path = r->path;
    std::string json = r->json;
    bool ok = r->ok;
    double ms = r->ms;
    std::string hash = r->hash;
    std::string errText = r->error;
    delete r;

    if (!ok) {
        SetWindowTextW(g_lblStatus, cb::utf8ToWide("Error analyzing " + path + ": " + errText).c_str());
        return;
    }

    if (g_root) { delete g_root; g_root = nullptr; }
    TreeView_DeleteAllItems(g_tree);
    SetWindowTextW(g_val, L"");
    g_analysisJson = json;
    g_path = path;

    JVal* jr = new JVal();
    if (!jsonParse(json, *jr) || jr->type != JVal::OBJ) {
        delete jr;
        SetWindowTextW(g_lblStatus, cb::utf8ToWide("Failed to parse analysis for " + path).c_str());
        return;
    }
    g_root = jr;
    populateTree(g_tree, *g_root);
    setSummaryTexts(*g_root);

    size_t slash = path.find_last_of("/\\");
    std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
    SetWindowTextW(g_hwnd, cb::utf8ToWide(name + "  \u2013  CodeBreak").c_str());

    char buf[120];
    snprintf(buf, sizeof(buf), "%s  \u00b7  SHA-256  %s  \u00b7  %d ms", path.c_str(),
             hash.substr(0, 16).c_str(), (int)ms);
    SetWindowTextW(g_lblStatus, cb::utf8ToWide(buf).c_str());
    refreshRecentMenu();
}

static void openFileDialog() {
    wchar_t fileBuf[4096];
    fileBuf[0] = 0;
    OPENFILENAMEW ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"All files\0*.*\0Executables (PE)\0*.exe;*.dll;*.sys;*.scr\0Archives & packages\0*.apk;*.jar;*.zip;*.tar;*.gz\0ELF / Mach-O\0*.so;*.bin;*.o;*.dylib\0Office (OLE2)\0*.doc;*.xls;*.ppt;*.msi\0Signatures & PDF\0*.p7;*.p7b;*.pdf\0\0";
    ofn.lpstrFile = fileBuf;
    ofn.nMaxFile = 4096;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER | OFN_HIDEREADONLY;
    if (GetOpenFileNameW(&ofn)) loadFile(wideToUtf8(fileBuf));
}

static void exportReport() {
    if (g_analysisJson.empty() || g_path.empty()) {
        MessageBoxW(g_hwnd, L"Analyze a file first, then export its HTML report.", WND_TITLE, MB_ICONINFORMATION);
        return;
    }
    wchar_t fileBuf[4096];
    fileBuf[0] = 0;
    OPENFILENAMEW ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"HTML report\0*.html\0\0";
    ofn.lpstrDefExt = L"html";
    ofn.lpstrFile = fileBuf;
    ofn.nMaxFile = 4096;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER | OFN_HIDEREADONLY;
    if (!GetSaveFileNameW(&ofn)) return;
    std::string html = buildHtmlReport(g_analysisJson, g_path);
    std::wstring file = fileBuf;
    HANDLE h = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        MessageBoxW(g_hwnd, L"Could not write the report file.", WND_TITLE, MB_ICONERROR);
        return;
    }
    DWORD written = 0;
    WriteFile(h, html.data(), (DWORD)html.size(), &written, nullptr);
    CloseHandle(h);
    std::string msg = "HTML report written:\n" + wideToUtf8(file.c_str());
    MessageBoxW(g_hwnd, cb::utf8ToWide(msg).c_str(), WND_TITLE, MB_ICONINFORMATION);
}

static void setFindFocus() {
    SetFocus(g_editFind);
    SendMessageW(g_editFind, EM_SETSEL, 0, -1);
}

static void expandAll(HWND tree, HTREEITEM parent, bool expand) {
    SendMessageW(tree, TVM_EXPAND, expand ? TVE_EXPAND : TVE_COLLAPSE, (LPARAM)parent);
    HTREEITEM child = TreeView_GetChild(tree, parent);
    while (child) {
        expandAll(tree, child, expand);
        child = TreeView_GetNextSibling(tree, child);
    }
}

static void setSubTreeExpansion(bool expand) {
    HTREEITEM root = TreeView_GetRoot(g_tree);
    while (root) {
        expandAll(g_tree, root, expand);
        root = TreeView_GetNextSibling(g_tree, root);
    }
}

static void ensureControls(HWND hwnd) {
    if (g_btnOpen) return;
    HINSTANCE hInst = GetModuleHandleW(nullptr);
    const DWORD labelSt = WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP;

    g_btnOpen = CreateWindowW(L"BUTTON", L"Open File\u2026",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)ID_BTN_OPEN, hInst, nullptr);
    g_lblTitle = CreateWindowW(L"STATIC", L"CODEBREAK",
        labelSt, 0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)ID_STAT_TITLE, hInst, nullptr);
    g_lblSummary = CreateWindowW(L"STATIC", L"Drop a file here or use File > Open...",
        labelSt, 0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)ID_STAT_SUMMARY, hInst, nullptr);
    g_lblRisk = CreateWindowW(L"STATIC", L"RISK -",
        labelSt | SS_CENTER, 0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)ID_STAT_RISK, hInst, nullptr);
    g_lblFindLbl = CreateWindowW(L"STATIC", L"Find",
        labelSt, 0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)ID_STAT_FINDLBL, hInst, nullptr);
    g_editFind = CreateWindowW(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)ID_EDIT_FIND, hInst, nullptr);
    g_tree = CreateWindowW(WC_TREEVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS | WS_BORDER,
        0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)ID_TREE, hInst, nullptr);
    g_val = CreateWindowW(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL | WS_HSCROLL | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_BORDER,
        0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)ID_VAL, hInst, nullptr);
    g_lblStatus = CreateWindowW(L"STATIC", L"Ready",
        WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP | WS_BORDER,
        0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)ID_STAT_STATUS, hInst, nullptr);

    SetWindowFont(g_btnOpen, g_fontUI, TRUE);
    SetWindowFont(g_lblTitle, g_fontTitle, TRUE);
    SetWindowFont(g_lblSummary, g_fontUI, TRUE);
    SetWindowFont(g_lblRisk, g_fontTitle, TRUE);
    SetWindowFont(g_lblFindLbl, g_fontUI, TRUE);
    SetWindowFont(g_editFind, g_fontUI, TRUE);
    SetWindowFont(g_tree, g_fontUI, TRUE);
    SetWindowFont(g_val, g_fontMono, TRUE);
    SetWindowFont(g_lblStatus, g_fontUI, TRUE);

    SendMessageW(g_tree, TVM_SETTEXTCOLOR, 0, (LPARAM)RGB(214, 222, 234));
    SendMessageW(g_tree, TVM_SETBKCOLOR, 0, (LPARAM)RGB(24, 30, 42));
    SendMessageW(g_tree, TVM_SETLINECOLOR, 0, (LPARAM)RGB(70, 80, 100));
    SendMessageW(g_tree, TVM_SETEXTENDEDSTYLE, TVS_EX_DOUBLEBUFFER, TVS_EX_DOUBLEBUFFER);
    SendMessageW(g_editFind, EM_SETCUEBANNER, TRUE, (LPARAM)L"field name  (sha256, risk, imports, subject...)");
}

static void layout(HWND hwnd) {
    RECT rc;
    GetClientRect(hwnd, &rc);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    if (w < 60 || h < 60) return;
    const int pad = 10;
    const int topPad = 6;
    const int titleY = topPad + 2;
    const int titleH = 24;
    const int riskW = 150;
    const int btnW = 96;

    SetWindowPos(g_lblTitle, nullptr, pad + 2, titleY, 120, titleH, SWP_NOZORDER);
    SetWindowPos(g_btnOpen, nullptr, w - pad - riskW - 8 - btnW, titleY, btnW, 24, SWP_NOZORDER);
    SetWindowPos(g_lblRisk, nullptr, w - pad - riskW, titleY, riskW, titleH, SWP_NOZORDER);

    int sumY = titleY + titleH + 6;
    int sumH = 20;
    SetWindowPos(g_lblSummary, nullptr, pad + 2, sumY, w - pad - pad - 4, sumH, SWP_NOZORDER);

    int findY = sumY + sumH + 8;
    int findH = 22;
    int findLabelW = 40;
    SetWindowPos(g_lblFindLbl, nullptr, pad + 2, findY + 3, findLabelW, findH, SWP_NOZORDER);
    SetWindowPos(g_editFind, nullptr, pad + 2 + findLabelW, findY, w - pad - (pad + 2 + findLabelW) - pad, findH, SWP_NOZORDER);

    int bodyY = findY + findH + 8;
    int statusH = 20;
    int bodyBottom = h - statusH - pad;
    if (bodyBottom < bodyY) bodyBottom = bodyY + 60;
    int gap = 6;
    int treeW = w * 46 / 100;
    SetWindowPos(g_tree, nullptr, pad, bodyY, treeW, bodyBottom - bodyY, SWP_NOZORDER);
    SetWindowPos(g_val, nullptr, pad + treeW + gap, bodyY, w - pad - treeW - gap - pad, bodyBottom - bodyY, SWP_NOZORDER);
    SetWindowPos(g_lblStatus, nullptr, pad, h - statusH - pad, w - pad - pad, statusH, SWP_NOZORDER);
}

static void aboutBox() {
    const char* msg =
        "CodeBreak - Binary Analysis Suite\n\n"
        "Native binary analysis for Windows.\n\n"
        "Formats: PE, ELF, Mach-O, APK/DEX, ZIP, JAR, Java class,\n"
        "GZIP, TAR, PDF, OLE2 (.doc/.xls/.msi), PKCS #7 / Authenticode.\n\n"
        "Drop a file anywhere to analyze it, or use File > Open.\n"
        "The Find box filters the analysis tree by field name.\n";
    MessageBoxW(g_hwnd, cb::utf8ToWide(msg).c_str(), L"About CodeBreak", MB_ICONINFORMATION);
}

static void openRecent(UINT id) {
    size_t idx = (size_t)id - IDM_OPEN - 100;
    if (idx < g_recent.size()) loadFile(g_recent[idx]);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hwnd;
        DragAcceptFiles(hwnd, TRUE);
        ensureControls(hwnd);
        layout(hwnd);

        g_menu = CreateMenu();
        HMENU mFile = CreatePopupMenu();
        AppendMenuW(mFile, MF_STRING, IDM_OPEN, L"&Open File...\tCtrl+O");
        AppendMenuW(mFile, MF_STRING, IDM_EXPORT, L"&Export HTML Report...");
        AppendMenuW(mFile, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(mFile, MF_STRING, IDM_EXIT, L"E&xit\tAlt+F4");
        HMENU mEdit = CreatePopupMenu();
        AppendMenuW(mEdit, MF_STRING, IDM_FIND, L"&Find Field\tCtrl+F");
        AppendMenuW(mEdit, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(mEdit, MF_STRING, IDM_EXPAND, L"Expand &All");
        AppendMenuW(mEdit, MF_STRING, IDM_COLLAPSE, L"&Collapse All");
        HMENU mHelp = CreatePopupMenu();
        AppendMenuW(mHelp, MF_STRING, IDM_ABOUT, L"&About");
        AppendMenuW(g_menu, MF_POPUP, (UINT_PTR)mFile, L"&File");
        AppendMenuW(g_menu, MF_POPUP, (UINT_PTR)mEdit, L"&Edit");
        AppendMenuW(g_menu, MF_POPUP, (UINT_PTR)mHelp, L"&Help");
        SetMenu(hwnd, g_menu);

        ACCEL acc[] = {
            { FCONTROL | FVIRTKEY, 'O', IDM_OPEN },
            { FCONTROL | FVIRTKEY, 'F', IDM_FIND },
            { FVIRTKEY, VK_F5, IDM_EXPAND },
        };
        g_accel = CreateAcceleratorTableW(acc, 3);
        return 0;
    }
    case WM_SIZE:
        layout(hwnd);
        return 0;
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize.x = 760;
        mmi->ptMinTrackSize.y = 480;
        return 0;
    }
    case WM_APP_RESULT:
        applyResult((ResultMsg*)lParam);
        return 0;
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDM_OPEN || id == ID_BTN_OPEN) openFileDialog();
        else if (id == IDM_EXPORT) exportReport();
        else if (id == IDM_EXIT) DestroyWindow(hwnd);
        else if (id == IDM_FIND) setFindFocus();
        else if (id == IDM_EXPAND) setSubTreeExpansion(true);
        else if (id == IDM_COLLAPSE) setSubTreeExpansion(false);
        else if (id == IDM_ABOUT) aboutBox();
        else if (id == ID_EDIT_FIND && HIWORD(wParam) == EN_CHANGE && g_root) populateTree(g_tree, *g_root);
        else if (id >= IDM_OPEN + 100) openRecent((UINT)id);
        return 0;
    }
    case WM_NOTIFY: {
        NMHDR* nm = (NMHDR*)lParam;
        if (nm->hwndFrom == g_tree && nm->code == TVN_SELCHANGEDW) {
            NMTREEVIEWW* nmt = (NMTREEVIEWW*)lParam;
            showValue((JVal*)nmt->itemNew.lParam);
        }
        return 0;
    }
    case WM_DROPFILES: {
        HDROP drop = (HDROP)wParam;
        if (DragQueryFileW(drop, 0, nullptr, 0) > 0) {
            wchar_t buf[4096];
            if (DragQueryFileW(drop, 0, buf, 4096)) loadFile(wideToUtf8(buf));
        }
        DragFinish(drop);
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wParam;
        HWND ctl = (HWND)lParam;
        int idc = GetDlgCtrlID(ctl);
        if (idc == ID_STAT_TITLE) {
            SetTextColor(dc, RGB(120, 190, 255));
            SetBkMode(dc, TRANSPARENT);
            return (LRESULT)g_brushBg;
        }
        if (idc == ID_STAT_RISK) {
            SetTextColor(dc, g_clrRisk);
            SetBkMode(dc, TRANSPARENT);
            return (LRESULT)g_brushBg;
        }
        if (idc == ID_STAT_FINDLBL) {
            SetTextColor(dc, RGB(150, 165, 185));
            SetBkMode(dc, TRANSPARENT);
            return (LRESULT)g_brushBg;
        }
        if (idc == ID_STAT_STATUS) {
            SetTextColor(dc, RGB(150, 165, 185));
            SetBkMode(dc, OPAQUE);
            SetBkColor(dc, RGB(14, 18, 26));
            return (LRESULT)g_brushBg;
        }
        SetTextColor(dc, g_clrSummary);
        SetBkMode(dc, TRANSPARENT);
        return (LRESULT)g_brushBg;
    }
    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)wParam;
        HWND ctl = (HWND)lParam;
        if (ctl == g_editFind) {
            SetTextColor(dc, RGB(220, 226, 236));
            SetBkColor(dc, RGB(30, 38, 52));
            return (LRESULT)g_brushBg;
        }
        break;
    }
    case WM_DESTROY:
        if (g_root) { delete g_root; g_root = nullptr; }
        if (g_menu) { DestroyMenu(g_menu); g_menu = nullptr; }
        if (g_accel) { DestroyAcceleratorTable(g_accel); g_accel = nullptr; }
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR cmdline, int nCmdShow) {
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    g_fontTitle = CreateFontW(-22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                              OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                              DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    g_fontUI = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    g_fontMono = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             FIXED_PITCH | FF_MODERN, L"Consolas");
    g_brushBg = CreateSolidBrush(RGB(14, 18, 26));

    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(102));
    wc.hIconSm = wc.hIcon;
    wc.hbrBackground = g_brushBg;
    wc.lpszClassName = WND_CLASS;
    RegisterClassExW(&wc);

    RECT wr = { 0, 0, 1240, 800 };
    AdjustWindowRect(&wr, WS_OVERLAPPEDWINDOW, FALSE);
    HWND hwnd = CreateWindowExW(0, WND_CLASS, WND_TITLE, WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT,
                                wr.right - wr.left, wr.bottom - wr.top,
                                nullptr, nullptr, hInstance, nullptr);
    if (!hwnd) return 1;
    g_hwnd = hwnd;

    BOOL dark = TRUE;
    DwmSetWindowAttribute(hwnd, 20, &dark, sizeof(dark));

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    if (cmdline && *cmdline) {
        std::wstring cl(cmdline);
        if (cl[0] == L'"' && cl.back() == L'"') cl = cl.substr(1, cl.size() - 2);
        loadFile(wideToUtf8(cl.c_str()));
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!g_accel || !TranslateAcceleratorW(hwnd, g_accel, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    if (g_fontTitle) DeleteObject(g_fontTitle);
    if (g_fontUI) DeleteObject(g_fontUI);
    if (g_fontMono) DeleteObject(g_fontMono);
    if (g_brushBg) DeleteObject(g_brushBg);
    return (int)msg.wParam;
}
