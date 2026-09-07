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

#include "../formats.h"
#include "../jsonr.h"
#include "../util.h"

#ifdef _MSC_VER
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ole32.lib")
#endif

using namespace cb;

#define ID_BTN_OPEN 1
#define ID_TREE 3
#define ID_VAL 4
#define ID_EDIT_FIND 5

#define WM_APP_RESULT (WM_APP + 1)

static const wchar_t* WND_CLASS = L"CodeBreakMainWindow";
static const wchar_t* WND_TITLE = L"CodeBreak - Binary Analysis Suite";

static HWND g_hwnd = nullptr;
static HWND g_btnOpen = nullptr;
static HWND g_lblSummary = nullptr;
static HWND g_lblFind = nullptr;
static HWND g_editFind = nullptr;
static HWND g_tree = nullptr;
static HWND g_val = nullptr;

static HFONT g_fontUI = nullptr;
static HFONT g_fontMono = nullptr;

static JVal* g_root = nullptr;
static std::string g_path;

struct ResultMsg {
    std::string path;
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

static std::string scalarText(const JVal& v) {
    switch (v.type) {
    case JVal::NUL: return "null";
    case JVal::BOOL: return v.b ? "true" : "false";
    case JVal::NUM: {
        double d = v.num;
        if (d == (double)(long long)d && d > -9.2e15 && d < 9.2e15)
            return std::to_string((long long)d);
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
        std::string key = p.first;
        std::string kl = key;
        std::transform(kl.begin(), kl.end(), kl.begin(), [](char x){ return (char)((x >= 'A' && x <= 'Z') ? x + 32 : x); });
        if (kl.find(ql) != std::string::npos) addNode(tree, nullptr, p2, &c);
        if (c.type == JVal::OBJ) addFiltered(tree, c, p2, ql);
        else if (c.type == JVal::ARR) {
            for (size_t i = 0; i < c.arr.size(); i++) {
                if (c.arr[i].type == JVal::OBJ) addFiltered(tree, c.arr[i], p2 + "[" + std::to_string(i) + "]", ql);
            }
        }
    }
}

static void populateTree(HWND tree, const JVal& root) {
    TreeView_DeleteAllItems(tree);
    wchar_t q[512];
    GetWindowTextW(g_editFind, q, 512);
    std::string ql = wideToUtf8(q);
    if (!ql.empty()) {
        std::transform(ql.begin(), ql.end(), ql.begin(), [](char x){ return (char)((x >= 'A' && x <= 'Z') ? x + 32 : x); });
        addFiltered(tree, root, "", ql);
        return;
    }
    addChildren(tree, nullptr, root);
}

static void setSummary(const JVal& root) {
    std::string txt = "Drop a file here or press Open File...";
    const JVal* file = root.get("file");
    const JVal* fmt = root.get("format");
    const JVal* risk = root.get("risk");
    const JVal* hashes = root.get("hashes");
    if (file || fmt || risk) {
        txt.clear();
        if (file) {
            txt += file->getStr("name");
            txt += "  |  " + file->getStr("sizeHuman");
        }
        if (fmt) txt += "  |  " + fmt->getStr("label");
        if (risk) {
            std::string level = risk->getStr("level");
            txt += "   |   RISK " + level + " (" + std::to_string((long long)risk->getNum("score", 0)) + "/100)";
        }
        const JVal* inds = root.get("indicators");
        if (inds && inds->type == JVal::ARR) txt += "   |   " + std::to_string(inds->arr.size()) + " indicator(s)";
        if (hashes) {
            std::string sh = hashes->getStr("sha256");
            txt += "   |   sha256 " + sh.substr(0, 16) + "...";
        }
    }
    SetWindowTextW(g_lblSummary, cb::utf8ToWide(txt).c_str());
}

static void showValue(JVal* v) {
    if (!v) { SetWindowTextW(g_val, L""); return; }
    size_t budget = 500;
    SetWindowTextW(g_val, cb::utf8ToWide(describeValue(*v, 0, budget)).c_str());
}

static void loadFile(const std::string& pathUtf8) {
    SetWindowTextW(g_lblSummary, cb::utf8ToWide("Analyzing " + pathUtf8 + " ...").c_str());
    std::thread([pathUtf8]() {
        std::vector<uint8_t> data;
        std::string err;
        ResultMsg* r = new ResultMsg();
        r->path = pathUtf8;
        if (readFileBytes(pathUtf8, data, err)) {
            FileInfo fi = queryFileInfo(pathUtf8);
            AnalysisOutput ao = analyzeFile(data.data(), data.size(), pathUtf8, fi);
            if (ao.ok) r->json = ao.json;
        } else {
            r->json.clear();
        }
        PostMessageW(g_hwnd, WM_APP_RESULT, 0, (LPARAM)r);
    }).detach();
}

static void applyResult(ResultMsg* r) {
    if (r->json.empty()) {
        SetWindowTextW(g_lblSummary, cb::utf8ToWide("Could not analyze: " + r->path).c_str());
        delete r;
        return;
    }
    g_path = r->path;
    std::string json = r->json;
    delete r;

    if (g_root) { delete g_root; g_root = nullptr; }
    TreeView_DeleteAllItems(g_tree);
    SetWindowTextW(g_val, L"");

    JVal* jr = new JVal();
    if (!jsonParse(json, *jr) || jr->type != JVal::OBJ) {
        delete jr;
        SetWindowTextW(g_lblSummary, cb::utf8ToWide("Failed to parse analysis for " + g_path).c_str());
        return;
    }
    g_root = jr;
    populateTree(g_tree, *g_root);
    setSummary(*g_root);

    size_t slash = g_path.find_last_of("/\\");
    std::string name = slash == std::string::npos ? g_path : g_path.substr(slash + 1);
    SetWindowTextW(g_hwnd, cb::utf8ToWide(name + " - CodeBreak").c_str());
}

static void openFileDialog() {
    wchar_t fileBuf[4096];
    fileBuf[0] = 0;
    OPENFILENAMEW ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"All files\0*.*\0Executables (PE)\0*.exe;*.dll;*.sys\0Android\0*.apk;*.jar;*.zip\0ELF\0*.so;*.bin;*.o\0Office (OLE2)\0*.doc;*.xls;*.ppt;*.msi\0Signatures\0*.p7;*.p7b\0\0";
    ofn.lpstrFile = fileBuf;
    ofn.nMaxFile = 4096;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER | OFN_HIDEREADONLY;
    if (GetOpenFileNameW(&ofn)) loadFile(wideToUtf8(fileBuf));
}

static void ensureControls(HWND hwnd) {
    if (g_btnOpen) return;
    HINSTANCE hInst = GetModuleHandleW(nullptr);

    g_btnOpen = CreateWindowW(L"BUTTON", L"Open File...",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)ID_BTN_OPEN, hInst, nullptr);
    g_lblSummary = CreateWindowW(L"STATIC", L"Drop a file here or press Open File...",
        WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP,
        0, 0, 0, 0, hwnd, nullptr, hInst, nullptr);
    g_lblFind = CreateWindowW(L"STATIC", L"Find:",
        WS_CHILD | WS_VISIBLE,
        0, 0, 0, 0, hwnd, nullptr, hInst, nullptr);
    g_editFind = CreateWindowW(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)ID_EDIT_FIND, hInst, nullptr);
    g_tree = CreateWindowW(WC_TREEVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS | WS_BORDER,
        0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)ID_TREE, hInst, nullptr);
    g_val = CreateWindowW(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL | WS_HSCROLL | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_BORDER,
        0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)ID_VAL, hInst, nullptr);

    SetWindowFont(g_btnOpen, g_fontUI, TRUE);
    SetWindowFont(g_lblSummary, g_fontUI, TRUE);
    SetWindowFont(g_lblFind, g_fontUI, TRUE);
    SetWindowFont(g_editFind, g_fontUI, TRUE);
    SetWindowFont(g_tree, g_fontUI, TRUE);
    SetWindowFont(g_val, g_fontMono, TRUE);
    SendMessageW(g_tree, TVM_SETEXTENDEDSTYLE, TVS_EX_DOUBLEBUFFER, TVS_EX_DOUBLEBUFFER);
}

static void layout(HWND hwnd) {
    RECT rc;
    GetClientRect(hwnd, &rc);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    if (w < 40 || h < 40) return;
    const int pad = 8;
    const int btnW = 96;
    const int btnH = 26;
    const int row1Y = 8;
    const int findLabelW = 44;
    const int findY = 40;
    const int findH = 22;
    const int bodyY = findY + findH + 8;

    if (g_btnOpen) SetWindowPos(g_btnOpen, nullptr, pad, row1Y, btnW, btnH, SWP_NOZORDER);
    if (g_lblSummary) SetWindowPos(g_lblSummary, nullptr, pad + btnW + 8, row1Y + 5, w - pad - btnW - 8 - pad, btnH, SWP_NOZORDER);
    if (g_lblFind) SetWindowPos(g_lblFind, nullptr, pad, findY + 2, findLabelW, findH, SWP_NOZORDER);
    if (g_editFind) SetWindowPos(g_editFind, nullptr, pad + findLabelW, findY, w - pad - findLabelW - pad, findH, SWP_NOZORDER);

    int treeW = w * 46 / 100;
    if (g_tree) SetWindowPos(g_tree, nullptr, pad, bodyY, treeW, h - bodyY - pad, SWP_NOZORDER);
    if (g_val) SetWindowPos(g_val, nullptr, pad + treeW + 6, bodyY, w - pad - treeW - 6 - pad, h - bodyY - pad, SWP_NOZORDER);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        g_hwnd = hwnd;
        DragAcceptFiles(hwnd, TRUE);
        ensureControls(hwnd);
        layout(hwnd);
        return 0;
    case WM_SIZE:
        layout(hwnd);
        return 0;
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize.x = 720;
        mmi->ptMinTrackSize.y = 460;
        return 0;
    }
    case WM_APP_RESULT:
        if (lParam) applyResult((ResultMsg*)lParam);
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == ID_BTN_OPEN) openFileDialog();
        else if (LOWORD(wParam) == ID_EDIT_FIND && HIWORD(wParam) == EN_CHANGE && g_root)
            populateTree(g_tree, *g_root);
        return 0;
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
    case WM_DESTROY:
        if (g_root) { delete g_root; g_root = nullptr; }
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR cmdline, int nCmdShow) {
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    g_fontUI = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    g_fontMono = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             DEFAULT_PITCH | FF_MODERN, L"Consolas");

    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(102));
    wc.hIconSm = wc.hIcon;
    wc.lpszClassName = WND_CLASS;
    RegisterClassExW(&wc);

    RECT wr = { 0, 0, 1180, 760 };
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
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (g_fontUI) DeleteObject(g_fontUI);
    if (g_fontMono) DeleteObject(g_fontMono);
    return (int)msg.wParam;
}
