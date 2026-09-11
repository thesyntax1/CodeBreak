#include "zipfmt.h"
#include "jsonw.h"
#include "util.h"
#include "axml.h"
#include "dex.h"

#include <cstring>

namespace cb {

bool looksLikeZip(const uint8_t* d, size_t n) {
    if (n < 4) return false;
    uint32_t sig = (uint32_t)d[0] | ((uint32_t)d[1] << 8) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
    return sig == 0x04034B50 || sig == 0x06054B50 || sig == 0x02014B50;
}

bool ZipData::entryData(size_t index, std::vector<uint8_t>& out, std::string& errOut) const {
    if (index >= entries.size()) { errOut = "bad entry index"; return false; }
    const ZipEntryInfo& e = entries[index];
    if (e.isDir || !data) { errOut = "no data"; return false; }
    Rd lr(data, size, (size_t)e.localOffset);
    uint32_t sig = lr.u32();
    if (sig != 0x04034B50) { errOut = "bad local header"; return false; }
    lr.u16(); lr.u16(); lr.u16(); lr.u16(); lr.u16();
    lr.u32(); lr.u32(); lr.u32();
    uint16_t nameLen = lr.u16();
    uint16_t extraLen = lr.u16();
    lr.skip(nameLen + extraLen);
    if (!lr.ok()) { errOut = "truncated local header"; return false; }
    const uint8_t* p = lr.take((size_t)e.compSize);
    if (!p) { errOut = "truncated entry data"; return false; }
    if (e.method == 0) {
        out.assign(p, p + e.compSize);
        return true;
    }
    if (e.method == 8) {
        std::string err;
        if (!inflateZlibOrRaw(p, e.compSize, out, false, (size_t)512 << 20, err)) { errOut = err; return false; }
        return true;
    }
    errOut = "unsupported compression method " + decU(e.method);
    return false;
}

static const char* zipMethodName(uint16_t m) {
    switch (m) {
    case 0: return "Store";
    case 1: return "Shrink";
    case 8: return "Deflate";
    case 9: return "Deflate64";
    case 12: return "BZip2";
    case 14: return "LZMA";
    case 51: return "WavPack";
    case 93: return "Zstandard";
    default: return nullptr;
    }
}

ZipData zipParse(const uint8_t* d, size_t n, Builder& b, IndCollector& inds) {
    ZipData z;
    z.data = d;
    z.size = n;

    int64_t eocd = -1;
    if (n >= 22) {
        // Scan backwards for the EOCD signature. i is unsigned, so the loop
        // must stop at scanStart explicitly: "i--" from 0 wraps to SIZE_MAX
        // and the next iteration reads a byte before the buffer.
        size_t scanStart = n > 65557 + 22 ? n - (65557 + 22) : 0;
        for (size_t i = n - 22;; i--) {
            if (d[i] == 'P' && d[i + 1] == 'K' && d[i + 2] == 5 && d[i + 3] == 6) { eocd = (int64_t)i; break; }
            if (i == scanStart) break;
        }
    }
    if (eocd < 0) {
        b.beginObj();
        b.kv("error", "end of central directory not found");
        b.endObj();
        return z;
    }
    z.eocdOffset = (uint64_t)eocd;
    Rd er(d, n, (size_t)eocd + 4);
    er.u16(); er.u16();
    uint16_t entriesDisk = er.u16();
    uint16_t entriesTotal16 = er.u16();
    uint32_t cdSize32 = er.u32();
    uint32_t cdOff32 = er.u32();
    uint16_t commentLen = er.u16();
    uint64_t entriesTotal = entriesTotal16;
    uint64_t cdSize = cdSize32;
    uint64_t cdOff = cdOff32;
    if (commentLen && (size_t)eocd + 22 + commentLen <= n)
        z.comment = utf8Sanitize(d + eocd + 22, commentLen);
    if (er.err) { b.beginObj(); b.kv("error", "truncated EOCD"); b.endObj(); return z; }

    if (entriesTotal16 == 0xFFFF || cdOff32 == 0xFFFFFFFF || cdSize32 == 0xFFFFFFFF || entriesDisk == 0xFFFF) {
        int64_t loc = eocd - 20;
        if (loc >= 0) {
            Rd lr(d, n, (size_t)loc);
            if (lr.u32() == 0x07064B50) {
                lr.u32();
                uint64_t z64off = lr.u64();
                uint32_t totalDisks = lr.u32();
                (void)totalDisks;
                if (z64off + 56 <= n) {
                    Rd zr(d, n, (size_t)z64off);
                    if (zr.u32() == 0x06064B50) {
                        zr.u16(); zr.u16(); zr.u32(); zr.u32(); zr.u32(); zr.u32();
                        zr.u64(); zr.u64();
                        uint64_t entriesDisk64 = zr.u64();
                        uint64_t entriesTotal64 = zr.u64();
                        cdSize = zr.u64();
                        cdOff = zr.u64();
                        entriesTotal = entriesTotal64;
                        z.zip64 = true;
                        (void)entriesDisk64;
                    }
                }
            }
        }
    }

    z.cdOffset = cdOff;
    z.cdSize = cdSize;

    if (cdOff + cdSize > n) {
        b.beginObj();
        b.kv("error", "central directory out of bounds (file may be truncated)");
        b.endObj();
        return z;
    }

    if (cdOff >= 32) {
        const uint8_t* mp = d + cdOff - 16;
        if (memcmp(mp, "APK Sig Block 42", 16) == 0) {
            Rd br(d, n, cdOff - 24);
            uint64_t size2 = br.u64();
            uint64_t start = cdOff - 8 - size2;
            Rd br2(d, n, (size_t)start);
            uint64_t size1 = br2.u64();
            if (size1 == size2 && start + size1 + 8 == cdOff) {
                size_t cur = (size_t)start + 8;
                size_t end = (size_t)cdOff - 24;
                while (cur + 8 <= end) {
                    Rd pr(d, n, cur);
                    uint64_t plen = pr.u64();
                    if (plen < 8 || cur + plen > end) break;
                    uint64_t pid = pr.u64();
                    const char* nm = nullptr;
                    if (pid == 0x7109871aull) { nm = "APK Signature Scheme v2"; z.apkV2 = true; }
                    else if (pid == 0xf05368c0ull) { nm = "APK Signature Scheme v3"; z.apkV3 = true; }
                    else if (pid == 0x1b93ad61ull) { nm = "APK Signature Scheme v3.1"; z.apkV31 = true; }
                    else if (pid == 0x42726577ull) nm = "Verity padding";
                    else if (pid == 0x2146444eull) nm = "Dependency info";
                    else if (pid == 0x50414b30ull) nm = "Source stamp v2";
                    z.signingBlocks.push_back({ pid, nm ? nm : "block 0x" + hexU(pid) });
                    cur += (size_t)plen;
                }
            }
        }
    }

    Rd cr(d, n, (size_t)cdOff);
    uint64_t readCount = entriesTotal;
    if (readCount > 200000) { readCount = 200000; z.truncated = true; }
    z.entries.reserve((size_t)readCount);
    for (uint64_t i = 0; i < readCount && cr.ok(); i++) {
        uint32_t sig = cr.u32();
        if (sig != 0x02014B50) { break; }
        cr.u16(); cr.u16();
        cr.u16();
        uint16_t method = cr.u16();
        cr.u16(); cr.u16();
        uint32_t crcv = cr.u32();
        uint32_t comp32 = cr.u32();
        uint32_t size32 = cr.u32();
        uint16_t nameLen = cr.u16();
        uint16_t extraLen = cr.u16();
        uint16_t commentLen2 = cr.u16();
        cr.u16(); cr.u16();
        cr.u32();
        uint32_t lho = cr.u32();
        const uint8_t* nm = cr.take(nameLen);
        if (!nm || cr.err) break;
        ZipEntryInfo e;
        e.name = utf8Sanitize(nm, nameLen);
        e.method = method;
        e.compSize = comp32;
        e.size = size32;
        e.crc32 = crcv;
        e.localOffset = lho;
        e.isDir = !e.name.empty() && e.name.back() == '/';
        if (e.name.rfind("META-INF/", 0) == 0) {
            std::string low = toLower(e.name);
            if (iendsWith(low, ".rsa") || iendsWith(low, ".dsa") || iendsWith(low, ".ec")) z.apkV1 = true;
        }
        if (comp32 == 0xFFFFFFFF || size32 == 0xFFFFFFFF || lho == 0xFFFFFFFF) {
            const uint8_t* ex = cr.take(extraLen);
            if (ex && extraLen >= 20) {
                Rd xr(ex, extraLen);
                uint16_t hid = xr.u16();
                xr.u16();
                if (hid == 0x0001) {
                    uint64_t uh = xr.u64();
                    uint64_t uc = xr.u64();
                    uint64_t us = xr.u64();
                    if (uh == 0xFFFFFFFFull) uh = 0;
                    if (uc == 0xFFFFFFFFull) uc = 0;
                    if (us == 0xFFFFFFFFull) us = 0;
                    (void)uh;
                    e.compSize = uc ? uc : e.compSize;
                    e.size = us ? us : e.size;
                }
            }
        } else {
            cr.skip(extraLen);
        }
        cr.skip(commentLen2);
        if (cr.err) break;
        z.entries.push_back(e);
    }

    bool hasManifest = false, hasDex = false, hasArsc = false;
    std::string firstEntry;
    for (auto& e : z.entries) {
        if (e.name == "AndroidManifest.xml") hasManifest = true;
        if (e.name.rfind("classes", 0) == 0 && iendsWith(e.name, ".dex")) hasDex = true;
        if (e.name == "resources.arsc") hasArsc = true;
        if (firstEntry.empty()) firstEntry = e.name;
    }
    z.isApk = hasManifest && (hasDex || hasArsc);
    z.isEpub = firstEntry == "mimetype" && z.entries.size() > 1;
    if (!z.isApk) {
        for (auto& e : z.entries) {
            if (e.name == "META-INF/MANIFEST.MF") { z.isJar = true; break; }
        }
    }
    for (auto& e : z.entries) {
        if (e.name.rfind("Payload/", 0) == 0 && iendsWith(e.name, ".app/Info.plist")) { z.isIpa = true; break; }
    }

    b.beginObj();
    b.kv("entryCount", entriesTotal);
    b.kv("zip64", z.zip64);
    if (!z.comment.empty()) b.kv("comment", z.comment);
    b.kv("apk", z.isApk);
    b.kv("jar", z.isJar);
    if (z.isEpub) b.kv("epub", true);
    if (z.isIpa) b.kv("ipa", true);

    b.arr("entries");
    size_t cap = z.entries.size() < 20000 ? z.entries.size() : 20000;
    uint64_t totalComp = 0, totalUncomp = 0;
    uint64_t methodCounts[100] = { 0 };
    for (size_t i = 0; i < z.entries.size(); i++) {
        auto& e = z.entries[i];
        totalComp += e.compSize;
        totalUncomp += e.size;
        if (e.method < 100) methodCounts[e.method]++;
        if (i < cap) {
            const char* mn = zipMethodName(e.method);
            b.beginObj();
            b.kv("name", e.name);
            b.kv("method", (uint64_t)e.method);
            b.kv("methodName", mn ? mn : "unknown");
            b.kv("compSize", e.compSize);
            b.kv("size", e.size);
            if (e.size) {
                char rb[32];
                snprintf(rb, sizeof(rb), "%.1f%%", 100.0 * (double)e.compSize / (double)e.size);
                b.kv("ratio", rb);
            }
            b.kvHex("crc32", e.crc32, 8);
            b.kv("offset", e.localOffset);
            b.kv("dir", e.isDir);
            b.endObj();
        }
    }
    b.endArr();
    b.kv("entriesTruncated", z.truncated || z.entries.size() < entriesTotal);
    if (totalUncomp) b.kv("compressionOverall", (int)(100.0 * (double)totalComp / (double)totalUncomp));

    b.arr("methodStats");
    static const uint16_t known[] = { 0, 1, 8, 9, 12, 14, 93 };
    for (uint16_t m : known) {
        if (!methodCounts[m]) continue;
        const char* mn = zipMethodName(m);
        b.beginObj();
        b.kv("method", (uint64_t)m);
        b.kv("name", mn ? mn : "unknown");
        b.kv("count", methodCounts[m]);
        b.endObj();
    }
    b.endArr();

    if (!z.signingBlocks.empty()) {
        b.arr("signingBlocks");
        for (auto& sb : z.signingBlocks) {
            b.beginObj();
            b.kvHex("id", sb.first, 16);
            b.kv("name", sb.second);
            b.endObj();
        }
        b.endArr();
    }

    b.endObj();
    return z;
}

static const char* dangerousPermissions[] = {
    "android.permission.READ_CONTACTS","android.permission.WRITE_CONTACTS","android.permission.READ_CALENDAR",
    "android.permission.CAMERA","android.permission.ACCESS_FINE_LOCATION","android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO","android.permission.READ_PHONE_STATE","android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG","android.permission.WRITE_CALL_LOG","android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS","android.permission.READ_SMS","android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE","android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES","android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.READ_SMS","android.permission.BODY_SENSORS","android.permission.GET_ACCOUNTS",
    "android.permission.MANAGE_EXTERNAL_STORAGE","android.permission.QUERY_ALL_PACKAGES",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS","android.permission.PACKAGE_USAGE_STATS"
};

void apkParse(ZipData& z, Builder& b, IndCollector& inds) {
    b.beginObj();

    size_t manifestIdx = (size_t)-1;
    std::vector<size_t> dexIdx;
    std::vector<std::pair<std::string, std::vector<std::string>>> libs;
    std::vector<std::string> assets;
    std::vector<std::string> certFiles;
    bool hasArsc = false;
    for (size_t i = 0; i < z.entries.size(); i++) {
        auto& e = z.entries[i];
        if (e.name == "AndroidManifest.xml") manifestIdx = i;
        else if (e.name.rfind("classes", 0) == 0 && iendsWith(e.name, ".dex")) dexIdx.push_back(i);
        else if (e.name == "resources.arsc") hasArsc = true;
        else if (e.name.rfind("lib/", 0) == 0) {
            std::string rest = e.name.substr(4);
            size_t slash = rest.find('/');
            if (slash != std::string::npos) {
                std::string abi = rest.substr(0, slash);
                bool found = false;
                for (auto& l : libs) if (l.first == abi) { l.second.push_back(e.name); found = true; break; }
                if (!found) libs.push_back({ abi, { e.name } });
            }
        } else if (e.name.rfind("assets/", 0) == 0 && !e.isDir) assets.push_back(e.name);
        if (e.name.rfind("META-INF/", 0) == 0) {
            std::string low = toLower(e.name);
            if (iendsWith(low, ".rsa") || iendsWith(low, ".dsa") || iendsWith(low, ".ec")) certFiles.push_back(e.name);
        }
    }

    std::string manifestErr;
    bool manifestOk = false;
    AxmlNode root;
    if (manifestIdx != (size_t)-1) {
        std::vector<uint8_t> md;
        std::string err;
        if (z.entryData(manifestIdx, md, err)) {
            manifestOk = axmlParse(md.data(), md.size(), root, manifestErr);
            if (!manifestOk) inds.add(0, "Manifest could not be parsed", manifestErr);
        } else {
            inds.add(1, "Manifest could not be extracted", err);
        }
    } else {
        inds.add(1, "No AndroidManifest.xml entry", "APK classification relied on other entries");
    }

    b.obj("manifest");
    b.kv("parsed", manifestOk);
    if (manifestOk) {
        if (root.tag == "manifest") {
            auto pkg = root.find("package");
            if (pkg) b.kv("package", pkg->value);
            auto vc = root.find("android:versionCode");
            if (vc) { b.kv("versionCode", vc->value); }
            auto vn = root.find("android:versionName");
            if (vn) b.kv("versionName", vn->value);
            auto plat = root.find("platformBuildVersionCode");
            if (plat) b.kv("platformBuildVersionCode", plat->value);
        }
        std::vector<std::string> permissions, features, actions, categories;
        struct Comp { std::string kind, name; bool exported; bool hasFilter; };
        std::vector<Comp> comps;
        std::string mainActivity;
        std::string applicationLabel;
        bool debuggable = false, allowBackup = true, cleartext = false;
        bool hasAllowBackupAttr = false;
        for (auto& c1 : root.children) {
            if (c1.tag == "uses-sdk") {
                auto mn = c1.find("android:minSdkVersion");
                auto tg = c1.find("android:targetSdkVersion");
                if (mn) b.kv("minSdk", mn->value);
                if (tg) b.kv("targetSdk", tg->value);
            } else if (c1.tag == "uses-permission" || c1.tag == "uses-permission-sdk-23" || c1.tag == "permission") {
                auto nm = c1.find("android:name");
                if (nm && nm->value.rfind("android.permission.", 0) == 0) permissions.push_back(nm->value);
            } else if (c1.tag == "uses-feature") {
                auto nm = c1.find("android:name");
                if (nm) {
                    auto req = c1.find("android:required");
                    features.push_back(nm->value + (req && req->value == "false" ? " (optional)" : ""));
                }
            } else if (c1.tag == "application") {
                auto lbl = c1.find("android:label");
                if (lbl) applicationLabel = lbl->value;
                auto dbg = c1.find("android:debuggable");
                debuggable = dbg && dbg->value == "true";
                auto ab = c1.find("android:allowBackup");
                if (ab) { hasAllowBackupAttr = true; allowBackup = ab->value != "false"; }
                auto ct = c1.find("android:usesCleartextTraffic");
                cleartext = ct && ct->value == "true";
                auto theme = c1.find("android:theme");
                if (theme) b.kv("theme", theme->value);
                for (auto& c2 : c1.children) {
                    if (c2.tag == "activity" || c2.tag == "activity-alias" || c2.tag == "service" ||
                        c2.tag == "receiver" || c2.tag == "provider") {
                        Comp comp;
                        comp.kind = c2.tag;
                        auto nm = c2.find("android:name");
                        comp.name = nm ? nm->value : "(anonymous)";
                        auto ex = c2.find("android:exported");
                        comp.hasFilter = false;
                        bool hasActionMain = false, hasCatLauncher = false;
                        for (auto& c3 : c2.children) {
                            if (c3.tag == "intent-filter") {
                                comp.hasFilter = true;
                                for (auto& c4 : c3.children) {
                                    if (c4.tag == "action") {
                                        auto an = c4.find("android:name");
                                        if (an) {
                                            actions.push_back(an->value);
                                            if (an->value == "android.intent.action.MAIN") hasActionMain = true;
                                        }
                                    } else if (c4.tag == "category") {
                                        auto cn = c4.find("android:name");
                                        if (cn) {
                                            categories.push_back(cn->value);
                                            if (cn->value == "android.intent.category.LAUNCHER") hasCatLauncher = true;
                                        }
                                    }
                                }
                            }
                        }
                        comp.exported = ex ? ex->value == "true" : comp.hasFilter;
                        if (hasActionMain && hasCatLauncher && mainActivity.empty()) mainActivity = comp.name;
                        comps.push_back(comp);
                    }
                }
            }
        }
        b.kv("applicationLabel", applicationLabel);
        b.kv("debuggable", debuggable);
        b.kv("allowBackup", allowBackup);
        b.kv("allowBackupDeclared", hasAllowBackupAttr);
        b.kv("usesCleartextTraffic", cleartext);
        b.kv("mainActivity", mainActivity);
        b.arr("permissions");
        for (auto& p : permissions) b.valStr(p);
        b.endArr();
        b.arr("dangerousPermissions");
        for (auto& p : permissions)
            for (auto dp : dangerousPermissions) if (p == dp) { b.valStr(p); break; }
        b.endArr();
        b.arr("features");
        for (auto& f : features) b.valStr(f);
        b.endArr();
        b.obj("components");
        static const char* kinds[] = { "activity","activity-alias","service","receiver","provider" };
        for (auto k : kinds) {
            std::string key(k);
            if (key == "activity-alias") key = "activityAlias";
            b.arr(key.c_str());
            for (auto& c : comps) {
                if (c.kind != k) continue;
                b.beginObj();
                b.kv("name", c.name);
                b.kv("exported", c.exported);
                b.kv("hasIntentFilter", c.hasFilter);
                b.endObj();
            }
            b.endArr();
        }
        b.endObj();
        (void)actions; (void)categories;

        int budget = 4000;
        b.key("tree");
        axmlWriteTree(root, b, 0, budget);

        if (debuggable) inds.add(2, "Application is debuggable", "android:debuggable=true allows arbitrary code injection on debug builds");
        if (allowBackup && hasAllowBackupAttr) inds.add(1, "Backup allowed", "android:allowBackup=true permits app data extraction via adb backup");
        if (cleartext) inds.add(1, "Cleartext traffic allowed", "android:usesCleartextTraffic=true");
        for (auto& p : permissions)
            for (auto dp : dangerousPermissions) if (p == dp) { inds.add(1, "Sensitive permission requested", p); break; }
        int exp = 0;
        for (auto& c : comps) if (c.exported && c.kind != "activity") exp++;
        if (exp) inds.add(1, "Exported non-activity components", std::to_string(exp) + " component(s) exportable by other apps");
    }
    b.endObj();

    b.obj("signing");
    b.kv("v1Jarsigned", z.apkV1);
    b.kv("v2", z.apkV2);
    b.kv("v3", z.apkV3);
    b.arr("certFiles");
    for (auto& c : certFiles) b.valStr(c);
    b.endArr();
    if (!z.apkV1 && !z.apkV2 && !z.apkV3) inds.add(2, "APK is not signed", "No v1 certificate entries and no APK Signing Block found");
    b.endObj();

    b.kv("resourcesArsc", hasArsc);
    b.obj("nativeLibs");
    for (auto& l : libs) {
        b.arr(l.first.c_str());
        for (auto& f : l.second) b.valStr(f);
        b.endArr();
    }
    b.endObj();
    b.kv("assetCount", (uint64_t)assets.size());

    b.arr("dex");
    for (size_t i = 0; i < dexIdx.size(); i++) {
        std::vector<uint8_t> dd;
        std::string err;
        if (z.entryData(dexIdx[i], dd, err)) {
            dexParse(dd.data(), dd.size(), z.entries[dexIdx[i]].name.c_str(), b, inds, dd.size());
        } else {
            b.beginObj();
            b.kv("name", z.entries[dexIdx[i]].name);
            b.kv("error", err);
            b.endObj();
        }
    }
    b.endArr();

    b.endObj();
}

}
