#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
CLI = os.environ.get("CB_CLI", os.path.join(ROOT, "build-cli", "codebreak-cli"))
FIX = os.path.join(HERE, "fixtures")

passed = 0
failed = 0


def analyze(path):
    r = subprocess.run([CLI, path], capture_output=True)
    if r.returncode != 0:
        raise RuntimeError("cli failed: " + r.stderr.decode()[:200])
    return json.loads(r.stdout)


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print("FAIL: " + name + (" - " + detail if detail else ""))


def main():
    pe = analyze(os.path.join(FIX, "fixture_pe.exe"))
    check("pe format", pe["format"]["label"] == "PE32+ executable (64-bit)")
    check("pe machine", pe["pe"]["machine"] == "x86-64")
    check("pe checksum", pe["pe"]["checksumValid"] is True)
    check("pe subsystem", pe["pe"]["subsystem"] == "Windows Console")
    check("pe entry section", pe["pe"]["entryPointSection"] == ".text")
    rich = {(r["productId"], r["build"], r["count"]) for r in pe["pe"]["rich"]}
    check("pe rich header", (125, 5776, 42) in rich and (101, 2570, 3) in rich and (129, 10000, 11) in rich, str(rich))
    imp = {i["dll"]: [f["name"] for f in i["functions"]] for i in pe["pe"]["imports"]}
    check("pe imports kernel32", imp.get("KERNEL32.DLL") == ["CreateFileW", "ReadFile", "#17"], str(imp))
    check("pe imports user32", imp.get("USER32.dll") == ["MessageBoxA"])
    exp = pe["pe"]["exports"]["symbols"]
    check("pe exports", {e["name"]: e["ordinal"] for e in exp} == {"TestFunction": 1, "AnotherFunc": 3}, str(exp))
    dbg = pe["pe"]["debug"]["entries"][0]
    check("pe pdb path", dbg["pdb"] == "C:\\projects\\fixture\\build\\fixture.pdb")
    check("pe pdb guid", dbg["pdbGuid"] == "1a2b3c4d-1234-5678-aabb-ccddee010203")
    check("pe pdb age", dbg["pdbAge"] == 7)
    check("pe tls callback", pe["pe"]["tls"]["callbacks"] == ["0x140001180"])
    check("pe signed", pe["pe"]["security"]["signed"] is True)
    cert = pe["pe"]["security"]["certificates"][0]
    check("pe cert type", cert["type"] == "PKCS #7 Signed Data" and cert["length"] == 104)
    vi = pe["pe"]["resources"]["versionInfo"]
    check("pe version fixed", vi["fileVersion"] == "1.2.3.4")
    vs = {s["key"]: s["value"] for s in vi["strings"]}
    check("pe version strings", vs.get("CompanyName") == "CodeBreak Test Labs" and vs.get("LegalCopyright") == "(c) CodeBreak Test Labs" and len(vs) == 8, str(len(vs)))
    check("pe manifest", pe["pe"]["resources"]["manifest"].startswith("<?xml"))
    check("pe hashes", pe["hashes"]["md5"] == hashlib.md5(open(os.path.join(FIX, "fixture_pe.exe"), "rb").read()).hexdigest())

    apk = analyze(os.path.join(FIX, "fixture_app.apk"))
    check("apk format", apk["format"]["label"] == "Android package (APK)")
    m = apk["apk"]["manifest"]
    check("apk package", m["package"] == "com.example.fixture")
    check("apk version", m["versionCode"] == "5" and m["versionName"] == "1.0.3")
    check("apk sdk", m["minSdk"] == "21" and m["targetSdk"] == "33")
    check("apk perms", set(m["permissions"]) == {"android.permission.INTERNET", "android.permission.CAMERA"})
    check("apk main activity", m["mainActivity"] == "com.example.fixture.MainActivity")
    check("apk debuggable", m["debuggable"] is True)
    check("apk cleartext", m["usesCleartextTraffic"] is True)
    comps = m["components"]
    check("apk activity exported", comps["activity"][0]["exported"] is True)
    check("apk service not exported", comps["service"][0]["exported"] is False)
    dex = apk["apk"]["dex"][0]
    check("dex checksum", dex["checksumOk"] is True)
    check("dex sha1", dex["signatureOk"] is True)
    check("dex counts", dex["stringCount"] == 16 and dex["classCount"] == 3 and dex["methodCount"] == 5)
    cls = {c["name"]: c for c in dex["classes"]}
    check("dex class", cls["Lcom/example/fixture/MainActivity;"]["super"] == "Landroid/app/Activity;")
    check("dex source", cls["Lcom/example/fixture/MainActivity;"]["source"] == "MainActivity.java")
    check("apk signing v2", apk["apk"]["signing"]["v2"] is True and apk["apk"]["signing"]["v1Jarsigned"] is True)
    check("apk libs", set(apk["apk"]["nativeLibs"].keys()) == {"arm64-v8a", "x86_64"})
    sev = {i["title"] for i in apk["indicators"]}
    check("apk indicators", "Application is debuggable" in sev and "APK is signed" not in sev)

    z = analyze(os.path.join(FIX, "fixture_plain.zip"))
    check("zip format", z["format"]["label"] == "ZIP archive")
    check("zip entries", z["zip"]["entryCount"] == 4)
    names = {e["name"] for e in z["zip"]["entries"]}
    check("zip names", "src/main.c" in names and "readme.txt" in names)

    jf = analyze(os.path.join(FIX, "FixtureClass.class"))
    check("java format", jf["format"]["label"] == "Java class file")
    jc = jf["javaclass"]
    check("java class name", jc["className"] == "com/fixture/FixtureClass")
    check("java version", jc["javaVersion"] == "Java 8")
    check("java methods", jc["methods"][0]["name"] == "<init>")

    ef = analyze(os.path.join(FIX, "fixture_elf64"))
    check("elf format", ef["format"]["label"] == "ELF executable/library")
    e = ef["elf"]
    check("elf machine", e["machine"] == "x86-64")
    secnames = [s["name"] for s in e["sections"]]
    check("elf sections", ".text" in secnames and ".dynsym" in secnames and ".rodata" in secnames)
    check("elf interp", any(p.get("interpreter", "").startswith("/lib64/ld-linux") for p in e["programHeaders"]))

    mo = analyze(os.path.join(FIX, "fixture_macho64.bin"))
    check("macho format", mo["format"]["label"] == "Mach-O binary")
    cmds = [c["name"] for c in mo["macho"]["loadCommands"]]
    check("macho commands", cmds == ["LC_SEGMENT_64", "LC_MAIN", "LC_LOAD_DYLIB"], str(cmds))

    r = subprocess.run([CLI, os.path.join(FIX, "fixture_pe.exe"), "--strings", "KERNEL32", "--count", "10"], capture_output=True)
    st = json.loads(r.stdout)
    check("strings filter", st["total"] == 1 and st["items"][0]["text"] == "KERNEL32.DLL", str(st))

    r = subprocess.run([CLI, os.path.join(FIX, "fixture_pe.exe"), "--hex", "0", "--hex-len", "16"], capture_output=True)
    hx = json.loads(r.stdout)
    check("hex dump", hx["bytes"][:2] == [0x4D, 0x5A])

    gz = analyze(os.path.join(FIX, "fixture_data.gz"))
    check("gzip format", gz["format"]["label"] == "GZIP compressed file")
    check("gzip filename", gz["gzip"]["filename"] == "fixture_payload.bin")
    check("gzip crc", gz["gzip"]["crc32"] is not None)
    check("gzip has risk", isinstance(gz["risk"], dict))

    ta = analyze(os.path.join(FIX, "fixture_bundle.tar"))
    check("tar format", ta["format"]["label"] == "TAR archive")
    names = {e["name"] for e in ta["tar"]["entries"]}
    check("tar entries", "src/lib.c" in names and "scripts/run.sh" in names)

    pd = analyze(os.path.join(FIX, "fixture_doc.pdf"))
    check("pdf format", pd["format"]["label"] == "PDF document")
    check("pdf version", pd["pdf"]["version"].startswith("1.7"))
    check("pdf objects", pd["pdf"]["objectCount"] >= 3 and pd["pdf"]["streamCount"] >= 1)

    ol = analyze(os.path.join(FIX, "fixture_macro.doc"))
    check("ole format", ol["format"]["label"] == "Compound File (OLE2)")
    ole = ol["ole"]
    check("ole kind word", ole["kind"].startswith("Microsoft Word"))
    names = [e["name"] for e in ole["entries"]]
    check("ole vba tree", "VBA" in names and "_VBA_PROJECT" in names and "ThisDocument" in names)
    check("ole macro indicator", any("VBA macro" in i["title"] for i in ol["indicators"]))
    check("ole has risk", "risk" in ol)

    def openssl_thumbprint(p7):
        c = subprocess.run(["openssl", "pkcs7", "-inform", "DER", "-in", p7, "-print_certs"],
                           capture_output=True)
        if c.returncode != 0:
            return None
        fp = subprocess.run(["openssl", "x509", "-fingerprint", "-sha1", "-noout"],
                            input=c.stdout, capture_output=True)
        if fp.returncode != 0:
            return None
        s = fp.stdout.decode().lower()
        m = re.search(r"=([0-9a-f]{40})", s.replace(":", ""))
        return m.group(1) if m else None

    expected_tp = openssl_thumbprint(os.path.join(FIX, "fixture_signature.p7"))
    ps = analyze(os.path.join(FIX, "fixture_signature.p7"))
    check("pkcs7 format", ps["format"]["label"].startswith("PKCS #7"))
    sg = ps["pkcs7"]["signers"][0]
    check("pkcs7 signer", "CodeBreak" in sg["subject"] and "CodeBreak" in sg["issuer"])
    check("pkcs7 thumbprint len", len(sg["thumbprintSha1"]) == 40)
    if expected_tp:
        check("pkcs7 thumbprint matches openssl", sg["thumbprintSha1"].lower() == expected_tp)

    sx = analyze(os.path.join(FIX, "fixture_signed.exe"))
    sc = sx["pe"]["security"]
    check("pe signed", sc["signed"] is True)
    check("pe authenticode signer", "CodeBreak Fixture Signer" in sc["signer"]["subject"])
    if expected_tp:
        check("pe signer thumbprint", sc["signer"]["thumbprintSha1"].lower() == expected_tp)
    check("pe signer indicator", any("Authenticode signer" in i["title"] for i in sx["indicators"]))

    r = subprocess.run([CLI, "--compare", os.path.join(FIX, "fixture_pe.exe"), os.path.join(FIX, "fixture_pe.exe")], capture_output=True)
    cmp2 = json.loads(r.stdout)
    check("compare identical", cmp2["identical"] is True and cmp2["sha256Equal"] is True)

    r = subprocess.run([CLI, "--hash", os.path.join(FIX, "fixture_pe.exe")], capture_output=True)
    hsh = json.loads(r.stdout)
    check("hash mode", hsh["hashes"]["sha256"] == pe["hashes"]["sha256"])

    check("apk risk present", isinstance(apk["risk"], dict) and "score" in apk["risk"])
    check("apk risk level", apk["risk"]["level"] in ("clean", "low", "medium", "high", "critical"))
    sevlev = {i["title"] for i in apk["indicators"]}
    check("risk incorporates findings", apk["risk"]["score"] >= 10 if "Application is debuggable" in sevlev else True)

    r = subprocess.run([CLI, os.path.join(FIX, "fixture_pe.exe"), "--risk"], capture_output=True)
    risk = json.loads(r.stdout)
    check("risk-only mode", "risk" in risk and "score" in risk["risk"])

    r = subprocess.run([CLI, os.path.join(FIX, "fixture_pe.exe"), "--behavior"], capture_output=True)
    beh = json.loads(r.stdout)
    check("behavior sections", set(beh.keys()) == {"network", "fileSystem", "process", "persistence"})
    check("behavior file path", any("fixture.pdb" in p for p in beh["fileSystem"]["paths"]))
    check("behavior file apis", "CreateFileW" in beh["fileSystem"]["apis"] and "ReadFile" in beh["fileSystem"]["apis"])

    r = subprocess.run([CLI, os.path.join(FIX, "fixture_pe.exe"), "--asm"], capture_output=True)
    asm = json.loads(r.stdout)["code"]
    texts = [ln["text"] for ln in asm["lines"]]
    check("asm section", asm["section"] == ".text")
    check("asm first insn", texts[0] == "mov qword ptr [rsp+8], rbx")
    check("asm push/ret", "push rdi" in texts and "ret" in texts)
    check("asm base", asm["base"] == "0x140001000")
    check("asm json fields", all(set(ln) >= {"addr", "bytes", "text"} for ln in asm["lines"]))

    r = subprocess.run([CLI, os.path.join(FIX, "fixture_elf64"), "--asm"], capture_output=True)
    asm2 = json.loads(r.stdout)["code"]
    t2 = [ln["text"] for ln in asm2["lines"]]
    check("elf asm nonempty", len(t2) > 3)
    check("elf asm mnemonics", any(x.split()[0] in ("mov", "push", "ret", "call", "jmp", "je", "jne") for x in t2))

    r = subprocess.run([CLI, os.path.join(FIX, "fixture_pe.exe"), "--calls"], capture_output=True)
    cg = json.loads(r.stdout)
    check("graph pe keys", set(cg) == {"format", "section", "entry", "directCalls", "indirectCalls", "functions"})
    check("graph pe entry", cg["entry"] == "0x140001000" and cg["section"] == ".text")
    check("graph pe functions", len(cg["functions"]) >= 1 and cg["functions"][0]["name"] == "start_140001000")
    check("graph pe entry flag", cg["functions"][0]["entry"] is True and all("callers" in f and "calls" in f for f in cg["functions"]))

    r = subprocess.run([CLI, os.path.join(FIX, "fixture_elf64"), "--calls"], capture_output=True)
    eg = json.loads(r.stdout)
    check("graph elf functions", len(eg["functions"]) >= 4)
    check("graph elf has callers", any(f["callerCount"] >= 1 for f in eg["functions"]))
    check("graph elf has edges", any(len(f["calls"]) >= 1 for f in eg["functions"]))
    start = next(f for f in eg["functions"] if f["entry"])
    check("graph elf entry flag", start["name"].startswith("start_"))

    r = subprocess.run([CLI, os.path.join(FIX, "fixture_elf64"), "--calls", "--dot"], capture_output=True)
    dot = r.stdout.decode()
    check("graph dot", dot.startswith("digraph callgraph") and "->" in dot)

    batchdir = FIX
    r = subprocess.run([CLI, "--batch", batchdir], capture_output=True)
    bd = json.loads(r.stdout)
    check("batch runs", bd["meta"]["fileCount"] == len(os.listdir(FIX)) and len(bd["items"]) >= 5)
    check("batch item risk", all("riskScore" in i and "riskLevel" in i for i in bd["items"]))

    print(f"{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
