#include "x509.h"
#include "jsonw.h"
#include "util.h"
#include "hashes.h"
#include <cstring>
#include <vector>

namespace cb {

namespace {

struct Region {
    const uint8_t* p = nullptr;
    size_t n = 0;
};

class Der {
public:
    explicit Der(Region r) : p_(r.p), n_(r.n) {}
    bool err() const { return err_; }
    bool done() const { return o_ >= n_ || err_; }
    bool next(Region& val, uint8_t& tag) {
        if (o_ + 2 > n_) { err_ = true; return false; }
        tag = p_[o_++];
        uint8_t l = p_[o_++];
        size_t len = 0;
        if (l < 0x80) len = l;
        else if (l == 0x81) { if (o_ + 1 > n_) { err_ = true; return false; } len = p_[o_++]; }
        else if (l == 0x82) { if (o_ + 2 > n_) { err_ = true; return false; } len = ((size_t)p_[o_] << 8) | p_[o_ + 1]; o_ += 2; }
        else { err_ = true; return false; }
        if (len > n_ - o_) { err_ = true; return false; }
        val = { p_ + o_, len };
        o_ += len;
        return true;
    }
    bool peek(uint8_t& tag) {
        if (o_ + 2 > n_) return false;
        tag = p_[o_];
        return true;
    }
    std::string oidOf(Region r) {
        std::string s;
        if (!r.n) return s;
        uint64_t v = 0;
        std::vector<uint64_t> c;
        for (size_t i = 0; i < r.n; i++) {
            v = (v << 7) | (r.p[i] & 0x7F);
            if (!(r.p[i] & 0x80)) { c.push_back(v); v = 0; }
        }
        if (c.empty()) return s;
        uint64_t f = c[0];
        s = (f < 40) ? "0." + std::to_string(f)
                     : (f < 80) ? "1." + std::to_string(f - 40)
                                : "2." + std::to_string(f - 80);
        for (size_t i = 1; i < c.size(); i++) s += "." + std::to_string(c[i]);
        return s;
    }
    std::string asciiOf(Region r) {
        std::string s;
        for (size_t i = 0; i < r.n; i++) {
            unsigned char ch = (unsigned char)r.p[i];
            if (ch >= 0x20 && ch < 0x7F) s += (char)ch;
        }
        return s;
    }
private:
    const uint8_t* p_;
    size_t n_;
    size_t o_ = 0;
    bool err_ = false;
};

const char* oidLabel(const std::string& o) {
    if (o == "2.5.4.3") return "CN";
    if (o == "2.5.4.10") return "O";
    if (o == "2.5.4.11") return "OU";
    if (o == "2.5.4.6") return "C";
    if (o == "2.5.4.7") return "L";
    if (o == "2.5.4.8") return "ST";
    if (o == "2.5.4.5") return "serialNumber";
    if (o == "1.2.840.113549.1.9.1") return "emailAddress";
    return nullptr;
}

void parseName(Region name, std::string& out) {
    Der d(name);
    while (!d.done()) {
        Region rdn;
        uint8_t tag;
        if (!d.next(rdn, tag)) break;
        if (tag != 0x31) continue;
        Der set(rdn);
        while (!set.done()) {
            Region atv;
            uint8_t t;
            if (!set.next(atv, t) || t != 0x30) break;
            Der av(atv);
            Region oidr, valr;
            uint8_t ot, vt;
            std::string oid;
            if (av.next(oidr, ot) && ot == 0x06) oid = av.oidOf(oidr);
            if (av.next(valr, vt) && !oid.empty()) {
                std::string str = av.asciiOf(valr);
                const char* lab = oidLabel(oid);
                if (lab && !str.empty()) {
                    if (!out.empty()) out += ", ";
                    out += std::string(lab) + "=" + str;
                }
            }
        }
    }
}

std::string intSerial(Region r) {
    if (!r.n) return std::string();
    const uint8_t* p = r.p;
    size_t n = r.n;
    while (n > 1 && p[0] == 0) { p++; n--; }
    std::string s;
    bool big = n > 1;
    char buf[4];
    for (size_t i = 0; i < n; i++) {
        snprintf(buf, sizeof(buf), i ? "%02x" : (big ? "%02x" : "%x"), p[i]);
        s += buf;
    }
    return s;
}

std::string fmtTime(Region r) {
    std::string s;
    for (size_t i = 0; i < r.n && i < 15; i++) {
        unsigned char ch = (unsigned char)r.p[i];
        if (ch >= '0' && ch <= '9') s += (char)ch;
    }
    if (s.size() < 12) return s;
    // YYMMDDHHMMSSZ -> YYYY-MM-DD
    std::string year = "20" + s.substr(0, 2);
    std::string out = year + "-" + s.substr(2, 2) + "-" + s.substr(4, 2) + " " +
                      s.substr(6, 2) + ":" + s.substr(8, 2) + ":" + s.substr(10, 2) + " UTC";
    return out;
}

struct ParsedCert {
    std::string der;
    std::string subject;
    std::string issuer;
    std::string serial;
    std::string notBefore;
    std::string notAfter;
};

bool parseCertificate(Region cert, ParsedCert& pc) {
    Der c(cert);
    Region seq;
    uint8_t tag;
    if (!c.next(seq, tag) || tag != 0x30) return false;
    std::string full;
    full.push_back((char)0x30);
    size_t len = cert.n;
    if (len < 0x80) full.push_back((char)len);
    else if (len < 0x100) { full.push_back((char)0x81); full.push_back((char)len); }
    else { full.push_back((char)0x82); full.push_back((char)(len >> 8)); full.push_back((char)(len & 0xFF)); }
    full.append((const char*)cert.p, len);
    pc.der = std::move(full);
    Der body(seq);
    Region r;
    uint8_t t = 0;
    // optional [0] EXPLICIT version, then the serial INTEGER (0x02)
    if (!body.next(r, t)) return false;
    if (t == 0xA0) {
        if (!body.next(r, t) || t != 0x02) return false;
    } else if (t != 0x02) {
        return false;
    }
    pc.serial = intSerial(r);
    // signature AlgorithmIdentifier (0x30)
    if (!body.next(r, t) || t != 0x30) return false;
    // issuer Name
    if (!body.next(r, t) || t != 0x30) return false;
    parseName(r, pc.issuer);
    // validity SEQUENCE
    if (!body.next(r, t) || t != 0x30) return false;
    Der val(r);
    Region vr;
    uint8_t vt;
    if (val.next(vr, vt)) pc.notBefore = fmtTime(vr);
    if (val.next(vr, vt)) pc.notAfter = fmtTime(vr);
    // subject Name
    if (!body.next(r, t) || t != 0x30) return false;
    parseName(r, pc.subject);
    return true;
}

std::string contentTypeLabel(const std::string& oid) {
    if (oid == "1.2.840.113549.1.7.2") return "SignedData (PKCS #7 / CMS)";
    if (oid == "1.2.840.113549.1.7.1") return "Data";
    if (oid == "1.2.840.113549.1.7.6") return "EnvelopedData";
    if (oid == "1.2.840.113549.1.7.4") return "DigestedData";
    return oid;
}

} // namespace

bool parsePkcs7(const uint8_t* d, size_t n, Pkcs7Result& out) {
    out.ok = false;
    Region root { d, n };
    Der top(root);
    Region content;
    uint8_t tag;
    if (!top.next(content, tag) || tag != 0x30) { out.error = "not a DER SEQUENCE"; return false; }
    Der ci(content);
    Region oidr;
    if (!ci.next(oidr, tag) || tag != 0x06) { out.error = "missing contentType OID"; return false; }
    std::string ctOid = ci.oidOf(oidr);
    out.contentType = contentTypeLabel(ctOid);
    if (ctOid != "1.2.840.113549.1.7.2") { out.error = "not SignedData"; return false; }
    // [0] EXPLICIT SignedData
    Region sdWrap;
    if (!ci.next(sdWrap, tag) || tag != 0xA0) { out.error = "missing SignedData"; return false; }
    Der wrap(sdWrap);
    Region sd;
    if (!wrap.next(sd, tag) || tag != 0x30) { out.error = "bad SignedData structure"; return false; }
    Der s(sd);
    Region r;
    // version INTEGER
    if (!s.next(r, tag) || tag != 0x02) { out.error = "bad version"; return false; }
    // digestAlgorithms SET
    if (!s.next(r, tag) || tag != 0x31) { out.error = "bad digestAlgorithms"; return false; }
    // contentInfo
    if (!s.next(r, tag) || tag != 0x30) { out.error = "bad contentInfo"; return false; }
    std::vector<ParsedCert> certs;
    // certificates [0] IMPLICIT (optional): content is a raw list of Certificate SEQUENCEs
    if (s.peek(tag) && tag == 0xA0) {
        Region certsRegion;
        s.next(certsRegion, tag);
        Der cd(certsRegion);
        while (!cd.done()) {
            Region cr;
            if (!cd.next(cr, tag)) break;
            if (tag != 0x30) continue;
            ParsedCert pc;
            if (parseCertificate(cr, pc)) {
                certs.push_back(std::move(pc));
                out.certCount++;
            }
        }
    }
    // crls [1] IMPLICIT optional
    if (s.peek(tag) && tag == 0xA1) {
        Region tmp;
        s.next(tmp, tag);
    }
    // signerInfos SET
    std::vector<std::string> signerSerials;
    if (s.peek(tag) && tag == 0x31) {
        Region sis;
        s.next(sis, tag);
        Der set(sis);
        while (!set.done()) {
            Region si;
            if (!set.next(si, tag) || tag != 0x30) break;
            Der sio(si);
            Region r0;
            uint8_t t0;
            // version
            if (!sio.next(r0, t0) || t0 != 0x02) continue;
            // sid: SEQUENCE issuerAndSerialNumber (0x30) or [0] subjectKeyIdentifier (0x80)
            Region sid;
            if (sio.next(sid, t0) && t0 == 0x30) {
                Der sd2(sid);
                Region name, serial;
                uint8_t t2;
                if (sd2.next(name, t2) && sd2.next(serial, t2) && t2 == 0x02) {
                    std::string ser = intSerial(serial);
                    if (!ser.empty()) signerSerials.push_back(ser);
                }
            }
        }
    }
    // attribute signers: whichever cert serial appears in signerInfos
    for (ParsedCert& pc : certs) {
        bool isSigner = false;
        for (const std::string& ser : signerSerials) {
            if (!pc.serial.empty() && pc.serial == ser) { isSigner = true; break; }
        }
        if (isSigner) {
            X509Signer sg;
            sg.subject = pc.subject;
            sg.issuer = pc.issuer;
            sg.serial = pc.serial;
            sg.notBefore = pc.notBefore;
            sg.notAfter = pc.notAfter;
            sg.thumbprintSha1 = sha1Hex((const uint8_t*)pc.der.data(), pc.der.size());
            out.signers.insert(out.signers.begin(), sg);
            isSigner = true;
            // remove duplicate handled below
        } else {
            X509Signer sg;
            sg.subject = pc.subject;
            sg.issuer = pc.issuer;
            sg.serial = pc.serial;
            sg.notBefore = pc.notBefore;
            sg.notAfter = pc.notAfter;
            sg.thumbprintSha1 = sha1Hex((const uint8_t*)pc.der.data(), pc.der.size());
            out.signers.push_back(sg);
        }
    }
    out.ok = out.certCount > 0;
    if (!out.ok && out.error.empty()) out.error = "no certificates found";
    return out.ok;
}

void writePkcs7Json(Builder& b, const Pkcs7Result& r) {
    b.beginObj();
    b.kv("ok", r.ok);
    b.kv("contentType", r.contentType);
    b.kv("certCount", (uint64_t)r.certCount);
    if (!r.error.empty()) b.kv("error", r.error);
    b.arr("signers");
    for (const X509Signer& s : r.signers) {
        b.beginObj();
        b.kv("subject", s.subject);
        b.kv("issuer", s.issuer);
        b.kv("serial", s.serial);
        b.kv("notBefore", s.notBefore);
        b.kv("notAfter", s.notAfter);
        b.kv("signatureAlg", s.signatureAlg);
        b.kv("thumbprintSha1", s.thumbprintSha1);
        b.endObj();
    }
    b.endArr();
    b.endObj();
}

}
