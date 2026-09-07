#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace cb {

class Builder;

struct X509Signer {
    std::string subject;
    std::string issuer;
    std::string serial;
    std::string notBefore;
    std::string notAfter;
    std::string signatureAlg;
    std::string thumbprintSha1;
};

struct Pkcs7Result {
    bool ok = false;
    uint32_t certCount = 0;
    std::vector<X509Signer> signers;
    std::string contentType;
    std::string error;
};

bool parsePkcs7(const uint8_t* d, size_t n, Pkcs7Result& out);
void writePkcs7Json(Builder& b, const Pkcs7Result& r);

}
