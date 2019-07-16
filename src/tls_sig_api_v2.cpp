#include "tls_sig_api_v2.h"
#if defined(WIN32) || defined(WIN64)
#pragma warning(disable: 4819)			// file codec warning, that's boring!
#endif

#include <cstdio>
#include <ctime>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>

#ifdef USE_OPENSSL
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/hmac.h"
#include "openssl/sha.h"
#else
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/base64.h"
#endif

#include "zlib.h"

#define fmt tls_signature_fmt
#define FMT_NO_FMT_STRING_ALIAS
#include "fmt/printf.h"

#define rapidjson tls_signature_rapidjson
#include "rapidjson/writer.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/pointer.h"

#if defined(WIN32) || defined(WIN64)
#pragma warning(disable: 4819)
#pragma warning(disable: 4267)
#pragma warning(disable: 4244)
#endif

static std::string hmacsha256(uint32_t sdkappid, const std::string& identifier,
        uint64_t initTime, uint64_t expire, const std::string& key);
static std::string hmacsha256(uint32_t sdkappid,
        const std::string& identifier, uint64_t initTime, uint64_t expire,
        const std::string& key, const std::string& userBuf);

//去掉某些base64中生成的\r\n space
static std::string base64_strip(const void* data, size_t data_len)
{
    const char* d = static_cast<const char*>(data);
    std::string s;
    s.reserve(data_len);
    for (size_t i = 0; i < data_len; ++i) {
        if (isspace(d[i])) continue;
        s.append(1, d[i]);
    }
    return s;
}

#ifdef USE_OPENSSL
static int base64_encode(const void* data, size_t data_len, std::string &base64_buffer){
    div_t res = std::div(data_len, 3);
    size_t outlen = res.quot * 4 + (res.rem ? 4 : 0);
    base64_buffer.resize(outlen);
    EVP_EncodeBlock(reinterpret_cast<uint8_t*>(const_cast<char*>(base64_buffer.data())),
            reinterpret_cast<const uint8_t*>(data), data_len);
    return 0;
}
static int base64_decode(const char* data, size_t data_len, std::string &raw){
    raw.resize(data_len);
    std::string base64 = base64_strip(data, data_len);
    int outlen = EVP_DecodeBlock(
        reinterpret_cast<uint8_t*>(const_cast<char*>(raw.data())),
        reinterpret_cast<const uint8_t*>(base64.data()), base64.size());
    if(outlen < 0) return outlen;
    if (base64.size() > 1 && base64[base64.size() - 1] == '=') {
        --outlen;
        if (base64.size() > 2 && base64[base64.size() - 2] == '=') --outlen;
    }
    raw.resize(outlen);
    return 0;
}
#else // USE_OPENSSL
static int base64_encode(const void* data, size_t data_len, std::string &base64_buffer){
    size_t outlen = 0;
    int ret = mbedtls_base64_encode(NULL, 0, &outlen, reinterpret_cast<const uint8_t*>(data), data_len);
    if(ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)return ret;
    base64_buffer.resize(outlen);
    ret = mbedtls_base64_encode(
        reinterpret_cast<uint8_t*>(const_cast<char*>(base64_buffer.data())),
        base64_buffer.size(), &outlen, reinterpret_cast<const uint8_t*>(data), data_len);
    base64_buffer.resize(outlen);
    return ret;
}
static int base64_decode(const char* data, size_t data_len, std::string &raw){
    size_t outlen = 0;
    std::string base64 = base64_strip(data, data_len);
    int ret = mbedtls_base64_decode(
        NULL, 0, &outlen, reinterpret_cast<const uint8_t*>(base64.data()),
        base64.size());
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) return ret;
    raw.resize(outlen);
    ret = mbedtls_base64_decode(
        reinterpret_cast<uint8_t*>(const_cast<char*>(raw.data())), raw.size(),
        &outlen, reinterpret_cast<const uint8_t*>(base64.data()),
        base64.size());
    return ret;
}
#endif // USE_OPENSSL

static int base64_encode_url(const void *data, size_t data_len, std::string &base64) {
    int ret = base64_encode(data, data_len, base64);
    if(ret != 0)return ret;
    for(size_t i=0;i<base64.size();++i){
        switch(base64[i]){
        case '+':
            base64[i] = '*';
            break;
        case '/':
            base64[i] = '-';
            break;
        case '=':
            base64[i] = '_';
            break;
        default:
            break;
        }
    }
    return 0;
}

static int compress(const void *data, size_t data_len, std::string &compressed) {
    compressed.resize(std::max(data_len, static_cast<size_t>(128)));
    uLongf uLen = compressed.size();
    int ret = compress2(
        reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data())), &uLen,
        reinterpret_cast<const Bytef*>(data), data_len, Z_BEST_SPEED);
    if(ret == Z_OK) {
        compressed.resize(uLen);
        return ret;
    }
    if(ret != Z_MEM_ERROR)return ret;
    compressed.resize(compressed.size() * 2);
    uLen = compressed.size();
    ret = compress2(
        reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data())), &uLen,
        reinterpret_cast<const Bytef*>(data), data_len, Z_BEST_SPEED);
    if(ret == Z_OK) compressed.resize(uLen);
    return ret;
}

static int JsonToSig(const rapidjson::Document &json, std::string &sig, std::string &errmsg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> w(s);
    json.Accept(w);

    std::string compressed;
    int ret = compress(s.GetString(), s.GetSize(), compressed);
    if (ret != Z_OK)
    {
        errmsg = fmt::sprintf("compress failed %d", ret);
        return CHECK_ERR16;
    }
    ret =base64_encode_url(compressed.data(), compressed.size(), sig);
    if(ret != 0){
        errmsg = fmt::sprintf("base64_encode_url failed %#x", ret);
        return CHECK_ERR16;
    }
    return 0;
}

// 生成签名
TLS_API int gen_sig(uint32_t sdkappid, const std::string& identifier,
        const std::string& key, int expire,
        std::string& sig, std::string& errMsg)
{
    uint64_t currTime = time(NULL);
    std::string base64RawSig = hmacsha256(sdkappid, identifier, currTime, expire, key);
    rapidjson::Document sigDoc;
    sigDoc.SetObject();
    sigDoc.AddMember("TLS.ver", "2.0", sigDoc.GetAllocator());
    sigDoc.AddMember("TLS.sdkappid", sdkappid, sigDoc.GetAllocator());
    sigDoc.AddMember("TLS.identifier", identifier, sigDoc.GetAllocator());
    sigDoc.AddMember("TLS.time", currTime, sigDoc.GetAllocator());
    sigDoc.AddMember("TLS.expire", expire, sigDoc.GetAllocator());
    sigDoc.AddMember("TLS.sig", base64RawSig, sigDoc.GetAllocator());
    return JsonToSig(sigDoc, sig, errMsg);
}

// 生成带 userbuf 的签名
TLS_API int gen_sig_with_userbuf(
        uint32_t sdkappid,
        const std::string& identifier,
		const std::string& key,
        int expire,
        const std::string& userBuf,
        std::string& sig,
        std::string& errMsg)
{
    uint64_t currTime = time(NULL);
    std::string base64UserBuf;
    base64_encode(userBuf.data(), userBuf.length(), base64UserBuf);
    std::string base64RawSig = hmacsha256(
            sdkappid, identifier, currTime, expire, key, base64UserBuf);
    rapidjson::Document sigDoc;
    sigDoc.SetObject();
    sigDoc.AddMember("TLS.ver", "2.0", sigDoc.GetAllocator());
    sigDoc.AddMember("TLS.sdkappid", sdkappid, sigDoc.GetAllocator());
    sigDoc.AddMember("TLS.identifier", identifier, sigDoc.GetAllocator());
    sigDoc.AddMember("TLS.time", currTime, sigDoc.GetAllocator());
    sigDoc.AddMember("TLS.expire", expire, sigDoc.GetAllocator());
    sigDoc.AddMember("TLS.userbuf", base64UserBuf, sigDoc.GetAllocator());
    sigDoc.AddMember("TLS.sig", base64RawSig, sigDoc.GetAllocator());
    return JsonToSig(sigDoc, sig, errMsg);
}


static std::string __hmacsha256(uint32_t sdkappid,
        const std::string& identifier, uint64_t initTime,
        uint64_t expire, const std::string& key,
        const std::string& base64UserBuf, bool userBufEnabled)
{
    std::string rawContentToBeSigned = "TLS.identifier:" + identifier + "\n"
        + "TLS.sdkappid:" + std::to_string(static_cast<long long>(sdkappid)) + "\n"
        + "TLS.time:" + std::to_string(static_cast<long long>(initTime)) + "\n"
        + "TLS.expire:" + std::to_string(static_cast<long long>(expire)) + "\n";
    if (true == userBufEnabled) {
        rawContentToBeSigned += "TLS.userbuf:" + base64UserBuf + "\n";
    }
    std::string base64Result;

#ifdef USE_OPENSSL
    unsigned char result[SHA256_DIGEST_LENGTH];
    unsigned resultLen = sizeof(result);
    HMAC(EVP_sha256(), key.data(), key.length(),
            reinterpret_cast<const unsigned char *>(rawContentToBeSigned.data()),
            rawContentToBeSigned.length(), result, &resultLen);
#else
    unsigned char result[32] = { 0 };
    unsigned resultLen = sizeof(result);
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx,
            reinterpret_cast<const unsigned char *>(key.data()), key.length());
    mbedtls_md_hmac_update(&ctx,
            reinterpret_cast<const unsigned char *>(rawContentToBeSigned.data()),
            rawContentToBeSigned.length());
    mbedtls_md_hmac_finish(&ctx, result);
    mbedtls_md_free(&ctx);
#endif
    base64_encode(result, resultLen, base64Result);
    return base64Result;
}


// 使用 hmac sha256 生成 sig
static std::string hmacsha256(uint32_t sdkappid,
        const std::string& identifier, uint64_t initTime,
        uint64_t expire, const std::string& key)
{
    return __hmacsha256(sdkappid, identifier,
            initTime, expire, key, "", false);
}


// 使用 hmac sha256 生成带 userbuf 的 sig
static std::string hmacsha256(uint32_t sdkappid,
        const std::string& identifier, uint64_t initTime,
        uint64_t expire, const std::string& key,
        const std::string& base64UserBuf)
{
    return __hmacsha256(sdkappid, identifier,
            initTime, expire, key, base64UserBuf, true);
}

