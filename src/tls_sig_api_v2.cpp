#include "tls_sig_api_v2.h"
#if defined(WIN32) || defined(WIN64)
#pragma warning(disable : 4819) // file codec warning, that's boring!
#endif

#include <cstdio>
#include <ctime>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>

#ifdef USE_OPENSSL
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
#pragma warning(disable : 4819)
#pragma warning(disable : 4267)
#pragma warning(disable : 4244)
#endif

static std::string hmacsha256(uint32_t sdkappid, const std::string &identifier,
                              uint64_t init_time, uint64_t expire, const std::string &key);
static std::string hmacsha256(uint32_t sdkappid,
                              const std::string &identifier, uint64_t init_time, uint64_t expire,
                              const std::string &key, const std::string &userbuf);

//去掉某些 base64 中生成的 \r\n space
static std::string base64_strip(const void *data, size_t data_len)
{
    const char *d = static_cast<const char *>(data);
    std::string s;
    s.reserve(data_len);
    for (size_t i = 0; i < data_len; ++i)
    {
        if (isspace(d[i]))
            continue;
        s.append(1, d[i]);
    }
    return s;
}

#ifdef USE_OPENSSL
static int base64_encode(const void *data, size_t data_len, std::string &base64_buffer)
{
    div_t res = std::div(data_len, 3);
    size_t outlen = res.quot * 4 + (res.rem ? 4 : 0);
    base64_buffer.resize(outlen);
    EVP_EncodeBlock(reinterpret_cast<uint8_t *>(const_cast<char *>(base64_buffer.data())),
                    reinterpret_cast<const uint8_t *>(data), data_len);
    return 0;
}

static int base64_decode(const char *data, size_t data_len, std::string &raw)
{
    raw.resize(data_len);
    std::string base64 = base64_strip(data, data_len);
    int outlen = EVP_DecodeBlock(
        reinterpret_cast<uint8_t *>(const_cast<char *>(raw.data())),
        reinterpret_cast<const uint8_t *>(base64.data()), base64.size());
    if (outlen < 0)
        return outlen;
    if (base64.size() > 1 && base64[base64.size() - 1] == '=')
    {
        --outlen;
        if (base64.size() > 2 && base64[base64.size() - 2] == '=')
            --outlen;
    }
    raw.resize(outlen);
    return 0;
}
#else  // USE_OPENSSL
static int base64_encode(const void *data, size_t data_len, std::string &base64_buffer)
{
    size_t outlen = 0;
    int ret = mbedtls_base64_encode(NULL, 0, &outlen, reinterpret_cast<const uint8_t *>(data), data_len);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
        return ret;
    base64_buffer.resize(outlen);
    ret = mbedtls_base64_encode(
        reinterpret_cast<uint8_t *>(const_cast<char *>(base64_buffer.data())),
        base64_buffer.size(), &outlen, reinterpret_cast<const uint8_t *>(data), data_len);
    base64_buffer.resize(outlen);
    return ret;
}

static int base64_decode(const char *data, size_t data_len, std::string &raw)
{
    size_t outlen = 0;
    std::string base64 = base64_strip(data, data_len);
    int ret = mbedtls_base64_decode(
        NULL, 0, &outlen, reinterpret_cast<const uint8_t *>(base64.data()),
        base64.size());
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
        return ret;
    raw.resize(outlen);
    ret = mbedtls_base64_decode(
        reinterpret_cast<uint8_t *>(const_cast<char *>(raw.data())), raw.size(),
        &outlen, reinterpret_cast<const uint8_t *>(base64.data()),
        base64.size());
    return ret;
}
#endif // USE_OPENSSL

static int base64_encode_url(const void *data, size_t data_len, std::string &base64)
{
    int ret = base64_encode(data, data_len, base64);
    if (ret != 0)
        return ret;
    for (size_t i = 0; i < base64.size(); ++i)
    {
        switch (base64[i])
        {
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

static int compress(const void *data, size_t data_len, std::string &compressed)
{
    compressed.resize(std::max(data_len, static_cast<size_t>(128)));
    uLongf len = compressed.size();
    int ret = compress2(
        reinterpret_cast<Bytef *>(const_cast<char *>(compressed.data())), &len,
        reinterpret_cast<const Bytef *>(data), data_len, Z_BEST_SPEED);
    if (ret == Z_OK)
    {
        compressed.resize(len);
        return ret;
    }
    if (ret != Z_MEM_ERROR)
        return ret;
    compressed.resize(compressed.size() * 2);
    len = compressed.size();
    ret = compress2(
        reinterpret_cast<Bytef *>(const_cast<char *>(compressed.data())), &len,
        reinterpret_cast<const Bytef *>(data), data_len, Z_BEST_SPEED);
    if (ret == Z_OK)
        compressed.resize(len);
    return ret;
}

static int json2sig(const rapidjson::Document &json, std::string &sig, std::string &errmsg)
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
    ret = base64_encode_url(compressed.data(), compressed.size(), sig);
    if (ret != 0)
    {
        errmsg = fmt::sprintf("base64_encode_url failed %#x", ret);
        return CHECK_ERR16;
    }
    return 0;
}

static std::string __hmacsha256(uint32_t sdkappid, const std::string &identifier, uint64_t init_time, uint64_t expire,
                                const std::string &key, const std::string &base64_userbuf, bool userbuf_enabled)
{
    std::string raw_content_to_be_signed = "TLS.identifier:" + identifier + "\n" + "TLS.sdkappid:" + std::to_string(static_cast<long long>(sdkappid)) + "\n" + "TLS.time:" + std::to_string(static_cast<long long>(init_time)) + "\n" + "TLS.expire:" + std::to_string(static_cast<long long>(expire)) + "\n";
    if (true == userbuf_enabled)
    {
        raw_content_to_be_signed += "TLS.userbuf:" + base64_userbuf + "\n";
    }
    std::string base64_result;

#ifdef USE_OPENSSL
    unsigned char result[SHA256_DIGEST_LENGTH];
    unsigned result_len = sizeof(result);
    HMAC(EVP_sha256(), key.data(), key.length(),
         reinterpret_cast<const unsigned char *>(raw_content_to_be_signed.data()),
         raw_content_to_be_signed.length(), result, &result_len);
#else
    unsigned char result[32] = {0};
    unsigned result_len = sizeof(result);
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx,
                           reinterpret_cast<const unsigned char *>(key.data()), key.length());
    mbedtls_md_hmac_update(&ctx,
                           reinterpret_cast<const unsigned char *>(raw_content_to_be_signed.data()),
                           raw_content_to_be_signed.length());
    mbedtls_md_hmac_finish(&ctx, result);
    mbedtls_md_free(&ctx);
#endif
    base64_encode(result, result_len, base64_result);
    return base64_result;
}

// 使用 hmac sha256 生成 sig
static std::string hmacsha256(uint32_t sdkappid, const std::string &identifier,
                              uint64_t init_time, uint64_t expire, const std::string &key)
{
    return __hmacsha256(sdkappid, identifier,
                        init_time, expire, key, "", false);
}

// 使用 hmac sha256 生成带 userbuf 的 sig
static std::string hmacsha256(uint32_t sdkappid, const std::string &identifier, uint64_t init_time,
                              uint64_t expire, const std::string &key, const std::string &base64_userbuf)
{
    return __hmacsha256(sdkappid, identifier,
                        init_time, expire, key, base64_userbuf, true);
}
// 生成签名
TLS_API int genUserSig(uint32_t sdkappid, const std::string &userid, const std::string &key,
                       int expire, std::string &usersig, std::string &errmsg)
{
    uint64_t curr_time = time(NULL);
    std::string base64_raw_sig = hmacsha256(sdkappid, userid, curr_time, expire, key);
    rapidjson::Document sig_doc;
    sig_doc.SetObject();
    sig_doc.AddMember("TLS.ver", "2.0", sig_doc.GetAllocator());
    sig_doc.AddMember("TLS.sdkappid", sdkappid, sig_doc.GetAllocator());
    sig_doc.AddMember("TLS.identifier", userid, sig_doc.GetAllocator());
    sig_doc.AddMember("TLS.time", curr_time, sig_doc.GetAllocator());
    sig_doc.AddMember("TLS.expire", expire, sig_doc.GetAllocator());
    sig_doc.AddMember("TLS.sig", base64_raw_sig, sig_doc.GetAllocator());
    return json2sig(sig_doc, usersig, errmsg);
}

// 生成带 userbuf 的签名
TLS_API int genPrivateMapKey(uint32_t sdkappid, const std::string &userid, const std::string &key, uint32_t roomid,
                             int expire, int privilegeMap, std::string &usersig, std::string &errmsg)
{
    uint64_t currTime = time(NULL);
    std::string userbuf = gen_userbuf(userid, sdkappid, roomid, expire, privilegeMap, 0);
    std::string base64UserBuf;
    base64_encode(userbuf.data(), userbuf.length(), base64UserBuf);
    std::string base64RawSig = hmacsha256(
        sdkappid, userid, currTime, expire, key, base64UserBuf);
    rapidjson::Document sig_doc;
    sig_doc.SetObject();
    sig_doc.AddMember("TLS.ver", "2.0", sig_doc.GetAllocator());
    sig_doc.AddMember("TLS.sdkappid", sdkappid, sig_doc.GetAllocator());
    sig_doc.AddMember("TLS.identifier", userid, sig_doc.GetAllocator());
    sig_doc.AddMember("TLS.time", currTime, sig_doc.GetAllocator());
    sig_doc.AddMember("TLS.expire", expire, sig_doc.GetAllocator());
    sig_doc.AddMember("TLS.userbuf", base64UserBuf, sig_doc.GetAllocator());
    sig_doc.AddMember("TLS.sig", base64RawSig, sig_doc.GetAllocator());
    return json2sig(sig_doc, usersig, errmsg);
}

TLS_API std::string gen_userbuf(const std::string &account, uint32_t dwSdkappid, uint32_t dwAuthID,
                                uint32_t dwExpTime, uint32_t dwPrivilegeMap, uint32_t dwAccountType)
{
    int length = 1 + 2 + account.length() + 20;
    int offset = 0;
    char userBuf[length];
    memset(userBuf, 0, sizeof(userBuf));

    userBuf[offset++] = 0;

    userBuf[offset++] = ((account.length() & 0xFF00) >> 8);
    userBuf[offset++] = (account.length() & 0x00FF);

    for (; offset < account.length() + 3; ++offset)
    {
        userBuf[offset] = account[offset - 3];
    }

    //dwSdkAppid
    userBuf[offset++] = ((dwSdkappid & 0xFF000000) >> 24);
    userBuf[offset++] = ((dwSdkappid & 0x00FF0000) >> 16);
    userBuf[offset++] = ((dwSdkappid & 0x0000FF00) >> 8);
    userBuf[offset++] = (dwSdkappid & 0x000000FF);

    //dwAuthId
    userBuf[offset++] = ((dwAuthID & 0xFF000000) >> 24);
    userBuf[offset++] = ((dwAuthID & 0x00FF0000) >> 16);
    userBuf[offset++] = ((dwAuthID & 0x0000FF00) >> 8);
    userBuf[offset++] = (dwAuthID & 0x000000FF);

    //uint32_t expire = now + dwExpTime;
    uint32_t expire = time(NULL) + dwExpTime;
    userBuf[offset++] = ((expire & 0xFF000000) >> 24);
    userBuf[offset++] = ((expire & 0x00FF0000) >> 16);
    userBuf[offset++] = ((expire & 0x0000FF00) >> 8);
    userBuf[offset++] = (expire & 0x000000FF);

    //dwPrivilegeMap
    userBuf[offset++] = ((dwPrivilegeMap & 0xFF000000) >> 24);
    userBuf[offset++] = ((dwPrivilegeMap & 0x00FF0000) >> 16);
    userBuf[offset++] = ((dwPrivilegeMap & 0x0000FF00) >> 8);
    userBuf[offset++] = (dwPrivilegeMap & 0x000000FF);

    //dwAccountType
    userBuf[offset++] = ((dwAccountType & 0xFF000000) >> 24);
    userBuf[offset++] = ((dwAccountType & 0x00FF0000) >> 16);
    userBuf[offset++] = ((dwAccountType & 0x0000FF00) >> 8);
    userBuf[offset++] = (dwAccountType & 0x000000FF);
    return std::string(userBuf, length);
}