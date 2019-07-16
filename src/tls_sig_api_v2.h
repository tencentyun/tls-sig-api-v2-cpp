#ifndef TLS_SIG_API_V2_H
#define TLS_SIG_API_V2_H

#if defined(WIN32) || defined(WIN64)
#pragma warning(disable: 4819)			// file codec warning, that's boring!
#define TLS_API __declspec(dllexport)
#else
#define TLS_API
#endif

#include <stdint.h>
#include <string>

enum {
    CHECK_ERR01 = 1,       // sig 为空
    CHECK_ERR02,           // sig base64 解码失败
    CHECK_ERR03,           // sig zip 解压缩失败
    CHECK_ERR04,           // sig 使用 json 解析时失败
    CHECK_ERR05,           // sig 使用 json 解析时失败
    CHECK_ERR06,           // sig 中 json 串 sig 字段 base64 解码失败
    CHECK_ERR07,           // sig 中字段缺失
    CHECK_ERR08,           // sig 校验签名失败，一般是秘钥不正确
    CHECK_ERR09,           // sig 过期
    CHECK_ERR10,           // sig 使用 json 解析时失败
    CHECK_ERR11,           // sig 中 appid_at_3rd 与明文不匹配
    CHECK_ERR12,           // sig 中 acctype 与明文不匹配
    CHECK_ERR13,           // sig 中 identifier 与明文不匹配
    CHECK_ERR14,           // sig 中 sdk_appid 与明文不匹配
    CHECK_ERR15,           // sig 中 userbuf 异常
    CHECK_ERR16,           // 内部错误
    CHECK_ERR17,           // 签名失败 可能是私钥有误
    CHECK_ERR_MAX,
};


/**
 * @brief 生成签名函数
 * @param sdkappid 应用ID
 * @param identifier 用户账号，utf-8 编码
 * @param key 密钥
 * @param expire 有效期，单位秒
 * @param sig 返回的 sig
 * @param errmsg 错误信息
 *
 * @return 0 为成功，非 0 为失败
 */
TLS_API int gen_sig(
        uint32_t sdkappid,
        const std::string& identifier,
        const std::string& key,
        int expire,
        std::string& sig,
        std::string& errmsg);


/**
 * @brief 生成带 userbuf 签名函数
 *
 * @param sdkappid 应用ID
 * @param identifier 用户账号，utf-8 编码
 * @param key 密钥
 * @param expire 有效期，单位秒
 * @param userbuf 用户数据
 * @param sig 返回的 sig
 * @param errmsg 错误信息
 *
 * @return 0 为成功，非 0 为失败
 */
TLS_API int gen_sig_with_userbuf(
        uint32_t sdkappid,
        const std::string& identifier,
        const std::string& key,
        int expire,
        const std::string& userbuf,
        std::string& sig,
        std::string& errmsg);


int thread_setup();
void thread_cleanup();

#endif // TLS_SIG_API_V2_H
