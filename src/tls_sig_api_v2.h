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
/**用于生成实时音视频(TRTC)业务进房权限加密串,具体用途用法参考TRTC文档：https://cloud.tencent.com/document/product/647/32240 
 * TRTC业务进房权限加密串需使用用户定义的userbuf
 * @brief 生成 userbuf
 * @param account 用户名
 * @param dwSdkappid sdkappid
 * @param dwAuthID  数字房间号
 * @param dwExpTime 过期时间：该权限加密串的过期时间，建议300秒，300秒内拿到该签名，并且发起进房间操作
 * @param dwPrivilegeMap 用户权限，255表示所有权限
 * @param dwAccountType 用户类型,默认为0
 * @return byte[] userbuf
 */
TLS_API std::string  gen_userbuf(
	const std::string & account,
	uint32_t dwSdkappid,
	uint32_t dwAuthID,
        uint32_t dwExpTime,
	uint32_t dwPrivilegeMap,
	uint32_t dwAccountType);
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
 * @param roomnum 房间号
 * @param expire 有效期，单位秒
 * @param privilege 用户权限，255表示所有权限
 * @param sig 返回的 sig
 * @param errmsg 错误信息
 *
 * @return 0 为成功，非 0 为失败
 */
TLS_API int gen_sig_with_userbuf(
        uint32_t sdkappid,
        const std::string& identifier,
        const std::string& key,
        int roomnum,
        int expire,
        int privilege,
        std::string& sig,
        std::string& errmsg);


int thread_setup();
void thread_cleanup();

#endif // TLS_SIG_API_V2_H
