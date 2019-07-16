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


/**
 * @brief 描述 sig 内容的结构体，各个字段的含义可以参考 tls_gen_signature_ex()
 * @see tls_gen_signature_ex()
 */
typedef struct
{
	std::string strAccountType;
	std::string strAppid3Rd;
	std::string strAppid;            /**< 即 sdkappid  */
	std::string strIdentify;
} SigInfo;

enum {
	CHECK_ERR1  =  1,       // sig 为空
	CHECK_ERR2 ,            // sig base64 解码失败
	CHECK_ERR3 ,            // sig zip 解压缩失败
	CHECK_ERR4 ,            // sig 使用 json 解析时失败
	CHECK_ERR5 ,            // sig 使用 json 解析时失败
	CHECK_ERR6 ,            // sig 中 json 串 sig 字段 base64 解码失败
	CHECK_ERR7 ,            // sig 中字段缺失
	CHECK_ERR8 ,            // sig 校验签名失败，一般是秘钥不正确
	CHECK_ERR9 ,            // sig 过期
	CHECK_ERR10 ,           // sig 使用 json 解析时失败
	CHECK_ERR11 ,           // sig 中 appid_at_3rd 与明文不匹配
	CHECK_ERR12 ,           // sig 中 acctype 与明文不匹配
	CHECK_ERR13 ,           // sig 中 identifier 与明文不匹配
	CHECK_ERR14 ,           // sig 中 sdk_appid 与明文不匹配
    CHECK_ERR15 ,           // sig 中 userbuf 异常
    CHECK_ERR16 ,           // 内部错误
    CHECK_ERR17 ,           // 签名失败 可能是私钥有误

	CHECK_ERR_MAX,
};

/**
 * @brief 生成签名函数
 * @param sdkappid 应用ID
 * @param identifier 用户账号，utf-8 编码
 * @param key 密钥
 * @param expire 有效期，单位秒
 * @param sig 返回的 sig
 * @param errMsg 错误信息
 *
 * @return 0 为成功，非 0 为失败
 */
TLS_API int gen_sig(
        uint32_t sdkappid,
        const std::string& identifier,
		const std::string& key,
        int expire,
        std::string& sig,
        std::string& errMsg);

/**
 * @brief 生成带 userbuf 签名函数
 *
 * @param sdkappid 应用ID
 * @param identifier 用户账号，utf-8 编码
 * @param key 密钥
 * @param expire 有效期，单位秒
 * @param userBuf 用户数据
 * @param sig 返回的 sig
 * @param errMsg 错误信息
 *
 * @return 0 为成功，非 0 为失败
 */
TLS_API int gen_sig_with_userbuf(
        uint32_t sdkappid,
        const std::string& identifier,
		const std::string& key,
        int expire,
        const std::string& userBuf,
        std::string& sig,
        std::string& errMsg);


int thread_setup();
void thread_cleanup();

namespace tls_signature_inner
{

TLS_API int SigToJson(const std::string &sig,
        std::string &json, std::string  &errmsg);

}

#endif

