#ifndef TLS_SIG_API_V2_H
#define TLS_SIG_API_V2_H

#if defined(WIN32) || defined(WIN64)
#pragma warning(disable : 4819) // file codec warning, that's boring!
#define TLS_API __declspec(dllexport)
#else
#define TLS_API
#endif

#include <stdint.h>
#include <string>

enum
{
        CHECK_ERR01 = 1, // sig 为空
        CHECK_ERR02,     // sig base64 解码失败
        CHECK_ERR03,     // sig zip 解压缩失败
        CHECK_ERR04,     // sig 使用 json 解析时失败
        CHECK_ERR05,     // sig 使用 json 解析时失败
        CHECK_ERR06,     // sig 中 json 串 sig 字段 base64 解码失败
        CHECK_ERR07,     // sig 中字段缺失
        CHECK_ERR08,     // sig 校验签名失败，一般是秘钥不正确
        CHECK_ERR09,     // sig 过期
        CHECK_ERR10,     // sig 使用 json 解析时失败
        CHECK_ERR11,     // sig 中 appid_at_3rd 与明文不匹配
        CHECK_ERR12,     // sig 中 acctype 与明文不匹配
        CHECK_ERR13,     // sig 中 identifier 与明文不匹配
        CHECK_ERR14,     // sig 中 sdk_appid 与明文不匹配
        CHECK_ERR15,     // sig 中 userbuf 异常
        CHECK_ERR16,     // 内部错误
        CHECK_ERR17,     // 签名失败 可能是私钥有误
        CHECK_ERR_MAX,
};
/**
 *【功能说明】用于签发 TRTC 和 IM 服务中必须要使用的 UserSig 鉴权票据
 *
 *【参数说明】
 * @param sdkappid - 应用id。
 * @param userid - 用户id，限制长度为32字节，只允许包含大小写英文字母（a-zA-Z）、数字（0-9）及下划线和连词符。
 * @param key - 计算 usersig 用的加密密钥,控制台可获取。
 * @param expire - UserSig 票据的过期时间，单位是秒，比如 86400 代表生成的 UserSig 票据在一天后就无法再使用了。
 * @param usersig - 生成的usersig。
 * @param errmsg - 错误信息。
 * @return 0 为成功，非 0 为失败
 */
TLS_API int genUserSig(
    uint32_t sdkappid,
    const std::string &userid,
    const std::string &key,
    int expire,
    std::string &usersig,
    std::string &errmsg);

/**
 *【功能说明】
 * 用于签发 TRTC 进房参数中可选的 PrivateMapKey 权限票据。
 * PrivateMapKey 需要跟 UserSig 一起使用，但 PrivateMapKey 比 UserSig 有更强的权限控制能力：
 *  - UserSig 只能控制某个 UserID 有无使用 TRTC 服务的权限，只要 UserSig 正确，其对应的 UserID 可以进出任意房间。
 *  - PrivateMapKey 则是将 UserID 的权限控制的更加严格，包括能不能进入某个房间，能不能在该房间里上行音视频等等。
 * 如果要开启 PrivateMapKey 严格权限位校验，需要在【实时音视频控制台】=>【应用管理】=>【应用信息】中打开“启动权限密钥”开关。\
 * 
 *【参数说明】
 * @param sdkappid - 应用id。
 * @param userid - 用户id，限制长度为32字节，只允许包含大小写英文字母（a-zA-Z）、数字（0-9）及下划线和连词符。
 * @param key - 计算 usersig 用的加密密钥,控制台可获取。
 * @param roomid - 房间号，用于指定该 userid 可以进入的房间号
 * @param expire - PrivateMapKey 票据的过期时间，单位是秒，比如 86400 生成的 PrivateMapKey 票据在一天后就无法再使用了。
 * @param privilegeMap - 权限位，使用了一个字节中的 8 个比特位，分别代表八个具体的功能权限开关：
 *  - 第 1 位：0000 0001 = 1，创建房间的权限
 *  - 第 2 位：0000 0010 = 2，加入房间的权限
 *  - 第 3 位：0000 0100 = 4，发送语音的权限
 *  - 第 4 位：0000 1000 = 8，接收语音的权限
 *  - 第 5 位：0001 0000 = 16，发送视频的权限  
 *  - 第 6 位：0010 0000 = 32，接收视频的权限  
 *  - 第 7 位：0100 0000 = 64，发送辅路（也就是屏幕分享）视频的权限
 *  - 第 8 位：1000 0000 = 200，接收辅路（也就是屏幕分享）视频的权限  
 *  - privilegeMap == 1111 1111 == 255 代表该 userid 在该 roomid 房间内的所有功能权限。
 *  - privilegeMap == 0010 1010 == 42  代表该 userid 拥有加入房间和接收音视频数据的权限，但不具备其他权限。
 * @param usersig - 生成的usersig。
 * @param errmsg - 错误信息。
 * @return 0 为成功，非 0 为失败
 */
TLS_API int genPrivateMapKey(
    uint32_t sdkappid,
    const std::string &userid,
    const std::string &key,
    uint32_t roomid,
    int expire,
    int privilegeMap,
    std::string &usersig,
    std::string &errmsg);

/**
 *【功能说明】
 * 用于签发 TRTC 进房参数中可选的 PrivateMapKey 权限票据。
 * PrivateMapKey 需要跟 UserSig 一起使用，但 PrivateMapKey 比 UserSig 有更强的权限控制能力：
 *  - UserSig 只能控制某个 UserID 有无使用 TRTC 服务的权限，只要 UserSig 正确，其对应的 UserID 可以进出任意房间。
 *  - PrivateMapKey 则是将 UserID 的权限控制的更加严格，包括能不能进入某个房间，能不能在该房间里上行音视频等等。
 * 如果要开启 PrivateMapKey 严格权限位校验，需要在【实时音视频控制台】=>【应用管理】=>【应用信息】中打开“启动权限密钥”开关。\
 * 
 *【参数说明】
 * @param sdkappid - 应用id。
 * @param userid - 用户id，限制长度为32字节，只允许包含大小写英文字母（a-zA-Z）、数字（0-9）及下划线和连词符。
 * @param key - 计算 usersig 用的加密密钥,控制台可获取。
 * @param roomstr - 房间号，用于指定该 userid 可以进入的房间号
 * @param expire - PrivateMapKey 票据的过期时间，单位是秒，比如 86400 生成的 PrivateMapKey 票据在一天后就无法再使用了。
 * @param privilegeMap - 权限位，使用了一个字节中的 8 个比特位，分别代表八个具体的功能权限开关：
 *  - 第 1 位：0000 0001 = 1，创建房间的权限
 *  - 第 2 位：0000 0010 = 2，加入房间的权限
 *  - 第 3 位：0000 0100 = 4，发送语音的权限
 *  - 第 4 位：0000 1000 = 8，接收语音的权限
 *  - 第 5 位：0001 0000 = 16，发送视频的权限  
 *  - 第 6 位：0010 0000 = 32，接收视频的权限  
 *  - 第 7 位：0100 0000 = 64，发送辅路（也就是屏幕分享）视频的权限
 *  - 第 8 位：1000 0000 = 200，接收辅路（也就是屏幕分享）视频的权限  
 *  - privilegeMap == 1111 1111 == 255 代表该 userid 在该 roomid 房间内的所有功能权限。
 *  - privilegeMap == 0010 1010 == 42  代表该 userid 拥有加入房间和接收音视频数据的权限，但不具备其他权限。
 * @param usersig - 生成的usersig。
 * @param errmsg - 错误信息。
 * @return 0 为成功，非 0 为失败
 */
TLS_API int genPrivateMapKeyWithStringRoomID(
    uint32_t sdkappid,
    const std::string &userid,
    const std::string &key,
    const std::string &roomstr,
    int expire,
    int privilegeMap,
    std::string &usersig,
    std::string &errmsg);

TLS_API std::string gen_userbuf(
    const std::string &account,
    uint32_t dwSdkappid,
    uint32_t dwAuthID,
    uint32_t dwExpTime,
    uint32_t dwPrivilegeMap,
    uint32_t dwAccountType,
    const std::string &roomStr);

TLS_API int genSig(uint32_t sdkappid, 
    const std::string &userid, 
    const std::string &key, 
    const std::string &userbuf,
    int expire,
    std::string &usersig,
    std::string &errmsg);
int thread_setup();
void thread_cleanup();

#endif // TLS_SIG_API_V2_H
