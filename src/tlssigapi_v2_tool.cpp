#if defined(WIN32) || defined(WIN64)
#pragma warning(disable : 4819)  // file codec warning, that's boring!
#pragma warning(disable : 4099)
#endif

// 此文件演示了文件两个接口的使用方法
// 首先是生成签名接口的方法，然后的校验签名接口的方法

#include <stdlib.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include "tls_sig_api_v2.h"

static void usage(const std::string &prog) {
  std::cout << "Usage:" << std::endl;
  std::cout << "\tgen sig: " << prog << " gen key sig_file sdkappid identifier" << std::endl;
  std::cout << "\tgen sig e.g.: " << prog
            << " gen 5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e sig 1400000000 xiaojun"
            << std::endl;
  std::cout << "\tgenuser sig: " << prog << " genuser key sig_file sdkappid identifier" << std::endl;
  std::cout << "\tgenuser sig: " << prog
            << " genuser 5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e sig 1400000000 xiaojun"
            << std::endl;
  std::cout
      << "\tgenuserbystringroom sig: " << prog
      << " genuserbystringroom 5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e sig 1400000000 xiaojun"
      << std::endl;
}

static int genUserSig(const std::string &key, const std::string &sig_file, uint32_t sdkappid,
                      const std::string &userid) {
  std::string sig;
  std::string err_msg;
  int ret = genUserSig(sdkappid, userid, key, 180 * 86400, sig, err_msg);
  if (0 != ret) {
    std::cout << "error msg: " << err_msg << " return " << ret << std::endl;
    return -3;
  }

#if defined(WIN32) || defined(WIN64)
  FILE *sig_fp = NULL;
  fopen_s(&sig_fp, sig_file.c_str(), "w+");
#else
  FILE *sig_fp = fopen(sig_file.c_str(), "w+");
#endif
  if (!sig_fp) {
    std::cout << "open file " << sig_file << "failed" << std::endl;
    return -4;
  }

  // 将签名写入文件
  int written_cnt = (int)fwrite(sig.c_str(), sizeof(char), sig.size(), sig_fp);
  if (sig.size() > (unsigned int)written_cnt && 0 != ferror(sig_fp)) {
    std::cout << "write sig content failed" << std::endl;
    return -5;
  }

  std::cout << sig << std::endl;
  std::cout << "generate sig ok" << std::endl;

  return 0;
}

static int genPrivateMapKey(const std::string &key, const std::string &sig_file, uint32_t sdkappid,
                            const std::string &userid) {
  std::string sig;
  std::string err_msg;
  int ret = genPrivateMapKey(sdkappid, userid, key, 10000, 180 * 86400, 255, sig, err_msg);
  if (0 != ret) {
    std::cout << "error msg: " << err_msg << " return " << ret << std::endl;
    return -3;
  }

#if defined(WIN32) || defined(WIN64)
  FILE *sig_fp = NULL;
  fopen_s(&sig_fp, sig_file.c_str(), "w+");
#else
  FILE *sig_fp = fopen(sig_file.c_str(), "w+");
#endif
  if (!sig_fp) {
    std::cout << "open file " << sig_file << "failed" << std::endl;
    return -4;
  }

  // 将签名写入文件
  int written_cnt = (int)fwrite(sig.c_str(), sizeof(char), sig.size(), sig_fp);
  if (sig.size() > (unsigned int)written_cnt && 0 != ferror(sig_fp)) {
    std::cout << "write sig content failed" << std::endl;
    return -5;
  }

  std::cout << sig << std::endl;
  std::cout << "generate sig ok" << std::endl;

  return 0;
}
static int genPrivateMapKeyWithStringRoomID(const std::string &key, const std::string &sig_file, uint32_t sdkappid,
                                            const std::string &userid) {
  std::string sig;
  std::string err_msg;
  int ret = genPrivateMapKeyWithStringRoomID(sdkappid, userid, key, "10000657", 180 * 86400, 255, sig, err_msg);
  if (0 != ret) {
    std::cout << "error msg: " << err_msg << " return " << ret << std::endl;
    return -3;
  }

#if defined(WIN32) || defined(WIN64)
  FILE *sig_fp = NULL;
  fopen_s(&sig_fp, sig_file.c_str(), "w+");
#else
  FILE *sig_fp = fopen(sig_file.c_str(), "w+");
#endif
  if (!sig_fp) {
    std::cout << "open file " << sig_file << "failed" << std::endl;
    return -4;
  }

  // 将签名写入文件
  int written_cnt = (int)fwrite(sig.c_str(), sizeof(char), sig.size(), sig_fp);
  if (sig.size() > (unsigned int)written_cnt && 0 != ferror(sig_fp)) {
    std::cout << "write sig content failed" << std::endl;
    return -5;
  }

  std::cout << sig << std::endl;
  std::cout << "generate sig ok" << std::endl;

  return 0;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    usage(argv[0]);
    return -1;
  }

  const char *cmd = argv[1];
  std::string sig_file;
  std::string sdkappid_str;
  std::string userid;

  int ret = 0;
  if (0 == strcmp(cmd, "gen") && 6 == argc) {
    std::string key = argv[2];
    std::string sig_file = argv[3];
    std::string sdkappid_str = argv[4];
    std::string userid = argv[5];
    ret = genUserSig(key, sig_file, strtol(sdkappid_str.c_str(), NULL, 10), userid);
  } else if (0 == strcmp(cmd, "genuser") && 6 == argc) {
    std::string key = argv[2];
    std::string sig_file = argv[3];
    std::string sdkappid_str = argv[4];
    std::string userid = argv[5];
    ret = genPrivateMapKey(key, sig_file, strtol(sdkappid_str.c_str(), NULL, 10), userid);
  } else if (0 == strcmp(cmd, "genuserbystringroom") && 6 == argc) {
    std::string key = argv[2];
    std::string sig_file = argv[3];
    std::string sdkappid_str = argv[4];
    std::string userid = argv[5];
    ret = genPrivateMapKeyWithStringRoomID(key, sig_file, strtol(sdkappid_str.c_str(), NULL, 10), userid);
  } else {
    usage(argv[0]);
    return -1;
  }

  if (0 != ret) {
    std::cout << "cmd " << cmd << " return " << ret << std::endl;
  }

  return ret;
}
