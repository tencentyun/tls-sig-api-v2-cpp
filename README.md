## 说明
此项目为 tls-sig-api-v2 版本 c++ 实现，之前非对称密钥无法使用此版本 api，如需使用请查看[这里](https://github.com/tencentyun/tls-sig-api)。

## 下载代码并同步依赖
```shell
git clone https://github.com/tencentyun/tls-sig-api-v2-cpp.git
cd tls-sig-api-v2-cpp
git submodule update --init --recursive
```

如果上面同步代码的操作出现问题，可以到[这里](https://github.com/tencentyun/tls-sig-api-v2-cpp/releases)下载源代码。

## 构建

### 类 Unix 系统
构建依赖于 `CMake` 、 `make` 以及 `gcc`，请确保已经安装。

```shell
cmake CMakeLists.txt
cmake --build .
```

如果需要手动指定 openssl 路径，运行 `cmake CMakeLists.txt` 命令时添加下列命令
```shell
cmake  -DOPENSSL_ROOT_DIR=your_openssl_root_dir CMakeLists.txt
cmake --build .
```

头文件路径如下
```
src/tls_sig_api_v2.h
```

库文件路径如下
```

./libtlssigapi_v2.a
```

用户构建项目时除了链接 `libtlssigapi_v2.a`，还需引入 `zlib` 和 `openssl`，类 Unix 系统一般都会自带，只需要在链接指令中添加下面的指令
```
-lz -lcrypto
```

### Windows
Windows 平台构建依赖 `CMake` 和 `Visual Studio`，请确保已经安装。

```
.\build.bat
```

头文件路径如下

```
src/tls_sig_api_v2.h
```

库文件路径，分 Win32 和 x64，而且 Debug 和 Release 也通过目录予以区分
```
tls-sig-api_xx/xxxx/tlssigapi_v2.lib
tls-sig-api_xx/xxxx/zlibstatic.lib
tls-sig-api_xx/xxxx/mbedcrypto.lib
```
另外 Debug 版本的 zlib 名称为 zlibstaticd.lib

用户构建项目时只需要引用头文件 `src/tls_sig_api_v2.h` 和上述三个库文件。

## 使用

### 接口使用

```C
#include "tls_sig_api_v2.h"
#include <string>
#include <iostream>

std::string key = "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e";

std::string sig;
std::sgring errMsg;
int ret = gen_sig(140000000, "xiaojun", key, 180*86400, sig, errMsg);
if (0 != ret) {
	std::cout << "gen_sig_v2 failed " << ret << " " << errMsg << std::endl;
} else {
	std::cout << "gen_sig_v2 " << sig << std::endl;
}

```

### 多线程支持
因为类 Unix 目前默认使用了 openssl，需要在多线程程序初始化时调用。windows 版本无此问题。
```C
thread_setup();
```
在程序结束时调用
```C
thread_cleanup();
```

