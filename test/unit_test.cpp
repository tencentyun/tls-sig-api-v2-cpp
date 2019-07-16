#include <gtest/gtest.h>
#include <iostream>

#include "tls_sig_api_v2.cpp"

TEST(gen_sig, 1)
{
    int ret = 0;
    std::string errmsg;
    std::string sig;
    ret = gen_sig(1400000000, "xiaojun",
            "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e",
            180*86400, sig, errmsg);
    ASSERT_EQ(0, ret);
    std::count << sig << std::endl;
}

TEST(gen_sig_with_userbuf, 1)
{
    int ret = 0;
    std::string errmsg;
    std::string sig;
    ret = gen_sig_with_userbuf(1400000000, "xiaojun",
            "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e",
            180*86400, "abc", sig, errmsg);
    ASSERT_EQ(0, ret);
    std::count << sig << std::endl;
}
