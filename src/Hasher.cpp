#include "Hasher.h"
#include <openssl/evp.h>

using namespace std;

constexpr uint32_t NUM_HASH_LOOPS = 15000;

optional<std::array<uint8_t, SHA256_LEN_BYTES>>
Hasher::getHash(uint8_t const *in, size_t length) const
{
    optional<std::array<uint8_t, SHA256_LEN_BYTES>> ret;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if(mdctx != nullptr)
    {
        std::array<uint8_t, SHA256_LEN_BYTES> feed1 = getInput(in, length);
        std::array<uint8_t, SHA256_LEN_BYTES> feed2 = {};

        std::array<uint8_t, SHA256_LEN_BYTES> &src = feed1;
        std::array<uint8_t, SHA256_LEN_BYTES> &tgt = feed2;

        bool success = true;

        for (uint32_t loopIdx = 0; loopIdx < NUM_HASH_LOOPS; loopIdx++)
        {
            if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) &&
                EVP_DigestUpdate(mdctx, static_cast<unsigned char const *>(&src[0]), src.size()))
            {
                unsigned int digest_len = tgt.size();
                if (EVP_DigestFinal_ex(mdctx, &tgt[0], &digest_len))
                {
                    std::swap(src, tgt);
                }
                else
                {
                    success = false;
                    break;
                }
            }
        }

        if (success)
        {
            ret = src;
        }

        EVP_MD_CTX_free(mdctx);
    }

    return ret;
}

std::array<uint8_t, SHA256_LEN_BYTES>
Hasher::getInput(uint8_t const *in, size_t length) const
{
    std::array<uint8_t, SHA256_LEN_BYTES> ret(m_salt);
    if (length > m_idx)
    {
        ret[0] = in[m_idx];
    }
    return ret;
}

