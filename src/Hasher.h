
#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <vector>
#include <optional>

constexpr uint32_t SHA256_LEN_BYTES = 32;

class Hasher
{
public:
    explicit Hasher(std::array<uint8_t, SHA256_LEN_BYTES> const &salt, int idx) : m_salt(salt), m_idx(idx) {};

    std::optional<std::array<uint8_t, SHA256_LEN_BYTES>> getHash(uint8_t const *in, size_t length) const;

private:

    std::array<uint8_t, SHA256_LEN_BYTES> getInput(uint8_t const *in, size_t length) const;

    std::array<uint8_t, SHA256_LEN_BYTES> m_salt;
    size_t m_idx;
};

