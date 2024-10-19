#include <array>
#include <cstdint>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <regex>

#include "Auth.h"
#include "Hasher.h"

using namespace std;

using UserEntry = struct
{
    char const *username;
    array<uint8_t, 32> pw_salt;
    array<uint8_t, 64> pw_hash;
};

// TODO: Could be read in from a .passwd file with authentication
constexpr UserEntry users[] =
{
    {
        "root", /* password is ... */
        {
            0x12, 0x59, 0x67, 0xec, 0x7f, 0x6e, 0xf3, 0xfa,
            0x45, 0xf5, 0xc5, 0x27, 0x98, 0x98, 0x3b, 0xab,
            0x48, 0x83, 0x47, 0x3b, 0x68, 0xf9, 0x33, 0xd2,
            0x33, 0x3a, 0xce, 0xcb, 0x10, 0xf8, 0xc6, 0x9f,
        },        
        {
            0x5b, 0xe2, 0x45, 0x44, 0xeb, 0xcf, 0x77, 0x7d, 
            0xcb, 0x35, 0xbd, 0x0e, 0xcf, 0xf5, 0x09, 0x07, 
            0xb3, 0x8a, 0xbc, 0x53, 0xe2, 0xd0, 0xd6, 0xe4, 
            0xff, 0x7e, 0xbb, 0x55, 0xc0, 0x53, 0x18, 0x8f, 
            0x79, 0x18, 0x8d, 0x38, 0xa1, 0xb5, 0x8e, 0x1e, 
            0x28, 0x0f, 0x36, 0x23, 0x61, 0xf6, 0x91, 0xbd, 
            0xf8, 0x0b, 0x22, 0xcf, 0x23, 0x58, 0x85, 0xe1, 
            0xf6, 0x93, 0xa6, 0xcf, 0x78, 0xdc, 0xd7, 0x98,
        }       
    },
    {
        "user", /* password is "user" */
        {
            0x62, 0xc9, 0x2c, 0x5b, 0xdd, 0xfd, 0x63, 0x6d,
            0xba, 0xf0, 0x2a, 0xbb, 0xd4, 0xd6, 0x51, 0x08,
            0x7f, 0x3b, 0xa7, 0x02, 0x36, 0xbb, 0xfe, 0x96,
            0x04, 0x28, 0x6f, 0xcb, 0x71, 0x4a, 0x81, 0xa9
        },        
        {
            0x56, 0x56, 0x18, 0x07, 0xd5, 0x6d, 0x41, 0xfd, 
            0x9a, 0x34, 0x77, 0x6b, 0x41, 0x57, 0x0a, 0x58, 
            0x00, 0x0b, 0x75, 0xc6, 0xd1, 0x56, 0x4b, 0x15, 
            0xa3, 0x46, 0xe5, 0x41, 0x43, 0x1f, 0x1e, 0xca, 
            0x42, 0x80, 0xac, 0x0b, 0xff, 0x98, 0x5b, 0x96, 
            0xb2, 0x98, 0x16, 0x6c, 0x8e, 0x91, 0x83, 0x05, 
            0xb0, 0x59, 0x29, 0x9c, 0x1b, 0xff, 0xe4, 0x1f, 
            0x63, 0xad, 0x48, 0x03, 0x1e, 0x46, 0xf3, 0xf9,
        }       
    },
}; 

static UserEntry const &findUser(std::string const &username)
{
    auto user = find_if(
        begin(users), 
        end(users), 
        [&](auto const &u){ return username == u.username; });

    if (user == end(users))
    {
        throw AuthenticationException(username);
    }

    return (*user);
}

static void streamBuf(std::ostream &s, uint8_t const *pBuf, uint32_t len)
{
#ifdef DEBUG
    for (uint32_t idx = 0; idx < len; idx++)
    {
        s << "0x" << setw(2) << setfill('0') << hex << static_cast<uint16_t>(pBuf[idx]) << ", ";
        if (idx % 8 == 7)
        {
            s << std::endl;
        }
    }
#endif
}

static bool getPartialHash(int idx, array<uint8_t, 64> const &pw_hash, std::string const &password, array<uint8_t, 32> &salt)
{
    bool success = false;;
    uint32_t partialHashLen = 4;

    Hasher hasher(salt, idx);
    auto optHash = hasher.getHash(reinterpret_cast<uint8_t const *>(password.c_str()), password.length());
    
    if (optHash.has_value())
    {
        auto hash = *optHash;
        success = (equal(&pw_hash[partialHashLen * idx], &pw_hash[partialHashLen * (idx + 1)], begin(hash)));

        copy(begin(hash), end(hash), begin(salt));
        streamBuf(cerr, &hash[0], partialHashLen);
    }

    return success;
}

static void checkPassword(std::string const &password)
{
    regex pwd_pattern("[a-zA-Z]+");    
    std::cmatch m;
    if (!regex_match(password.c_str(), m, pwd_pattern))
    {
        throw AuthenticationException("password must only consist of upper/lower case letters");
    }
}

void checkUser(std::string const &username, std::string const &password)
{
    UserEntry const &user = findUser(username);

    checkPassword(password);

    bool success = true;

    std::array<uint8_t, 32UL> salt = user.pw_salt;
#ifdef DEBUG
    for (size_t idx = 0; (idx < 16) /*&& success*/; idx++)
#else
    for (size_t idx = 0; (idx < 16) && success; idx++)
#endif
    {      
        success = getPartialHash(idx, user.pw_hash, password, salt) && success;
    }

    if (!success)
    {
        throw AuthenticationException(username);
    }
}