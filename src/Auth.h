#pragma once

#include <exception>
#include <string>
#include <sstream>

class AuthenticationException
{
public:
    AuthenticationException(std::string const &username) 
    {
        std::stringstream s;
        s << "Failed to authenticate user " << username << "." << std::endl;
        msg = s.str();
    }

    virtual const char* what() const noexcept
    {
        return msg.c_str();
    }

private:
    std::string msg;
};

void checkUser(std::string const &username, std::string const &password);