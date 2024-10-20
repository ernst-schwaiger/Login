#include <iostream>
#include <string.h>

#include "Auth.h"

using namespace std;

// TODO: Rewrite such that the input  is not seen on terminal
std::string getString(std::string const &text)
{
    std::cout << text << ":";
    std::string ret; 
    std::cin >> ret;
    return ret;
}


int main(int argc, char *argv[])
{
    bool authenticated = true;
    std::string username = getString("username");
    std::string password = getString("password");

    try
    {
        checkUser(username, password);
    }
    catch (AuthenticationException const &e)
    {
        cerr << e.what();
        authenticated = false;
    }
    catch(...)
    {
        cerr << "Uknown error occurred." << std::endl;
        authenticated = false;
    }

    if  (authenticated)
    {
        if (username == "root")
        {
            cout << "Have the keys to the kingdom Your Majesty." << std::endl;
        } else if (username == "user")
        {
            cout << "Here's the shovel, now start digging, peasant!" << std::endl;
        }
    }

    return authenticated ? 0 : 1;
}