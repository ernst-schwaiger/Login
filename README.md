# Login
Demo App with side channel vulnerability

# HOWTO
- for the compiler, libraries and make, do ``sudo apt install libssl-dev g++ make gdb``
- in src/Makefile choose one of the CCOPTS, i.e. comment out the other one, then do ``make clean && make -sj``
- two accounts exist: user (pwd: user), root (pwd:YouDidItWellDone)
- exploit/exploit.py uses the side channel to find the password for root, currently starts failing towards the end of the password, needs to be fixed.
- for changing the hashing algorithm or password of a user, compile with -DDEBUG, run ./login for the user(s) with the desired password (which will fail), then replace the users pw_hash field in Auth.cpp with the one output on the console. Recompile, password should work again.

# TODO
- Add incorrect Exception handling that can be exploited
