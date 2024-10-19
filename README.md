# Login
Demo App with side channel vulnerability

# HOWTO
- sudo apt install libssl-dev g++ make gdb
- in src/Makefile choose one of the CCOPTS, i.e. comment out the other one then do ``make clean && make -sj``
- two accounts exist: user (pwd: user), root (pwd:YouDidItWellDone)
- exploit/exploit.py uses the side channel to find the password for root

