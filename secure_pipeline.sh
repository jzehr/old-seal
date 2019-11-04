#!/bin/bash

cd native/bin/

printf "\n~~Encrypting site A~~\n"
./site_A

printf "\n~~Encrypting site B~~\n"
./site_B

printf "\n~~Comparing Sites A and B~~\n"
./t_compare

printf "\n~~Results of run: \n"
./read_in_hamming
