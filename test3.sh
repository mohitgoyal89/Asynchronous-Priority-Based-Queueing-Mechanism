#!/bin/bash

echo Testing cases KERNEL LEVEL

echo Test case: encryption with overwrite option
./main -e test_overwrite -k "mohitgoyal" -p 8 -o; 

echo Test case: encryption with blowfish algorithm with rename option
./main -e test_old test_new -k "mohitgoyal" -t "blowfish" -p 3 -n; 

echo Test case: failure case: compression infile not present
./main -c -t "deflate" infilen c1

echo Test case: failure case: decryption with different will result in failure
./main -d test_overwrite -k "mohitgoy" -p 8 -o;
