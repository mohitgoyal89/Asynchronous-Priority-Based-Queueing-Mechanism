#!/bin/bash

echo Testing cases job

echo Test case: compression
./main -c -t "deflate" s1 c1 -p 7;

echo Test case: encryption
./main -e s1 e1 -k "mohitgoyal" -p 8; 

echo Test case: encryption with blowfish algorithm
./main -e s1 e2 -k "mohitgoyal" -t "blowfish" -p 3; 

echo Test case: checksum
./main -s s1 -t "md5" -p 10 ;

echo Test case: encryption with aes algorithm
./main -e s1 e3 -k "mohitgoyal" -t "aes" -p 3; 

echo Test case: concatenation
./main -a s1 s2 s3 a1 -p 4;

echo Test case: decryption with blowfish algorithm
./main -d enc1 d1 -k "mohitgoyal" -t "blowfish" -p 3; 

echo Test case: extraction
./main -x com1 x1 -t "deflate" -p 1;

echo Test case: list operation
./main -l;

echo Test case: change priority operation
./main -C 4 -p 2;

echo Test case: list operation
./main -l;

echo Test case: remove operation
./main -r 5;

echo Test case: list operation
./main -l;

#echo Test case: remove all operation
#./main -R;

echo Test case: list operation
./main -l;

