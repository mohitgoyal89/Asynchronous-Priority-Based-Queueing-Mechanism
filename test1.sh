#!/bin/bash


echo Testing failure cases

echo 1.
echo Test case: outfile not given
./main -c -t "deflate" c1

echo 2.
echo Test case: compression and extraction both given
./main -c -x c1 x1 

echo 3.
echo Test case: two files given with overwrite option
./main -c s1 c2 -o

echo 4.
echo Test case: key not given
./main -e c2 x2 

echo 5.
echo Test case: wrong algorithm given
./main -c s1 c3 -t "deflat" -p 4

echo 6.
echo Test case: key length less than 6
./main -e s1 e1 -k "abcd" -p 1

echo 7.
echo Test case: another operation with list operation 
./main -l -e

echo 8.
echo Test case: job id not given with remove
./main -r

echo 9.
echo Test case: priority not given with change priority
./main -C 4

echo 10.
echo Test case: checksum file not given
./main -s -t "sha1" -p 8;

echo 11.
echo Test case: rename option outfile not given
./main -e s1 -k "abcdefg" -p 1 -n

echo 11.
echo Test case: wrong priority
./main -e s1 e1 -k "abcdefg" -p 14 -n
