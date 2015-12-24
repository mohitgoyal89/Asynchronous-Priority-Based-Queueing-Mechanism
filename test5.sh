#!/bin/bash

echo Testing cases job

echo Test case: encryption
./main -l;

./main -e s1 e1 -k "mohitgoyal" -p 4; 

./main -e s1 e2 -k "mohitgoyal" -p 6; 

./main -e s1 e3 -k "mohitgoyal" -p 7; 

./main -e s1 e4 -k "mohitgoyal" -p 3; 

./main -e s1 e5 -k "mohitgoyal" -p 9; 

./main -e s1 e6 -k "mohitgoyal" -p 1; 

./main -e s1 e7 -k "mohitgoyal" -p 3; 

./main -e s1 e8 -k "mohitgoyal" -p 3; 

./main -e s1 e9 -k "mohitgoyal" -p 8; 

./main -e s1 e10 -k "mohitgoyal" -p 1; 

./main -e s1 e11 -k "mohitgoyal" -p 7; 

./main -e s1 e12 -k "mohitgoyal" -p 6; 

./main -e s1 e13 -k "mohitgoyal" -p 3; 

./main -e s1 e14 -k "mohitgoyal" -p 2; 

./main -e s1 e15 -k "mohitgoyal" -p 10; 

echo Test case: list operation
./main -l;

