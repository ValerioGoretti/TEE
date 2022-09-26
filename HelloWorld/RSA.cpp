#include<stdio.h>
#include<time.h>
#include<stdlib.h>
#include <string.h>

inline int generatePrimeNumbers() {
    int primeNumbers[10] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29 };

    int randomIndex = rand() % 10;
    int randomValue = primeNumbers[randomIndex];
    return randomValue;
}


//e and totient must be coprime
inline int exponent(int totient, int p, int q) {

    for (int i = 2; i < totient; i++) {
        if (i % p != 0 && i % q != 0) {
            return i;
        }
    }
}
