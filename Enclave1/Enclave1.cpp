#include "sgx_trts.h"
#include "Enclave1_t.h"
#include "sgx_trts.h"
#include <string.h>
#include "sgx_tprotected_fs.h"
#include "string.h"
#include "stdlib.h"
#include "math.h"
#include "../../../../../../Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/ucrt/stdlib.h"
#include "../../../../../../Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/ucrt/time.h"

char* secret = "Hello App!";
long int p, q, n, t, flag, e[100], d[100], temp[100], j, m[100], en[100], i;
char msg[100];

int prime(long int);
void ce();
long int cd(long int);
void encrypt();
void decrypt();

void getSecret(char* buf, size_t len)
{
	if (len > strlen(secret))
	{
		memcpy(buf, secret, strlen(secret) + 1);
	}
}

void setSecret(char* setString)
{
	memcpy(secret, setString, strlen(setString) + 1);
}



void ecall_enclaveString(char* s, size_t len)
{
	const char* secret = "Hello Enclave!";
	if (len > strlen(secret))
	{
		memcpy(s, secret, strlen(secret) + 1);
	}
	else
	{
		memcpy(s, "false", strlen("false") + 1);
	}
}

SGX_FILE* ecall_file_open(const char* filename, const char* mode)
{
	SGX_FILE* a;
	a = sgx_fopen_auto_key(filename, mode);
	return a;
}

size_t ecall_file_write(SGX_FILE* fp, char *data)
{
	size_t sizeofWrite;
	size_t len = strlen(data);
	sizeofWrite = sgx_fwrite(data, sizeof(char), len, fp);

	for (int i = 0; i < 5; i++)
	{
		char buffer[] = { 'x' , 'c' };
		sizeofWrite += sgx_fwrite(buffer, sizeof(char), sizeof(buffer), fp);
	}

	return sizeofWrite;
}

size_t ecall_file_read(SGX_FILE* fp, char* readData)
{
	char* data;
	uint64_t startN = 1;
	sgx_fseek(fp, 0, SEEK_END);
	uint64_t finalN = sgx_ftell(fp);
	sgx_fseek(fp, 0, SEEK_SET);

	data = (char*)malloc(sizeof(char) * finalN);
	memset(data, 0, sizeof(char) * finalN);

	size_t sizeofRead = sgx_fread(data, startN, finalN, fp);
	int len = strlen(data);
	memcpy(readData, data, sizeofRead);
	return sizeofRead;
}

int32_t ecall_file_close(SGX_FILE* fp)
{
	int32_t a;
	a = sgx_fclose(fp);
	return a;
}

int32_t ecall_file_delete(char* filename)
{
	int32_t a;
	a = sgx_remove(filename);
	return a;
}

int prime(long int pr) {
    int i;
    j = sqrt(pr);
    for (i = 2; i <= j; i++) {
        if (pr % i == 0)
            return 0;
    }
    return 1;
}

void ce() {
    int k;
    k = 0;
    for (i = 2; i < t; i++) {
        if (t % i == 0)
            continue;
        flag = prime(i);
        if (flag == 1 && i != p && i != q) {
            e[k] = i;
            flag = cd(e[k]);
            if (flag > 0) {
                d[k] = flag;
                k++;
            }
            if (k == 99)
                break;
        }
    }
}

long int cd(long int x) {
    long int k = 1;
    while (1) {
        k = k + t;
        if (k % x == 0)
            return (k / x);
    }
}

void encrypt() {
    long int pt, ct, key = e[0], k, len;
    i = 0;
    len = strlen(msg);
    while (i != len) {
        pt = m[i];
        pt = pt - 96;
        k = 1;
        for (j = 0; j < key; j++) {
            k = k * pt;
            k = k % n;
        }
        temp[i] = k;
        ct = k + 96;
        en[i] = ct;
        i++;
    }
    en[i] = -1;
    /*printf("\nTHE ENCRYPTED MESSAGE IS\n");
    for (i = 0; en[i] != -1; i++)
        printf("%c", en[i]);*/
}

void decrypt() {
    long int pt, ct, key = d[0], k;
    i = 0;
    while (en[i] != -1) {
        ct = temp[i];
        k = 1;
        for (j = 0; j < key; j++) {
            k = k * ct;
            k = k % n;
        }
        pt = k + 96;
        m[i] = pt;
        i++;
    }
    m[i] = -1;
    /*printf("\nTHE DECRYPTED MESSAGE IS\n");
    for (i = 0; m[i] != -1; i++)
        printf("%c", m[i]);*/
}


int generatePrimeNumbers(int x) {
    //int primeNumbers[4] = {2, 3, 5, 7};
    int primeNumbers[10] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29 };
   
    srand(time(NULL) + (x * x));
    int randomIndex = rand() % 10;
    //printf("\n%d", randomIndex);
    int randomValue = primeNumbers[randomIndex];
    //printf("\n-> %d", randomValue);
    return randomValue;
}