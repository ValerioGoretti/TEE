#include "sgx_trts.h"
#include "Enclave1_t.h"
#include "sgx_trts.h"
#include <string.h>
#include "sgx_tprotected_fs.h"
#include "string.h"
#include "stdlib.h"

char* secret = "Hello App!";

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

size_t ecall_file_write(SGX_FILE* fp, char data[100])
{
	size_t sizeofWrite;
	size_t len = strlen(data);
	sizeofWrite = sgx_fwrite(data, sizeof(char), len, fp);

	/*for (int i = 0; i < 5; i++)
	{
		char buffer[] = { 'x' , 'c' };
		sizeofWrite += sgx_fwrite(buffer, sizeof(char), sizeof(buffer), fp);
	}*/

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

