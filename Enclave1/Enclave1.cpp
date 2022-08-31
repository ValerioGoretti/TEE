#include "sgx_trts.h"
#include "Enclave1_t.h"
#include "sgx_trts.h"
#include <string.h>

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