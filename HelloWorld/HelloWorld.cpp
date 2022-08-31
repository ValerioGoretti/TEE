//#include "stdafx.h"
#include <stdio.h>
#include <tchar.h>
#include "sgx_urts.h"
#include <string.h>
#include "Enclave1_u.h"
#define ENCLAVE_FILE _T("Enclave1.signed.dll")
#define MAX_BUF_LEN 100
int main()
{
	sgx_enclave_id_t	eid;
	sgx_status_t		ret = SGX_SUCCESS;
	sgx_launch_token_t	token = { 0 };
	int updated = 0;
	char buffer[MAX_BUF_LEN] = "Hello World!";


	//create a enclave container
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token,
		&updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("APP:error %#x ,failed to create enclave .\n", ret);
		return -1;
	}



	//Enclave CALL(ECALL) 
	printf("\n Buffer BEFORE: %s\n", buffer);
	getSecret(eid, buffer, MAX_BUF_LEN);
	printf("\n Nell'enclave c'è: %s\n", buffer);
	char b1[MAX_BUF_LEN] = "NUOVO SEGRETO";
	setSecret(eid, b1);
	getSecret(eid, buffer, MAX_BUF_LEN);
	printf("\n DOPO nell'enclave c'è: %s\n", buffer);

	getchar();
	//distory enclave container
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	system("pause");
	getchar();
	return 0;
}
