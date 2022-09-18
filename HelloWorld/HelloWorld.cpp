//#include "stdafx.h"
#include <stdio.h>
#include <tchar.h>
#include "sgx_urts.h"
#include <string.h>
#include "Enclave1_u.h"
#define ENCLAVE_FILE _T("Enclave1.signed.dll")
#define MAX_BUF_LEN 100

void printMenu() {
	printf("\n 1) Input a secret in the Enclave \n 2) Print the secret in the enclave \n 3) Exit\n");
}

void newSecret(sgx_enclave_id_t eid, char *sec) {
	char buffer[MAX_BUF_LEN];
	setSecret(eid, sec);
	getSecret(eid, buffer, MAX_BUF_LEN);
	printf("\n The new secret is: %s\n", buffer);
}

void prendiSecret(sgx_enclave_id_t eid) {
	char buffer[MAX_BUF_LEN];
	getSecret(eid, buffer, MAX_BUF_LEN);
	printf("\n The secret is: %s\n", buffer);
}

int main()
{
	sgx_enclave_id_t	eid;
	sgx_status_t		ret = SGX_SUCCESS;
	sgx_launch_token_t	token = { 0 };
	int updated = 0;
	char buffer[MAX_BUF_LEN] = "Hello World!";
	int selection = 1;
	bool again = true;

	//create a enclave container
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("APP:error %#x ,failed to create enclave .\n", ret);
		return -1;
	}


	while (again) {
		printMenu();
		printf("\n What do you do?:  ");
		scanf_s("%d", &selection);
		printf("Your selection is %d\n", selection);

		if (selection == 3) {
			again = false;
		}

		if (selection == 2) {
			prendiSecret(eid);
		}

		if (selection == 1) {
			char sec[100];
			printf("Insert the new secret: ");
			scanf_s("%9s", &sec, (unsigned)_countof(sec));
			newSecret(eid, sec);
		}
	}

	//distory enclave container
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	system("pause");
	return 0;
}

