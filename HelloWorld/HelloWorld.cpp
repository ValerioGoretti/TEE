//#include "stdafx.h"
#include <errno.h>
#include <stdio.h>
#include <tchar.h>
#include "sgx_urts.h"
#include <string.h>
#include "Enclave1_u.h"
#include <inttypes.h>
#include "sgx_tprotected_fs.h"

#define ENCLAVE_FILE _T("Enclave1.signed.dll")
#define MAX_BUF_LEN 100

void printMenu() {
	printf("\n 1) Input a secret in the Enclave \n 2) Print the secret in the enclave \n 3) Exit\n 4) Open file");
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

void createNewFile(sgx_enclave_id_t eid, sgx_status_t ret, char* buffer, char* filename) {
	SGX_FILE* fp;
	//const char* filename = "SGX_File_Protection_System.txt";
	const char* mode = "w+";

	//file Open
	ret = ecall_file_open(eid, &fp, filename, mode);

	//Write buffer value into the file
	size_t sizeOfWrite = 0;
	ret = ecall_file_write(eid, &sizeOfWrite, fp, buffer);
	printf("Size of Write=  %d\n", sizeOfWrite);

	int32_t fileHandle;
	ret = ecall_file_close(eid, &fileHandle, fp);
}

void readFile(sgx_enclave_id_t eid, sgx_status_t ret, char* buffer, char* filename) {
	SGX_FILE* fp;
	const char* mode = "r";

	//file Open
	ret = ecall_file_open(eid, &fp, filename, mode);
	
	//Read from File
	size_t sizeOfRead = 0;
	char data[100];
	ret = ecall_file_read(eid, &sizeOfRead, fp, data);
	printf("Read file %s Data= %s\n", filename, data);
	int32_t fileHandle;
	ret = ecall_file_close(eid, &fileHandle, fp);
}

/*
void playWithFiles(sgx_status_t ret, sgx_enclave_id_t eid, char* buffer) {
	SGX_FILE* fp;
	const char* filename = "SGX_File_Protection_System.txt";
	const char* mode = "w+";
	//const char* mode = "r";

	//file Open
	ret = ecall_file_open(eid, &fp, filename, mode);

	//Get Enclve Secret
	ret = ecall_enclaveString(eid, buffer, MAX_BUF_LEN);
	printf("Enclave Secret Value: %s\n", buffer);

	//Write to file
	size_t sizeOfWrite = 0;
	ret = ecall_file_write(eid, &sizeOfWrite, fp, buffer);
	printf("Size of Write=  %d\n", sizeOfWrite);

	//Read from File
	size_t sizeOfRead = 0;
	char data[100];
	ret = ecall_file_read(eid, &sizeOfRead, fp, data);
	printf("Size of Read= %d\n", sizeOfRead);


	data[sizeOfRead] = '\0';
	printf("Read file %s Data= %s\n", filename, data);

	int32_t fileHandle;
	ret = ecall_file_close(eid, &fileHandle, fp);
}*/

void removeFile(sgx_enclave_id_t eid) {
	sgx_status_t r;
	int32_t filehandler;
	char filename[] = "SGX_File_Protection_System.txt";
	r = ecall_file_delete(eid, &filehandler, filename);
	printf("%" PRId32 "\n", r);
	printf("%s REMOVED", filename);
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

	//Apri(o crea) -> scrivi -> leggi -> chiudi file
	//playWithFiles(ret, eid, buffer);
	
	//Rimuovi un file già creato, aggiungere passaggio del filename?
	//removeFile(eid);
	char filename[] = "SGX_File_Protection_System.txt";

	createNewFile(eid, ret, buffer, filename);
	readFile(eid, ret, buffer, filename);

	while (again) {
		char sel[MAX_BUF_LEN];
		printMenu();
		printf("\n What do you do?:  ");
		fgets(sel, sizeof(sel), stdin);
		sscanf_s(sel, "%d", &selection);
		//scanf_s("%d", &selection);
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
			fgets(sec, sizeof(sec), stdin);
			printf("New secret: %s", sec);
			//scanf_s("%9s", &sec, (unsigned)_countof(sec));
			//newSecret(eid, sec);
		}

		if (selection == 4) {
			printf("The file content is: ");
			//passFile();
		}
	}

	//distory enclave container
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	system("pause");
	return 0;
}

