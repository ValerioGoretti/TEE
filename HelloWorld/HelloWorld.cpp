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
	printf("\n ---------TEE MENU--------- \
				\n 0) Login	\
				\n 1) File list \
				\n 2) Read an already used file stored in the enclave  \
				\n 3) Request a new resource \
				\n 4) Exit \
				\n -------Utilty function-------- \
				\n 5) Check Policy \
				\n 6) Remove file \
				\n 7) Input a new secret in the enclave \
				\n 8) Print the secret in the enclave  \
				\n ------------------ \n");
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

/*
 * Function: readFile
 * -------------------
 * Prints the contents of a file
 * 
 * Parameters:
 *   eid: enclave id
 *   ret: return value for success or failure
 *	 filename: name of file to be read
 *
 * Returns: void
 */
void readFile(sgx_enclave_id_t eid, sgx_status_t ret, char* filename) {
	SGX_FILE* fp;
	const char* mode = "r";

	//file Open
	ret = ecall_file_open(eid, &fp, filename, mode);
	
	//Read from File
	size_t sizeOfRead = 0;
	char data[MAX_BUF_LEN];
	ret = ecall_file_read(eid, &sizeOfRead, fp, data);
	printf("Read file %s Data= %s\n", filename, data);
	
	//Close File
	int32_t fileHandle;
	ret = ecall_file_close(eid, &fileHandle, fp);
}

void removeFile(sgx_enclave_id_t eid, char* filename) {
	sgx_status_t r;
	int32_t filehandler;
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


	char filename[] = "sgx.txt";

	//Apri(o crea) -> scrivi -> leggi -> chiudi file
	//playWithFiles(ret, eid, buffer);
	
	//Rimuovi un file già creato, aggiungere passaggio del filename?
	//removeFile(eid, filename);

	createNewFile(eid, ret, buffer, filename);
	//readFile(eid, ret, filename);

	while (again) {
		char sel[MAX_BUF_LEN];
		printMenu();
		printf("\n What do you do?:  ");
		fgets(sel, sizeof(sel), stdin);
		sscanf_s(sel, "%d", &selection);
		//scanf_s("%d", &selection);
		printf("Your selection is %d\n", selection);

		if (selection == 0) {
			//TODO: Login
			printf("LOGIN DONE!");
		}

		if (selection == 1) {
			//TODO: File list
			printf("FILE LIST");
		}

		if (selection == 2) {
			//Read an aready used file stored in the enclave
			//printf("READ AN ALREADY USED FILE IN THE ENCLAVE \n");
			char name[MAX_BUF_LEN];
			printf("\n Enter the name of the file you want to read: ");
			fgets(name, sizeof(name), stdin);
			//I cut the last element of the name because the insertion \n is present
			name[strlen(name) - 1] = '\0';
			printf("The file name is: %s", name);
			readFile(eid, ret, name);
		}

		if (selection == 3) {
			//TODO: Request a new resource
			printf("REQUEST A NEW RESOURCE");
		}

		if (selection == 4) {
			//Exit to the app
			again = false;
		}

		if (selection == 5) {
			//TODO: Check policy
			//Questa funzione sarà invisibile all'utente, la inserisco perchè è utile per testarla
			printf("CHECK POLICY");
		}

		if (selection == 6) {
			//Remove file
			char name[MAX_BUF_LEN];
			printf("\n Enter the name of the file you want to delete: ");
			fgets(name, sizeof(name), stdin);
			//I cut the last element of the name because the insertion \n is present
			name[strlen(name) - 1] = '\0';
			printf("The file to delete is: %s", name);
			removeFile(eid, name);
		}

		if (selection == 7) {
			//Input a new secret in the Enclave
			char sec[100];
			printf("Insert the new secret: ");
			fgets(sec, sizeof(sec), stdin);
			printf("New secret: %s", sec);
			//scanf_s("%9s", &sec, (unsigned)_countof(sec));
			newSecret(eid, sec);
		}

		if (selection == 8) {
			//Print the enclave secret
			prendiSecret(eid);
		}
	}

	//distory enclave container
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	system("pause");
	return 0;
}

