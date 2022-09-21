//#include "stdafx.h"
#include <errno.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include "sgx_urts.h"
#include <string.h>
#include "Enclave1_u.h"
#include <inttypes.h>
#include "sgx_tprotected_fs.h"

#define ENCLAVE_FILE _T("Enclave1.signed.dll")
#define MAX_BUF_LEN 100


/*
 * Function: printMenu
 * -------------------
 * Prints the menu on the console application
 *
 * Returns: void
 */
void printMenu() {
	printf("\n\n\n\n ================= TEE MENU ================= \
				\n 1) File list \
				\n 2) Read an already used file stored in the enclave  \
				\n 3) Request a new resource \
				\n 4) Exit \
				\n -------Utilty function-------- \
				\n 5) Check Policy \
				\n 6) Remove file \
				\n 7) Input a new secret in the enclave \
				\n 8) Print the secret in the enclave  \
				\n 9) Add file to FileTracker (Web3 call simulation) \
				\n 10) Access to a resource (resourceAddress, Web3 call simulation when an application request a file) \
				\n ============================================ \n");
}

/*
* ________________________ newSecret _________________________
 * Function: newSecret
 * -------------------
 * This function allow the user to change the secret stored in the enclave
 *
 * Parameters:
 *   eid: enclave id
 *   sec: new secret to store
 *
 * Returns: void
 */
void newSecret(sgx_enclave_id_t eid, char *sec) {
	char buffer[MAX_BUF_LEN];
	setSecret(eid, sec);
	getSecret(eid, buffer, MAX_BUF_LEN);
	printf("\n The new secret is: %s\n", buffer);
}

/*
* ________________________ prendiSecret _________________________
 * Function: prendiSecret
 * ----------------------
 * Retrieves the secret stored in the enclave
 *
 * Parameters:
 *   eid: enclave id
 *
 * Returns: void
 */
void prendiSecret(sgx_enclave_id_t eid) {
	char buffer[MAX_BUF_LEN];
	getSecret(eid, buffer, MAX_BUF_LEN);
	printf("\n The secret is: %s\n", buffer);
}


/*
* ________________________ readFile _________________________
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
void readFile(sgx_enclave_id_t eid, char* filename) {
	SGX_FILE* fp;
	const char* mode = "r";
	sgx_status_t ret = SGX_SUCCESS;

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

/*
* ________________________ removeFile _________________________
 * Function: removeFile
 * --------------------
 * Removing a file from the enclave
 *
 * Parameters:
 *   eid: enclave id
 *	 filename: name of file to be read
 *
 * Returns: void
 */
void removeFile(sgx_enclave_id_t eid, char* filename) {
	//printf("\nFILENAME ----> %s\n", filename);
	char support[100];
	strcpy_s(support, 100, filename);
	//printf("\nsupport %s\n", support);
	sgx_status_t r;
	int32_t filehandler;
	r = ecall_file_delete(eid, &filehandler, support);
	//printf("%" PRId32 "\n", r);
	printf("\nFile removed\n");
}

/*
* ________________________ split _________________________
* Function: split
* ----------------------
* 
* 
* Structure of the tracker row  "0.ID , 1.Filename , 2.Domain , 3.maxAccess , 4.Location , 5.FinalTimestamp"
*
* Parameters:
*   
*
* Returns: 
*/
char* split(char* string1, int pos) {
	//char string1[] =		"http://folder,Hello.txt,medical,10,Rome,20";
	char seps[] = ",";
	char* token1 = NULL;
	char* next_token1 = NULL;
	char support[1000];
	strcpy_s(support, 1000, string1);
	token1 = strtok_s(support, seps, &next_token1);
	int conta = 0;
	// While there are tokens in "string1" or "string2"
	while ((token1 != NULL))
	{
		// Get next token:
		if (token1 != NULL)
		{
			if (conta == pos) {
				//printf("\nTOKEN1 -> % s",token1);
				return token1;
			}
			//printf("\n-> %s", token1);
			token1 = strtok_s(NULL, seps, &next_token1);
			conta++;
		}
	}

}

/*
* ________________________ resourceAccess _________________________
 * Function: resourceAccess
 * ----------------------
 * Access request to a resource
 *
 * Parameters:
 *   eid: enclave id
 *
 * Returns: void
 */
void resourceAccess(sgx_enclave_id_t eid, const char* id) {
	FILE* file;
	FILE* file2;
	char err[256];
	//errno_t e= fopen_s(&file,"FileTracker.txt", "r");
	//rename("C:/Users/Asus/Desktop/TESI_MAGISTRALE/TEE/HelloWorld/FileTracker.txt", "C:/Users/Asus/Desktop/TESI_MAGISTRALE/TEE/HelloWorld/FileTrackerAppo.txt");

	errno_t e = fopen_s(&file, "C:/Users/Asus/Desktop/TESI_MAGISTRALE/TEE/HelloWorld/FileTracker.txt", "r");
	errno_t e2 = fopen_s(&file2, "C:/Users/Asus/Desktop/TESI_MAGISTRALE/TEE/HelloWorld/FileTrackerAppo.txt", "w+");

	if (file == NULL || file2 == NULL) {
		strerror_s(err, 100, e);
		printf("Unable to open file, the error is: %s", err);
	}
	else {
		char buf[1000];
		while (fgets(buf, 1000, file) != NULL) {
			//printf("\n buf -> %s", buf);
			char* p = split(buf, 0);
			if (strcmp(id, p) == 0) {
				//printf("\n %s and %s are equal", id, p);
				//printf("\n buf is %s ", buf);
				char* fname = split(buf, 1);
				//printf("\n fname -> %s ", fname);
				int newA= atoi(split(buf, 3));
				if (newA<=0) {
					printf("Maximum number of accesses reached");
					removeFile(eid,fname);
				} else {
					newA--;
					//printf("newA has became %d", newA);
					char mA[100];
					sprintf_s(mA, 100, "%d", newA);
					
					fputs(id, file2);
					fputs(",", file2);
					fputs(split(buf, 1), file2);
					fputs(",", file2);
					fputs(split(buf, 2), file2);
					fputs(",", file2);
					fputs(mA, file2);
					fputs(",", file2);
					fputs(split(buf, 4), file2);
					fputs(",", file2);
					fputs(split(buf, 5), file2);
				}
			}
			else {
				//printf("\n %s and %s are DIFFERENT", id, p);
				fputs(buf, file2);
			}
		}
		fclose(file);
		fclose(file2);
		if (remove("C:/Users/Asus/Desktop/TESI_MAGISTRALE/TEE/HelloWorld/FileTracker.txt") == 0)
			printf("");
		else
			printf("Unable to delete the file");

		rename("C:/Users/Asus/Desktop/TESI_MAGISTRALE/TEE/HelloWorld/FileTrackerAppo.txt", "C:/Users/Asus/Desktop/TESI_MAGISTRALE/TEE/HelloWorld/FileTracker.txt");
	}
}


/*
* ________________________ createNewFile _________________________
 * Function: createNewFile
 * -----------------------
 * This function is called Web3. A request is made for a resource via 
   the menu (choice 3) and web3 retrieves the resource and passes it 
   to this function which will store it in the enclave.
 *
 * Parameters:
 *   eid: enclave id
 *	 ret: return value for success or failure
 *	 buffer: content of the file
 *	 filename: name of the file to be created
 *
 * Returns: void
 */
//void createNewFile(sgx_enclave_id_t eid, sgx_status_t ret, char* buffer, char* filename, char *purpose, int maxAccess, char* location, int* temporal) {
void createNewFileInEnclave(sgx_enclave_id_t eid, char* buffer, char* filename) {
	SGX_FILE* fp;
	sgx_status_t ret = SGX_SUCCESS;
	//const char* filename = "SGX_File_Protection_System.txt";
	const char* mode = "w+";

	//file Open
	ret = ecall_file_open(eid, &fp, filename, mode);

	//Write buffer value into the file
	size_t sizeOfWrite = 0;
	ret = ecall_file_write(eid, &sizeOfWrite, fp, buffer);
	//printf("Size of Write=  %d\n", sizeOfWrite);

	int32_t fileHandle;
	ret = ecall_file_close(eid, &fileHandle, fp);
}


/*
* ________________________ AddFile _________________________
 * Function: AddFile
 * ----------------------
 * Add the new resourcers to the FileTracker
 *
 * Parameters:
 *   eid: enclave id
 *
 * Returns: void
 */
void AddFile(sgx_enclave_id_t eid, char* buffer, char* id, char* filename, char* purpose, int maxAccess,  char* location, int temporal) {
	FILE* file;
	char err[256];
	//errno_t e= fopen_s(&file,"FileTracker.txt", "r");
	errno_t e = fopen_s(&file, "C:/Users/Asus/Desktop/TESI_MAGISTRALE/TEE/HelloWorld/FileTracker.txt", "a");

	if (file == NULL) {
		strerror_s(err, 100, e);
		printf("Unable to open file, the error is: %s", err);
	}
	else {
		char mA[100];
		char tem[100];
		sprintf_s(mA, 100, "%d", maxAccess);
		sprintf_s(tem, 100, "%d", temporal);

		fputs(id, file);
		fputs(",", file);
		fputs(filename, file);
		fputs(",", file);
		fputs(purpose, file);
		fputs(",", file);
		fputs(mA, file);
		fputs(",", file);
		fputs(location, file);
		fputs(",", file);
		fputs(tem, file);
		fputs("\n", file);
		fclose(file);
	}
	createNewFileInEnclave(eid, buffer, filename);
}

/*
* ________________________ fileTrackerList _________________________
 * Function: fileTrackerList
 * -----------------------
 * Manage the file tracker
 *
 * Parameters:
 *    
 *
 * Returns: void
 */
void fileTrackerList() {
	FILE* file;
	char err[256];
	errno_t e= fopen_s(&file,"C:/Users/Asus/Desktop/TESI_MAGISTRALE/TEE/HelloWorld/FileTracker.txt", "r");

	if (file == NULL) {
		strerror_s(err, 100, e);
		printf("Unable to open file, the error is: %s", err);
	}else {
		char buf[1000];
		while (fgets(buf, 1000, file) != NULL) {
			printf("%s", buf);
		}
		fclose(file);
	}
}


/*
*________________________ main _________________________
*/
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


	// filename[] = "sgx.txt";
	//createNewFile(eid, ret, buffer, filename);
	//Apri(o crea) -> scrivi -> leggi -> chiudi file
	//playWithFiles(ret, eid, buffer);
	
	//Rimuovi un file già creato, aggiungere passaggio del filename?
	//removeFile(eid, filename);

	
	//readFile(eid, ret, filename);


	while (again) {
		char sel[MAX_BUF_LEN];
		printMenu();
		printf("\nWhat do you do?:  ");
		fgets(sel, sizeof(sel), stdin);
		sscanf_s(sel, "%d", &selection);
		//scanf_s("%d", &selection);
		printf("Your selection is %d\n", selection);

		if (selection == 1) {
			//TODO: File list
			printf("\n___ FILE LIST ___ \n");
			fileTrackerList();
		}

		if (selection == 2) {
			//Read an aready used file stored in the enclave
			//printf("READ AN ALREADY USED FILE IN THE ENCLAVE \n");
			char name[MAX_BUF_LEN];
			printf("\nEnter the name of the file you want to read: ");
			fgets(name, sizeof(name), stdin);
			//I cut the last element of the name because the insertion \n is present
			name[strlen(name) - 1] = '\0';
			printf("The file name is: %s", name);
			readFile(eid, name);
		}

		if (selection == 3) {
			//TODO: Request a new resource - IMPLEMENTED, I need to Web3 for the string provided by the owner file
			/*
			In this task, a file is requested from the blockchain. 
			Web3 reads the file and sends me the content string, which is 
			then passed to the function to create a new file together with 
			the file name.
			*/
			printf("REQUEST A NEW RESOURCE");
			char name[MAX_BUF_LEN];
			char content[MAX_BUF_LEN];  //String passed by Web3
			printf("\n Which resource do you want to request? ");
			fgets(name, sizeof(name), stdin);
			//I cut the last element of the name because the insertion \n is present
			name[strlen(name) - 1] = '\0';
			printf("Resource %s's request forwarded to Web3...", name);
		}

		if (selection == 4) {
			//Exit to the app
			again = false;
		}

		if (selection == 5) {
			//TODO: Check policy
			//Questo task sarà invisibile all'utente, la inserisco perchè è utile testarla da menu
			printf("CHECK POLICY");
		}


		if (selection == 6) {
			//Remove file
			char name[MAX_BUF_LEN];
			printf("\nEnter the name of the file you want to delete: ");
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

		if (selection == 9) {
			//Add file to filetracker 
			//Questo task è chiamato da WEB3, l'utilizzo nel menù è solo per una questione di comodità
			//I seguenti campi verranno passati da web3 in base al nome del file(identificativo) e alle policy, 
			//li inseriamo poichè non è ancora presente una comunicazione tramite web3
			char name[MAX_BUF_LEN];
			char content[MAX_BUF_LEN];
			char id[MAX_BUF_LEN];
			char domain[MAX_BUF_LEN];
			char location[MAX_BUF_LEN];
			char maxA_c[MAX_BUF_LEN];
			char time_c[MAX_BUF_LEN];
			int maxA_i=1, time_i=1;

			printf("\nEnter the ID of the file you want to add: ");
			fgets(id, sizeof(id), stdin);
			//I cut the last element of the name because the insertion \n is present
			id[strlen(id) - 1] = '\0';

			printf("\nEnter the name of the file you want to add: ");
			fgets(name, sizeof(name), stdin);
			//I cut the last element of the name because the insertion \n is present
			name[strlen(name) - 1] = '\0';

			printf("\nEnter the content of the file: ");
			fgets(content, sizeof(content), stdin);
			//I cut the last element of the name because the insertion \n is present
			content[strlen(content) - 1] = '\0';

			printf("\nEnter the name of the domain: ");
			fgets(domain, sizeof(domain), stdin);
			//I cut the last element of the name because the insertion \n is present
			domain[strlen(domain) - 1] = '\0';

			printf("\nEnter the name of the location: ");
			fgets(location, sizeof(location), stdin);
			//I cut the last element of the name because the insertion \n is present
			location[strlen(location) - 1] = '\0';

			printf("\nEnter the age: ");
			fgets(maxA_c, sizeof(maxA_c), stdin);
			//I cut the last element of the name because the insertion \n is present
			maxA_c[strlen(maxA_c) - 1] = '\0';
			maxA_i = atoi(maxA_c);

			printf("\nEnter the date: ");
			fgets(time_c, sizeof(time_c), stdin);
			//I cut the last element of the name because the insertion \n is present
			time_c[strlen(time_c) - 1] = '\0';
			time_i = atoi(time_c);

			AddFile(eid, content, id,name, domain, maxA_i, location, time_i);
			//AddFile("id1","Hello", "medical", 10, "Rome", 20);
		}

		if (selection == 10) {
			//Access to a resource 
			//Questo task è chiamato da WEB3, l'utilizzo nel menù è solo per una questione di comodità
			//I seguenti campi verranno passati da web3 in base al nome del file(identificativo) e alle policy, 
			//li inseriamo poichè non è ancora presente una comunicazione tramite web3
			char id[MAX_BUF_LEN];

			printf("\nEnter the ID of the file you want to access: ");
			fgets(id, sizeof(id), stdin);
			//I cut the last element of the name because the insertion \n is present
			id[strlen(id) - 1] = '\0';

			resourceAccess(eid, id);
		}
	}

	//distory enclave container
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	system("pause");
	return 0;
}

