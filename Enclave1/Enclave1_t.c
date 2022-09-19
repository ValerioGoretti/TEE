#include "Enclave1_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_getSecret_t {
	char* ms_buf;
	size_t ms_len;
} ms_getSecret_t;

typedef struct ms_setSecret_t {
	char* ms_setString;
	size_t ms_setString_len;
} ms_setSecret_t;

typedef struct ms_ecall_enclaveString_t {
	char* ms_s;
	size_t ms_len;
} ms_ecall_enclaveString_t;

typedef struct ms_ecall_file_open_t {
	SGX_FILE* ms_retval;
	const char* ms_filename;
	size_t ms_filename_len;
	const char* ms_mode;
	size_t ms_mode_len;
} ms_ecall_file_open_t;

typedef struct ms_ecall_file_write_t {
	size_t ms_retval;
	SGX_FILE* ms_fp;
	char* ms_data;
} ms_ecall_file_write_t;

typedef struct ms_ecall_file_read_t {
	size_t ms_retval;
	SGX_FILE* ms_fp;
	char* ms_readData;
	size_t ms_readData_len;
} ms_ecall_file_read_t;

typedef struct ms_ecall_file_close_t {
	int32_t ms_retval;
	SGX_FILE* ms_fp;
} ms_ecall_file_close_t;

typedef struct ms_ecall_file_delete_t {
	int32_t ms_retval;
	char* ms_filename;
	size_t ms_filename_len;
} ms_ecall_file_delete_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_u_sgxprotectedfs_exclusive_file_open_t {
	void* ms_retval;
	const char* ms_filename;
	uint8_t ms_read_only;
	int64_t* ms_file_size;
	int32_t* ms_error_code;
} ms_u_sgxprotectedfs_exclusive_file_open_t;

typedef struct ms_u_sgxprotectedfs_check_if_file_exists_t {
	uint8_t ms_retval;
	const char* ms_filename;
} ms_u_sgxprotectedfs_check_if_file_exists_t;

typedef struct ms_u_sgxprotectedfs_fread_node_t {
	int32_t ms_retval;
	void* ms_f;
	uint64_t ms_node_number;
	uint8_t* ms_buffer;
	uint32_t ms_node_size;
} ms_u_sgxprotectedfs_fread_node_t;

typedef struct ms_u_sgxprotectedfs_fwrite_node_t {
	int32_t ms_retval;
	void* ms_f;
	uint64_t ms_node_number;
	uint8_t* ms_buffer;
	uint32_t ms_node_size;
} ms_u_sgxprotectedfs_fwrite_node_t;

typedef struct ms_u_sgxprotectedfs_fclose_t {
	int32_t ms_retval;
	void* ms_f;
} ms_u_sgxprotectedfs_fclose_t;

typedef struct ms_u_sgxprotectedfs_fflush_t {
	uint8_t ms_retval;
	void* ms_f;
} ms_u_sgxprotectedfs_fflush_t;

typedef struct ms_u_sgxprotectedfs_remove_t {
	int32_t ms_retval;
	const char* ms_filename;
} ms_u_sgxprotectedfs_remove_t;

typedef struct ms_u_sgxprotectedfs_recovery_file_open_t {
	void* ms_retval;
	const char* ms_filename;
} ms_u_sgxprotectedfs_recovery_file_open_t;

typedef struct ms_u_sgxprotectedfs_fwrite_recovery_node_t {
	uint8_t ms_retval;
	void* ms_f;
	uint8_t* ms_data;
	uint32_t ms_data_length;
} ms_u_sgxprotectedfs_fwrite_recovery_node_t;

typedef struct ms_u_sgxprotectedfs_do_file_recovery_t {
	int32_t ms_retval;
	const char* ms_filename;
	const char* ms_recovery_filename;
	uint32_t ms_node_size;
} ms_u_sgxprotectedfs_do_file_recovery_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#pragma warning(disable: 4090)
#endif

static sgx_status_t SGX_CDECL sgx_getSecret(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_getSecret_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_getSecret_t* ms = SGX_CAST(ms_getSecret_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = ms->ms_buf;
	size_t _tmp_len = ms->ms_len;
	size_t _len_buf = _tmp_len;
	char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_buf = (char*)malloc(_len_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_buf, 0, _len_buf);
	}
	getSecret(_in_buf, _tmp_len);
	if (_in_buf) {
		if (MEMCPY_S(_tmp_buf, _len_buf, _in_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_setSecret(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_setSecret_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_setSecret_t* ms = SGX_CAST(ms_setSecret_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_setString = ms->ms_setString;
	size_t _len_setString = ms->ms_setString_len ;
	char* _in_setString = NULL;

	CHECK_UNIQUE_POINTER(_tmp_setString, _len_setString);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_setString != NULL && _len_setString != 0) {
		_in_setString = (char*)malloc(_len_setString);
		if (_in_setString == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_setString, _len_setString, _tmp_setString, _len_setString)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_setString[_len_setString - 1] = '\0';
		if (_len_setString != strlen(_in_setString) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	setSecret(_in_setString);

err:
	if (_in_setString) free(_in_setString);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_enclaveString(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_enclaveString_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_enclaveString_t* ms = SGX_CAST(ms_ecall_enclaveString_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_s = ms->ms_s;
	size_t _tmp_len = ms->ms_len;
	size_t _len_s = _tmp_len;
	char* _in_s = NULL;

	CHECK_UNIQUE_POINTER(_tmp_s, _len_s);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_s != NULL && _len_s != 0) {
		if ( _len_s % sizeof(*_tmp_s) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_s = (char*)malloc(_len_s)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_s, 0, _len_s);
	}
	ecall_enclaveString(_in_s, _tmp_len);
	if (_in_s) {
		if (MEMCPY_S(_tmp_s, _len_s, _in_s, _len_s)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_s) free(_in_s);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_file_open(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_file_open_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_file_open_t* ms = SGX_CAST(ms_ecall_file_open_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_filename = ms->ms_filename;
	size_t _len_filename = ms->ms_filename_len ;
	char* _in_filename = NULL;
	const char* _tmp_mode = ms->ms_mode;
	size_t _len_mode = ms->ms_mode_len ;
	char* _in_mode = NULL;
	SGX_FILE* _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_filename, _len_filename);
	CHECK_UNIQUE_POINTER(_tmp_mode, _len_mode);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_filename != NULL && _len_filename != 0) {
		_in_filename = (char*)malloc(_len_filename);
		if (_in_filename == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_filename, _len_filename, _tmp_filename, _len_filename)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_filename[_len_filename - 1] = '\0';
		if (_len_filename != strlen(_in_filename) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_mode != NULL && _len_mode != 0) {
		_in_mode = (char*)malloc(_len_mode);
		if (_in_mode == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_mode, _len_mode, _tmp_mode, _len_mode)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_mode[_len_mode - 1] = '\0';
		if (_len_mode != strlen(_in_mode) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_file_open((const char*)_in_filename, (const char*)_in_mode);
	if (MEMCPY_S(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_filename) free(_in_filename);
	if (_in_mode) free(_in_mode);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_file_write(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_file_write_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_file_write_t* ms = SGX_CAST(ms_ecall_file_write_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	SGX_FILE* _tmp_fp = ms->ms_fp;
	char* _tmp_data = ms->ms_data;
	size_t _len_data = 100 * sizeof(char);
	char* _in_data = NULL;
	size_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (char*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_file_write(_tmp_fp, _in_data);
	if (MEMCPY_S(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_data) free(_in_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_file_read(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_file_read_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_file_read_t* ms = SGX_CAST(ms_ecall_file_read_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	SGX_FILE* _tmp_fp = ms->ms_fp;
	char* _tmp_readData = ms->ms_readData;
	size_t _len_readData = ms->ms_readData_len ;
	char* _in_readData = NULL;
	size_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_readData, _len_readData);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_readData != NULL && _len_readData != 0) {
		_in_readData = (char*)malloc(_len_readData);
		if (_in_readData == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_readData, _len_readData, _tmp_readData, _len_readData)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_readData[_len_readData - 1] = '\0';
		if (_len_readData != strlen(_in_readData) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_file_read(_tmp_fp, _in_readData);
	if (MEMCPY_S(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_readData)
	{
		_in_readData[_len_readData - 1] = '\0';
		_len_readData = strlen(_in_readData) + 1;
		if (MEMCPY_S((void*)_tmp_readData, _len_readData, _in_readData, _len_readData)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_readData) free(_in_readData);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_file_close(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_file_close_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_file_close_t* ms = SGX_CAST(ms_ecall_file_close_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	SGX_FILE* _tmp_fp = ms->ms_fp;
	int32_t _in_retval;


	_in_retval = ecall_file_close(_tmp_fp);
	if (MEMCPY_S(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_file_delete(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_file_delete_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_file_delete_t* ms = SGX_CAST(ms_ecall_file_delete_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_filename = ms->ms_filename;
	size_t _len_filename = ms->ms_filename_len ;
	char* _in_filename = NULL;
	int32_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_filename, _len_filename);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_filename != NULL && _len_filename != 0) {
		_in_filename = (char*)malloc(_len_filename);
		if (_in_filename == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_filename, _len_filename, _tmp_filename, _len_filename)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_filename[_len_filename - 1] = '\0';
		if (_len_filename != strlen(_in_filename) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_file_delete(_in_filename);
	if (MEMCPY_S(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_filename) free(_in_filename);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[8];
} g_ecall_table = {
	8,
	{
		{(void*)(uintptr_t)sgx_getSecret, 0, 0},
		{(void*)(uintptr_t)sgx_setSecret, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_enclaveString, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_file_open, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_file_write, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_file_read, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_file_close, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_file_delete, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[19][8];
} g_dyn_entry_table = {
	19,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (MEMCPY_S(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		MEMSET(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (MEMCPY_S(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (MEMCPY_S(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (MEMCPY_S(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (MEMCPY_S(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (MEMCPY_S(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (MEMCPY_S(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (MEMCPY_S(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (MEMCPY_S(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (MEMCPY_S(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_exclusive_file_open(void** retval, const char* filename, uint8_t read_only, int64_t* file_size, int32_t* error_code)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_file_size = sizeof(int64_t);
	size_t _len_error_code = sizeof(int32_t);

	ms_u_sgxprotectedfs_exclusive_file_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_exclusive_file_open_t);
	void *__tmp = NULL;

	void *__tmp_file_size = NULL;
	void *__tmp_error_code = NULL;

	CHECK_ENCLAVE_POINTER(filename, _len_filename);
	CHECK_ENCLAVE_POINTER(file_size, _len_file_size);
	CHECK_ENCLAVE_POINTER(error_code, _len_error_code);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (file_size != NULL) ? _len_file_size : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error_code != NULL) ? _len_error_code : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_exclusive_file_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_exclusive_file_open_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_exclusive_file_open_t);

	if (filename != NULL) {
		if (MEMCPY_S(&ms->ms_filename, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (MEMCPY_S(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}

	if (MEMCPY_S(&ms->ms_read_only, sizeof(ms->ms_read_only), &read_only, sizeof(read_only))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (file_size != NULL) {
		if (MEMCPY_S(&ms->ms_file_size, sizeof(int64_t*), &__tmp, sizeof(int64_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_file_size = __tmp;
		if (_len_file_size % sizeof(*file_size) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		MEMSET(__tmp_file_size, 0, _len_file_size);
		__tmp = (void *)((size_t)__tmp + _len_file_size);
		ocalloc_size -= _len_file_size;
	} else {
		ms->ms_file_size = NULL;
	}

	if (error_code != NULL) {
		if (MEMCPY_S(&ms->ms_error_code, sizeof(int32_t*), &__tmp, sizeof(int32_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_error_code = __tmp;
		if (_len_error_code % sizeof(*error_code) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		MEMSET(__tmp_error_code, 0, _len_error_code);
		__tmp = (void *)((size_t)__tmp + _len_error_code);
		ocalloc_size -= _len_error_code;
	} else {
		ms->ms_error_code = NULL;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (file_size) {
			if (memcpy_s((void*)file_size, _len_file_size, __tmp_file_size, _len_file_size)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error_code) {
			if (memcpy_s((void*)error_code, _len_error_code, __tmp_error_code, _len_error_code)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_check_if_file_exists(uint8_t* retval, const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_u_sgxprotectedfs_check_if_file_exists_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_check_if_file_exists_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(filename, _len_filename);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_check_if_file_exists_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_check_if_file_exists_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_check_if_file_exists_t);

	if (filename != NULL) {
		if (MEMCPY_S(&ms->ms_filename, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (MEMCPY_S(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}

	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fread_node(int32_t* retval, void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = node_size;

	ms_u_sgxprotectedfs_fread_node_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fread_node_t);
	void *__tmp = NULL;

	void *__tmp_buffer = NULL;

	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fread_node_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fread_node_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_fread_node_t);

	if (MEMCPY_S(&ms->ms_f, sizeof(ms->ms_f), &f, sizeof(f))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (MEMCPY_S(&ms->ms_node_number, sizeof(ms->ms_node_number), &node_number, sizeof(node_number))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buffer != NULL) {
		if (MEMCPY_S(&ms->ms_buffer, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buffer = __tmp;
		if (_len_buffer % sizeof(*buffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		MEMSET(__tmp_buffer, 0, _len_buffer);
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}

	if (MEMCPY_S(&ms->ms_node_size, sizeof(ms->ms_node_size), &node_size, sizeof(node_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buffer) {
			if (memcpy_s((void*)buffer, _len_buffer, __tmp_buffer, _len_buffer)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_node(int32_t* retval, void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = node_size;

	ms_u_sgxprotectedfs_fwrite_node_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fwrite_node_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fwrite_node_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fwrite_node_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_fwrite_node_t);

	if (MEMCPY_S(&ms->ms_f, sizeof(ms->ms_f), &f, sizeof(f))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (MEMCPY_S(&ms->ms_node_number, sizeof(ms->ms_node_number), &node_number, sizeof(node_number))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buffer != NULL) {
		if (MEMCPY_S(&ms->ms_buffer, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_buffer % sizeof(*buffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (MEMCPY_S(__tmp, ocalloc_size, buffer, _len_buffer)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}

	if (MEMCPY_S(&ms->ms_node_size, sizeof(ms->ms_node_size), &node_size, sizeof(node_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fclose(int32_t* retval, void* f)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sgxprotectedfs_fclose_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fclose_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fclose_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fclose_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_fclose_t);

	if (MEMCPY_S(&ms->ms_f, sizeof(ms->ms_f), &f, sizeof(f))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fflush(uint8_t* retval, void* f)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sgxprotectedfs_fflush_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fflush_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fflush_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fflush_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_fflush_t);

	if (MEMCPY_S(&ms->ms_f, sizeof(ms->ms_f), &f, sizeof(f))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_remove(int32_t* retval, const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_u_sgxprotectedfs_remove_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_remove_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(filename, _len_filename);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_remove_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_remove_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_remove_t);

	if (filename != NULL) {
		if (MEMCPY_S(&ms->ms_filename, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (MEMCPY_S(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}

	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_recovery_file_open(void** retval, const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_u_sgxprotectedfs_recovery_file_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_recovery_file_open_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(filename, _len_filename);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_recovery_file_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_recovery_file_open_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_recovery_file_open_t);

	if (filename != NULL) {
		if (MEMCPY_S(&ms->ms_filename, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (MEMCPY_S(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}

	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_recovery_node(uint8_t* retval, void* f, uint8_t* data, uint32_t data_length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data = data_length * sizeof(uint8_t);

	ms_u_sgxprotectedfs_fwrite_recovery_node_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fwrite_recovery_node_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(data, _len_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (data != NULL) ? _len_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fwrite_recovery_node_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fwrite_recovery_node_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_fwrite_recovery_node_t);

	if (MEMCPY_S(&ms->ms_f, sizeof(ms->ms_f), &f, sizeof(f))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (data != NULL) {
		if (MEMCPY_S(&ms->ms_data, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_data % sizeof(*data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (MEMCPY_S(__tmp, ocalloc_size, data, _len_data)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_data);
		ocalloc_size -= _len_data;
	} else {
		ms->ms_data = NULL;
	}

	if (MEMCPY_S(&ms->ms_data_length, sizeof(ms->ms_data_length), &data_length, sizeof(data_length))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_do_file_recovery(int32_t* retval, const char* filename, const char* recovery_filename, uint32_t node_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_recovery_filename = recovery_filename ? strlen(recovery_filename) + 1 : 0;

	ms_u_sgxprotectedfs_do_file_recovery_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_do_file_recovery_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(filename, _len_filename);
	CHECK_ENCLAVE_POINTER(recovery_filename, _len_recovery_filename);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (recovery_filename != NULL) ? _len_recovery_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_do_file_recovery_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_do_file_recovery_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_do_file_recovery_t);

	if (filename != NULL) {
		if (MEMCPY_S(&ms->ms_filename, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (MEMCPY_S(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}

	if (recovery_filename != NULL) {
		if (MEMCPY_S(&ms->ms_recovery_filename, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_recovery_filename % sizeof(*recovery_filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (MEMCPY_S(__tmp, ocalloc_size, recovery_filename, _len_recovery_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_recovery_filename);
		ocalloc_size -= _len_recovery_filename;
	} else {
		ms->ms_recovery_filename = NULL;
	}

	if (MEMCPY_S(&ms->ms_node_size, sizeof(ms->ms_node_size), &node_size, sizeof(node_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sid = sizeof(uint32_t);
	size_t _len_dh_msg1 = dh_msg1_size;

	ms_create_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_create_session_ocall_t);
	void *__tmp = NULL;

	void *__tmp_sid = NULL;
	void *__tmp_dh_msg1 = NULL;

	CHECK_ENCLAVE_POINTER(sid, _len_sid);
	CHECK_ENCLAVE_POINTER(dh_msg1, _len_dh_msg1);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sid != NULL) ? _len_sid : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dh_msg1 != NULL) ? _len_dh_msg1 : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_create_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_create_session_ocall_t));
	ocalloc_size -= sizeof(ms_create_session_ocall_t);

	if (sid != NULL) {
		if (MEMCPY_S(&ms->ms_sid, sizeof(uint32_t*), &__tmp, sizeof(uint32_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_sid = __tmp;
		if (_len_sid % sizeof(*sid) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		MEMSET(__tmp_sid, 0, _len_sid);
		__tmp = (void *)((size_t)__tmp + _len_sid);
		ocalloc_size -= _len_sid;
	} else {
		ms->ms_sid = NULL;
	}

	if (dh_msg1 != NULL) {
		if (MEMCPY_S(&ms->ms_dh_msg1, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_dh_msg1 = __tmp;
		if (_len_dh_msg1 % sizeof(*dh_msg1) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		MEMSET(__tmp_dh_msg1, 0, _len_dh_msg1);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
		ocalloc_size -= _len_dh_msg1;
	} else {
		ms->ms_dh_msg1 = NULL;
	}

	if (MEMCPY_S(&ms->ms_dh_msg1_size, sizeof(ms->ms_dh_msg1_size), &dh_msg1_size, sizeof(dh_msg1_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (MEMCPY_S(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (sid) {
			if (memcpy_s((void*)sid, _len_sid, __tmp_sid, _len_sid)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (dh_msg1) {
			if (memcpy_s((void*)dh_msg1, _len_dh_msg1, __tmp_dh_msg1, _len_dh_msg1)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = dh_msg2_size;
	size_t _len_dh_msg3 = dh_msg3_size;

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	void *__tmp_dh_msg3 = NULL;

	CHECK_ENCLAVE_POINTER(dh_msg2, _len_dh_msg2);
	CHECK_ENCLAVE_POINTER(dh_msg3, _len_dh_msg3);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dh_msg2 != NULL) ? _len_dh_msg2 : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dh_msg3 != NULL) ? _len_dh_msg3 : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));
	ocalloc_size -= sizeof(ms_exchange_report_ocall_t);

	if (MEMCPY_S(&ms->ms_sid, sizeof(ms->ms_sid), &sid, sizeof(sid))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (dh_msg2 != NULL) {
		if (MEMCPY_S(&ms->ms_dh_msg2, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_dh_msg2 % sizeof(*dh_msg2) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (MEMCPY_S(__tmp, ocalloc_size, dh_msg2, _len_dh_msg2)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
		ocalloc_size -= _len_dh_msg2;
	} else {
		ms->ms_dh_msg2 = NULL;
	}

	if (MEMCPY_S(&ms->ms_dh_msg2_size, sizeof(ms->ms_dh_msg2_size), &dh_msg2_size, sizeof(dh_msg2_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (dh_msg3 != NULL) {
		if (MEMCPY_S(&ms->ms_dh_msg3, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_dh_msg3 = __tmp;
		if (_len_dh_msg3 % sizeof(*dh_msg3) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		MEMSET(__tmp_dh_msg3, 0, _len_dh_msg3);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
		ocalloc_size -= _len_dh_msg3;
	} else {
		ms->ms_dh_msg3 = NULL;
	}

	if (MEMCPY_S(&ms->ms_dh_msg3_size, sizeof(ms->ms_dh_msg3_size), &dh_msg3_size, sizeof(dh_msg3_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (MEMCPY_S(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (dh_msg3) {
			if (memcpy_s((void*)dh_msg3, _len_dh_msg3, __tmp_dh_msg3, _len_dh_msg3)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_close_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_close_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_close_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_close_session_ocall_t));
	ocalloc_size -= sizeof(ms_close_session_ocall_t);

	if (MEMCPY_S(&ms->ms_sid, sizeof(ms->ms_sid), &sid, sizeof(sid))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (MEMCPY_S(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pse_message_req = pse_message_req_size;
	size_t _len_pse_message_resp = pse_message_resp_size;

	ms_invoke_service_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_invoke_service_ocall_t);
	void *__tmp = NULL;

	void *__tmp_pse_message_resp = NULL;

	CHECK_ENCLAVE_POINTER(pse_message_req, _len_pse_message_req);
	CHECK_ENCLAVE_POINTER(pse_message_resp, _len_pse_message_resp);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pse_message_req != NULL) ? _len_pse_message_req : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pse_message_resp != NULL) ? _len_pse_message_resp : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_invoke_service_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_invoke_service_ocall_t));
	ocalloc_size -= sizeof(ms_invoke_service_ocall_t);

	if (pse_message_req != NULL) {
		if (MEMCPY_S(&ms->ms_pse_message_req, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pse_message_req % sizeof(*pse_message_req) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (MEMCPY_S(__tmp, ocalloc_size, pse_message_req, _len_pse_message_req)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pse_message_req);
		ocalloc_size -= _len_pse_message_req;
	} else {
		ms->ms_pse_message_req = NULL;
	}

	if (MEMCPY_S(&ms->ms_pse_message_req_size, sizeof(ms->ms_pse_message_req_size), &pse_message_req_size, sizeof(pse_message_req_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (pse_message_resp != NULL) {
		if (MEMCPY_S(&ms->ms_pse_message_resp, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_pse_message_resp = __tmp;
		if (_len_pse_message_resp % sizeof(*pse_message_resp) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		MEMSET(__tmp_pse_message_resp, 0, _len_pse_message_resp);
		__tmp = (void *)((size_t)__tmp + _len_pse_message_resp);
		ocalloc_size -= _len_pse_message_resp;
	} else {
		ms->ms_pse_message_resp = NULL;
	}

	if (MEMCPY_S(&ms->ms_pse_message_resp_size, sizeof(ms->ms_pse_message_resp_size), &pse_message_resp_size, sizeof(pse_message_resp_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (MEMCPY_S(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (pse_message_resp) {
			if (memcpy_s((void*)pse_message_resp, _len_pse_message_resp, __tmp_pse_message_resp, _len_pse_message_resp)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
