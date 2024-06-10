#include <windows.h>

// to tap winhttp properly, this dll should be loaded earlier than winhttp's usage
#include <winhttp.h>

// other winapis
#include <stringapiset.h>

// std
#include <stdint.h>

// there are likely multiple flavors of winhttp.dll, so let's use a hooking library
// https://github.com/TsudaKageyu/minhook
#include "MinHook.h"

#include "logging.h"

int convert_wide_string(char *out_buf, int out_buf_len, LPCWSTR wide_string, int wide_string_len){
	int len = WideCharToMultiByte(CP_UTF8, MB_ERR_INVALID_CHARS, wide_string, wide_string_len, NULL, 0, NULL, NULL);
	if(len > out_buf_len){
		return -1;
	}
	return WideCharToMultiByte(CP_UTF8, MB_ERR_INVALID_CHARS, wide_string, wide_string_len, out_buf, out_buf_len, NULL, NULL);
}

HINTERNET (WINAPI *WinHttpConnectOrig)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
HINTERNET WINAPI WinHttpConnectPatched(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved){
	HINTERNET ret = WinHttpConnectOrig(hSession, pswzServerName, nServerPort, dwReserved);

	char server_name_buf[4096];
	int len = convert_wide_string(server_name_buf, sizeof(server_name_buf), pswzServerName, -1);
	if(len > 0){
		LOG("WinHttpConnect connecting to %s:%d, hSession 0x%p, ret 0x%p", server_name_buf, nServerPort, hSession, ret);
	}else{
		LOG("WinHttpConnect failed converting pswzServerName wdf");
	}
	return ret;
}

HINTERNET (WINAPI *WinHttpOpenRequestOrig)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
HINTERNET WINAPI WinHttpOpenRequestPatched(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags){
	HINTERNET ret = WinHttpOpenRequestOrig(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);
	char method_buf[4096];
	int method_len = convert_wide_string(method_buf, sizeof(method_buf), pwszVerb, -1);
	if(method_len <= 0){
		LOG("WinHttpOpenRequest failed converting pwszVerb wdf");
		return ret;
	}

	char resource_buf[4096];
	int resource_len = convert_wide_string(resource_buf, sizeof(resource_buf), pwszObjectName, -1);
	if(resource_len <= 0){
		LOG("WinHttpOpenRequest failed converting pwszObjectName wdf");
		return ret;
	}

	LOG("WinHttpOpenRequest hConnect 0x%p, method %s, resource %s, ret 0x%p", hConnect, method_buf, resource_buf, ret);
	return ret;
}

WINBOOL (WINAPI *WinHttpSendRequestOrig)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
WINBOOL WINAPI WinHttpSendRequestPatched(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext){
	WINBOOL ret = WinHttpSendRequestOrig(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
	LOG("WinHttpSendRequest hRequest 0x%p, ret %s", hRequest, ret? "true" : "false");

	char header_buf[4096] = {0};
	int header_len = 0;
	if(lpszHeaders != NULL){
		memcpy(header_buf, &hRequest, sizeof(HINTERNET));
		header_len = convert_wide_string(header_buf + sizeof(HINTERNET), sizeof(header_buf) - sizeof(HINTERNET), lpszHeaders, dwHeadersLength);
		if(header_len <= 0){
			LOG("WinHttpSendRequestPatched failed converting lpszHeaders wdf");
			return ret;
		}
		dump_data(header_buf, header_len + sizeof(HINTERNET), LOG_TYPE_REQUEST_HEADER);
	}

	if(lpOptional != NULL){
		char *optional_buf = (char *)malloc(dwOptionalLength + sizeof(HINTERNET));
		if(optional_buf == NULL){
			LOG("WinHttpSendRequestPatched cannot allocate buffer for dumping on-request optional data wdf");
		}else{
			memcpy(optional_buf, &hRequest, sizeof(HINTERNET));
			memcpy(optional_buf + sizeof(HINTERNET), lpOptional, dwOptionalLength);
			dump_data(optional_buf, sizeof(HINTERNET) + dwOptionalLength, LOG_TYPE_REQUEST_OPTIONAL_DUMP);
			free(optional_buf);
		}
	}

	return ret;
}

WINBOOL (WINAPI *WinHttpReadDataOrig)(HINTERNET,LPVOID,DWORD,LPDWORD);
WINBOOL WINAPI WinHttpReadDataPatched(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead){
	WINBOOL ret = WinHttpReadDataOrig(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
	LOG("WinHttpReadData hRequest 0x%p, dwNumberOfBytesToRead %d, lpdwNumberOfBytesRead %d, ret %s", hRequest, dwNumberOfBytesToRead, *lpdwNumberOfBytesRead, ret? "true" : "false");
	if(ret && *lpdwNumberOfBytesRead > 0){
		char *data_buf = (char *)malloc(*lpdwNumberOfBytesRead + sizeof(HINTERNET));
		if(data_buf == NULL){
			LOG("WinHttpReadData cannot allocate buffer for dumping data wdf");
		}else{
			memcpy(data_buf, &hRequest, sizeof(HINTERNET));
			memcpy(data_buf + sizeof(HINTERNET), lpBuffer, *lpdwNumberOfBytesRead);
			dump_data(data_buf, sizeof(HINTERNET) + *lpdwNumberOfBytesRead, LOG_TYPE_READ_DATA_DUMP);
			free(data_buf);
		}
	}

	return ret;
}

WINBOOL (WINAPI *WinHttpReadDataExOrig)(HINTERNET,LPVOID,DWORD,LPDWORD,ULONGLONG,DWORD,PVOID);
WINBOOL WINAPI WinHttpReadDataExPatched(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead, ULONGLONG ullFlags, DWORD cbProperty, PVOID pvProperty){
	WINBOOL ret = WinHttpReadDataExOrig(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead, ullFlags, cbProperty, pvProperty);
	LOG("WinHttpReadDataEx hRequest 0x%p, dwNumberOfBytesToRead %d, lpdwNumberOfBytesRead %d, ret %s", hRequest, dwNumberOfBytesToRead, *lpdwNumberOfBytesRead, ret? "true" : "false");
	if(ret && *lpdwNumberOfBytesRead > 0){
		char *data_buf = (char *)malloc(*lpdwNumberOfBytesRead + sizeof(HINTERNET));
		if(data_buf == NULL){
			LOG("WinHttpReadData cannot allocate buffer for dumping data wdf");
		}else{
			memcpy(data_buf, &hRequest, sizeof(HINTERNET));
			memcpy(data_buf + sizeof(HINTERNET), lpBuffer, *lpdwNumberOfBytesRead);
			dump_data(data_buf, sizeof(HINTERNET) + *lpdwNumberOfBytesRead, LOG_TYPE_READ_DATA_DUMP);
			free(data_buf);
		}
	}

	return ret;
}

int hook_functions(){
	int ret = 0;
	while(true){
		// load winhttp once
		HMODULE handle = LoadLibraryA("winhttp.dll");
		if(handle == NULL){
			LOG("Failed loading winhttp.dll");
			ret = -1;
			break;
		}
		int ret = MH_CreateHookApiEx(L"winhttp", "WinHttpConnect", (LPVOID)&WinHttpConnectPatched, NULL, (void**)&WinHttpConnectOrig);
		if(ret != MH_OK){
			LOG("Failed hooking winhttp WinHttpConnect");
			break;
		}

		ret = MH_CreateHookApiEx(L"winhttp", "WinHttpOpenRequest", (LPVOID)&WinHttpOpenRequestPatched, NULL, (void**)&WinHttpOpenRequestOrig);
		if(ret != MH_OK){
			LOG("Failed hooking winhttp WinHttpOpenRequest");
			break;
		}

		ret = MH_CreateHookApiEx(L"winhttp", "WinHttpSendRequest", (LPVOID)&WinHttpSendRequestPatched, NULL, (void**)&WinHttpSendRequestOrig);
		if(ret != MH_OK){
			LOG("Failed hooking winhttp WinHttpSendRequest");
			break;
		}

		ret = MH_CreateHookApiEx(L"winhttp", "WinHttpReadData", (LPVOID)&WinHttpReadDataPatched, NULL, (void**)&WinHttpReadDataOrig);
		if(ret != MH_OK){
			LOG("Failed hooking winhttp WinHttpReadData");
			break;
		}

		ret = MH_CreateHookApiEx(L"winhttp", "WinHttpReadDataEx", (LPVOID)&WinHttpReadDataExPatched, NULL, (void**)&WinHttpReadDataExOrig);
		if(ret != MH_OK){
			LOG("Failed hooking winhttp WinHttpReadData");
			break;
		}

		break;
	}

	if(ret != MH_OK){
		return 1;
	}
	return 0;
}

// entrypoint
__attribute__((constructor))
int init(){
	init_logging();
	hook_functions();
	return 0;
}
