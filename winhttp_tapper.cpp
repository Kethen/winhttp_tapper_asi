#include <windows.h>

// to tap winhttp properly, this dll should be loaded earlier than winhttp's usage
#include <winhttp.h>

// other winapis
#include <stringapiset.h>

// std
#include <stdint.h>
#include <string.h>

// there are likely multiple flavors of winhttp.dll, so let's use a hooking library
// https://github.com/TsudaKageyu/minhook
#include "MinHook.h"

#include "logging.h"

int convert_wide_string(char *out_buf, int out_buf_len, LPCWSTR wide_string, int wide_string_len){
	int len = WideCharToMultiByte(CP_UTF8, 0, wide_string, wide_string_len, NULL, 0, NULL, NULL);
	if(len > out_buf_len){
		return -1;
	}
	return WideCharToMultiByte(CP_UTF8, 0, wide_string, wide_string_len, out_buf, out_buf_len, NULL, NULL);
}


HINTERNET (WINAPI *WinHttpConnectOrig)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
HINTERNET WINAPI WinHttpConnectPatched(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved){
	HINTERNET ret = WinHttpConnectOrig(hSession, pswzServerName, nServerPort, dwReserved);

	char server_name_buf[4096];
	int len = convert_wide_string(server_name_buf, sizeof(server_name_buf), pswzServerName, -1);
	if(len > 0){
		LOG("WinHttpConnect connecting to %s:%d, hSession 0x%p, ret 0x%p", server_name_buf, nServerPort, hSession, ret);
		if(ret != NULL){
			char data_buf[sizeof(server_name_buf) + 8 + 6] = {0};
			memcpy(data_buf, &ret, sizeof(HINTERNET));
			// remove null
			len = len - 1;
			memcpy(data_buf + 8, server_name_buf, len);
			data_buf[8 + len] = ':';
			int port_len = sprintf(&data_buf[8 + len + 1], "%d", nServerPort);
			dump_data(data_buf, 8 + len + 1 + port_len, LOG_TYPE_CONNECT);
		}
	}else{
		LOG("WinHttpConnect failed converting pswzServerName wdf %d", len);
	}
	return ret;
}

HINTERNET (WINAPI *WinHttpOpenRequestOrig)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
HINTERNET WINAPI WinHttpOpenRequestPatched(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags){
	HINTERNET ret = WinHttpOpenRequestOrig(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);
	char method_buf[4096];
	if(pwszVerb != NULL){
		int method_len = convert_wide_string(method_buf, sizeof(method_buf), pwszVerb, -1);
		if(method_len <= 0){
			LOG("WinHttpOpenRequest failed converting pwszVerb wdf %d", method_len);
			return ret;
		}
	}else{
		strcpy(method_buf, "GET");
	}

	char resource_buf[4096];
	int resource_len = convert_wide_string(resource_buf, sizeof(resource_buf), pwszObjectName, -1);
	if(resource_len <= 0){
		LOG("WinHttpOpenRequest failed converting pwszObjectName wdf %d", resource_len);
		return ret;
	}

	LOG("WinHttpOpenRequest hConnect 0x%p, method %s, resource %s, ret 0x%p", hConnect, method_buf, resource_buf, ret);
	if(ret != NULL){
		char data_buf[8 + sizeof(method_buf) + sizeof(resource_buf)] = {0};
		int offset = 0;
		memcpy(&data_buf[offset], &hConnect, sizeof(HINTERNET));
		offset += 8;
		memcpy(&data_buf[offset], &ret, sizeof(HINTERNET));
		offset += 8;
		int len = strlen(method_buf);
		strcpy(&data_buf[offset], method_buf);
		offset += len;
		data_buf[offset] = '|';
		offset++;
		len = strlen(resource_buf);
		strcpy(&data_buf[offset], resource_buf);
		offset += len;

		dump_data(data_buf, offset, LOG_TYPE_REQUEST);
	}

	return ret;
}

WINBOOL (WINAPI *WinHttpSendRequestOrig)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
WINBOOL WINAPI WinHttpSendRequestPatched(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext){
	WINBOOL ret = WinHttpSendRequestOrig(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
	LOG("WinHttpSendRequest hRequest 0x%p, ret %s", hRequest, ret? "true" : "false");

	char header_buf[4096] = {0};
	int header_len = 0;
	if(lpszHeaders != NULL){
		memset(header_buf, 0, 8);
		memcpy(header_buf, &hRequest, sizeof(HINTERNET));
		header_len = convert_wide_string(header_buf + 8, sizeof(header_buf) - sizeof(HINTERNET), lpszHeaders, dwHeadersLength);
		if(header_len <= 0){
			LOG("WinHttpSendRequestPatched failed converting lpszHeaders wdf %d", header_len);
			return ret;
		}
		dump_data(header_buf, header_len + 8, LOG_TYPE_REQUEST_HEADER);
	}

	if(lpOptional != NULL){
		char *optional_buf = (char *)malloc(8 + dwOptionalLength);
		if(optional_buf == NULL){
			LOG("WinHttpSendRequestPatched cannot allocate buffer for dumping on-request optional data wdf");
		}else{
			memset(optional_buf, 0, 8);
			memcpy(optional_buf, &hRequest, sizeof(HINTERNET));
			memcpy(optional_buf + 8, lpOptional, dwOptionalLength);
			dump_data(optional_buf, 8 + dwOptionalLength, LOG_TYPE_REQUEST_OPTIONAL_DUMP);
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
		char *data_buf = (char *)malloc(*lpdwNumberOfBytesRead + 8);
		if(data_buf == NULL){
			LOG("WinHttpReadData cannot allocate buffer for dumping data wdf");
		}else{
			memset(data_buf, 0, 8);
			memcpy(data_buf, &hRequest, sizeof(HINTERNET));
			memcpy(data_buf + 8, lpBuffer, *lpdwNumberOfBytesRead);
			dump_data(data_buf, 8 + *lpdwNumberOfBytesRead, LOG_TYPE_READ_DATA_DUMP);
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
		char *data_buf = (char *)malloc(*lpdwNumberOfBytesRead + 8);
		if(data_buf == NULL){
			LOG("WinHttpReadData cannot allocate buffer for dumping data wdf");
		}else{
			memset(data_buf, 0, 8);
			memcpy(data_buf, &hRequest, sizeof(HINTERNET));
			memcpy(data_buf + 8, lpBuffer, *lpdwNumberOfBytesRead);
			dump_data(data_buf, 8 + *lpdwNumberOfBytesRead, LOG_TYPE_READ_DATA_DUMP);
			free(data_buf);
		}
	}

	return ret;
}

WINBOOL (WINAPI *WinHttpWriteDataOrig)(HINTERNET,LPCVOID,DWORD,LPDWORD);
WINBOOL WINAPI WinHttpWriteDataPatched(HINTERNET hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten){
	WINBOOL ret = WinHttpWriteDataOrig(hRequest, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
	LOG("WinHttpWriteData hRequest 0x%p, dwNumberOfBytesToWrite %d, lpdwNumberOfBytesWritten %d, ret %s", hRequest, dwNumberOfBytesToWrite, *lpdwNumberOfBytesWritten, ret? "true": "false");
	if(ret && *lpdwNumberOfBytesWritten > 0){
		char *data_buf = (char *)malloc(8 + *lpdwNumberOfBytesWritten);
		if(data_buf == NULL){
			LOG("WinHttpWriteData cannot allocate buffer for dumping data wdf");
		}else{
			memset(data_buf, 0, 8);
			memcpy(data_buf, &hRequest, sizeof(HINTERNET));
			memcpy(data_buf + 8, lpBuffer, *lpdwNumberOfBytesWritten);
			dump_data(data_buf, 8 + *lpdwNumberOfBytesWritten, LOG_TYPE_WRITE_DATA_DUMP);
			free(data_buf);
		}
	}

	return ret;
}

WINBOOL (WINAPI *WinHttpCloseHandleOrig)(HINTERNET);
WINBOOL WINAPI WinHttpCloseHandlePatched(HINTERNET hInternet){
	WINBOOL ret = WinHttpCloseHandleOrig(hInternet);
	LOG("WinHttpCloseHandle 0x%p, ret %s", hInternet, ret? "true": "false");
	if(ret){
		char data_buf[8] = {0};
		memcpy(data_buf, &hInternet, sizeof(HINTERNET));
		dump_data(data_buf, 8, LOG_TYPE_CLOSE_HANDLE);
	}
	return ret;
}

HINTERNET (WINAPI *WinHttpOpenOrig)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
HINTERNET WINAPI WinHttpOpenPatched(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags){
	HINTERNET ret = WinHttpOpenOrig(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags);
	char user_agent_buf[4096] = {0};
	if(pszAgentW != NULL){
		if(convert_wide_string(user_agent_buf, sizeof(user_agent_buf), pszAgentW, -1) <= 0){
			LOG("WinHttpOpen failed converting pszAgentW wdf");
			return ret;
		}
	}else{
		strcpy(user_agent_buf, "<no user agent set>");
	}

	char proxy_buf[4096] = {0};
	if(pszProxyW != NULL){
		if(convert_wide_string(proxy_buf, sizeof(proxy_buf), pszProxyW, -1) <= 0){
			LOG("WinHttpOpen failed converting pszProxyW wdf");
			return ret;
		}
	}else{
		strcpy(proxy_buf, "<no proxy>");
	}

	char proxy_bypass_buf[4096] = {0};
	if(pszProxyBypassW != NULL){
		if(convert_wide_string(proxy_bypass_buf, sizeof(proxy_bypass_buf), pszProxyBypassW, -1) <= 0){
			LOG("WinHttpOpen failed converting pszProxyW wdf");
			return ret;
		}
	}else{
		strcpy(proxy_bypass_buf, "<no proxy> bypass set");
	}

	LOG("WinHttpOpen pszAgentW %s, dwAccessType %d, pszProxyW %s, pszProxyBypassW %s, dwFlags %d, ret 0x%p, async %s", user_agent_buf, dwAccessType, proxy_buf, proxy_bypass_buf, dwFlags, ret, dwFlags & WINHTTP_FLAG_ASYNC? "true" : "false");
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
		ret = MH_Initialize();
		if(ret != MH_OK){
			LOG("Failed initializing MinHook, %d", ret);
			break;
		}
		LPVOID target;
		ret = MH_CreateHookApiEx(L"winhttp", "WinHttpConnect", (LPVOID)&WinHttpConnectPatched, (void**)&WinHttpConnectOrig, &target);
		if(ret != MH_OK){
			LOG("Failed hooking winhttp WinHttpConnect, %d", ret);
			break;
		}
		ret = MH_EnableHook(target);
		if(ret != MH_OK){
			LOG("Failed enabling winhttp WinHttpConnect hook");
			break;
		}

		ret = MH_CreateHookApiEx(L"winhttp", "WinHttpOpenRequest", (LPVOID)&WinHttpOpenRequestPatched, (void**)&WinHttpOpenRequestOrig, &target);
		if(ret != MH_OK){
			LOG("Failed hooking winhttp WinHttpOpenRequest, %d", ret);
			break;
		}
		ret = MH_EnableHook(target);
		if(ret != MH_OK){
			LOG("Failed enabling winhttp WinHttpOpenRequest hook");
			break;
		}

		ret = MH_CreateHookApiEx(L"winhttp", "WinHttpSendRequest", (LPVOID)&WinHttpSendRequestPatched, (void**)&WinHttpSendRequestOrig, &target);
		if(ret != MH_OK){
			LOG("Failed hooking winhttp WinHttpSendRequest, %d", ret);
			break;
		}
		ret = MH_EnableHook(target);
		if(ret != MH_OK){
			LOG("Failed enabling winhttp WinHttpSendRequest hook");
			break;
		}

		ret = MH_CreateHookApiEx(L"winhttp", "WinHttpReadData", (LPVOID)&WinHttpReadDataPatched, (void**)&WinHttpReadDataOrig, &target);
		if(ret != MH_OK){
			LOG("Failed hooking winhttp WinHttpReadData, %d", ret);
			break;
		}
		ret = MH_EnableHook(target);
		if(ret != MH_OK){
			LOG("Failed enabling winhttp WinHttpReadData hook");
			break;
		}

		ret = MH_CreateHookApiEx(L"winhttp", "WinHttpWriteData", (LPVOID)&WinHttpWriteDataPatched, (void**)&WinHttpWriteDataOrig, &target);
		if(ret != MH_OK){
			LOG("Failed hooking winhttp WinHttpWriteData, %d", ret);
			break;
		}
		ret = MH_EnableHook(target);
		if(ret != MH_OK){
			LOG("Failed enabling winhttp WinHttpWriteData hook");
			break;
		}

		ret = MH_CreateHookApiEx(L"winhttp", "WinHttpCloseHandle", (LPVOID)&WinHttpCloseHandlePatched, (void**)&WinHttpCloseHandleOrig, &target);
		if(ret != MH_OK){
			LOG("Failed hooking winhttp WinHttpCloseHandle, %d", ret);
			break;
		}
		ret = MH_EnableHook(target);
		if(ret != MH_OK){
			LOG("Failed enabling winhttp WinHttpCloseHandle hook");
			break;
		}

		ret = MH_CreateHookApiEx(L"winhttp", "WinHttpOpen", (LPVOID)&WinHttpOpenPatched, (void**)&WinHttpOpenOrig, &target);
		if(ret != MH_OK){
			LOG("Failed hooking winhttp WinHttpOpen, %d", ret);
			break;
		}
		ret = MH_EnableHook(target);
		if(ret != MH_OK){
			LOG("Failed enabling winhttp WinHttpOpen hook");
			break;
		}

		/*
		not even in 10 22h2..?
		ret = MH_CreateHookApiEx(L"winhttp", "WinHttpReadDataEx", (LPVOID)&WinHttpReadDataExPatched, (void**)&WinHttpReadDataExOrig, &target);
		if(ret != MH_OK){
			LOG("Failed hooking winhttp WinHttpReadDataEx, %d", ret);
			break;
		}
		ret = MH_EnableHook(target);
		if(ret != MH_OK){
			LOG("Failed enabling winhttp WinHttpReadDataEx hook");
			break;
		}
		*/

		break;
	}

	if(ret != MH_OK){
		return 1;
	}
	LOG("functions hooked successfully");
	return 0;
}

// entrypoint
__attribute__((constructor))
int init(){
	if(init_logging() != 0){
		LOG("pthread init failed, terminating process :(");
		exit(1);
	}
	if(hook_functions() != 0){
		LOG("hooking failed, terminating process :(");
		exit(1);
	}
	return 0;
}
