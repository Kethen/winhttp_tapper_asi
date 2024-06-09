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


HINTERNET (WINAPI *WinHttpConnectOrig)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
HINTERNET WINAPI WinHttpConnectPatched(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved){
	HINTERNET ret = WinHttpConnectOrig(hSession, pswzServerName, nServerPort, dwReserved);

	int server_name_len = WideCharToMultiByte(CP_UTF8, MB_ERR_INVALID_CHARS, pswzServerName, -1, NULL, 0, NULL, NULL);
	if(server_name_len <= 0){
		LOG("XXX failed recording WinHttpConnect, cannot determine len of pswzServerName");
		return ret;
	}
	if(server_name_len > 1024){
		LOG("XXX failed recording WinHttpConnect, pswzServerName too long");
	}
	// if we blow up here so be it..? it should not be so long
	char server_name_buf[1024];
	WideCharToMultiByte(CP_UTF8, MB_ERR_INVALID_CHARS, pswzServerName, -1, server_name_buf, server_name_len, NULL, NULL);
	LOG("WinHttpConnect connecting to %s", server_name_buf);
	return ret;
}

int hook_functions(){
	int ret = MH_CreateHookApiEx(L"winhttp", "WinHttpConnect", (LPVOID)&WinHttpConnectPatched, NULL, (void**)&WinHttpConnectOrig);
	if(ret != MH_OK){
		LOG("Failed hooking winhttp");
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
