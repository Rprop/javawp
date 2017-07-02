#define DISABLE_UI_IMPORT
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define SAFE_PTR(a,b) (a == NULL ? b : a)
#include <RLib_Native.h>
#include "../Support/Utils/HookHelper.h"
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")
#ifdef _WIN64 
# pragma comment(lib, "ntdll_x64.lib")
#else
# pragma comment(lib, "ntdll_x86.lib")
#endif // _WIN64

//-------------------------------------------------------------------------

__declspec(dllexport) void _stdcall __dummy()
{
}

//-------------------------------------------------------------------------

#pragma pack(push)
#pragma pack(1)
typedef union flag
{
	unsigned char a;
	struct
	{
		unsigned short patched : 4;
		unsigned short exclude : 4;
	} b;
} flag;
#pragma pack(pop)

//-------------------------------------------------------------------------

INT WINAPI DllMain(_In_ void* _DllHandle, _In_ unsigned long _Reason, _In_opt_ void *_Reserved)
{
	if (_Reason == DLL_PROCESS_ATTACH) {
		MH_Initialize();

		// HKEY_CURRENT_USER\SOFTWARE\JavaSoft\Prefs\
		static volatile flag hits_ts[1024 * 1024 * 2] = { 0 };
		static volatile long hits_cc = 0;
		static auto nt_file_time = FastHook(EvaluateJmp(GetSystemTimeAsFileTime));
		nt_file_time = [](_Out_ LPFILETIME lpSystemTimeAsFileTime)
		{
			nt_file_time.OriginalTargetFunction(lpSystemTimeAsFileTime);
// 			SYSTEMTIME st;
// 			FileTimeToSystemTime(lpSystemTimeAsFileTime, &st);
// 			FILETIME t;
// 			SystemTimeToFileTime(&st, &ft);
			DWORD t = GetCurrentThreadId();
			if (hits_cc <= 20000) {
				ULARGE_INTEGER ui;
				ui.LowPart  = lpSystemTimeAsFileTime->dwLowDateTime;
				ui.HighPart = lpSystemTimeAsFileTime->dwHighDateTime;
				if (ui.QuadPart >= 131252191348000000LL) { // 2016/12/03
					InterlockedIncrement(&hits_cc);
					ui.QuadPart = 131197536000000000;      // 2016/10/01
					lpSystemTimeAsFileTime->dwLowDateTime  = ui.LowPart;
					lpSystemTimeAsFileTime->dwHighDateTime = ui.HighPart;
					if (!hits_ts[t].b.patched) {
						hits_ts[t].b.patched = 1;
//						printf("thread %u patched, %u.\n", t, hits_cc);
					} //if
				} //if
			} else {
// 				if (!hits_ts[t].b.exclude) {
// 					hits_ts[t].b.exclude = 1;
// 					printf("thread %u excluded, %u.\n", t, hits_cc);
// 				} //if
				// new threads will not be patched
				if (hits_ts[t].b.patched) {
					ULARGE_INTEGER ui;
					ui.LowPart  = lpSystemTimeAsFileTime->dwLowDateTime;
					ui.HighPart = lpSystemTimeAsFileTime->dwHighDateTime;
					if (ui.QuadPart >= 131252191348000000LL) { // 2016/12/03
						ui.QuadPart = 131197536000000000;      // 2016/10/01
						lpSystemTimeAsFileTime->dwLowDateTime  = ui.LowPart;
						lpSystemTimeAsFileTime->dwHighDateTime = ui.HighPart;
					} //if
				} //if
			} //if
//			printf("GetSystemTimeAsFileTime hits %u %u\n", lpSystemTimeAsFileTime->dwLowDateTime, lpSystemTimeAsFileTime->dwHighDateTime);
		};
// 		static auto nt_rtl_time = FastHook(EvaluateJmp(RtlTimeToTimeFields));
// 		nt_rtl_time = [](_In_  PLARGE_INTEGER Time,
// 						 _Out_ PTIME_FIELDS   TimeFields)
// 		{
// 			printf("RtlTimeToTimeFields hits %d %d\n", TimeFields->Year, TimeFields->Month);
// 			if (TimeFields->Year >= 2016 && TimeFields->Month >= 12) {
// 				TimeFields->Year  = 2016;
// 				TimeFields->Month = 10;
// 			} //if
// 		};
// 		static auto nt_loc_time = FastHook(EvaluateJmp(GetLocalTime));
// 		nt_loc_time = [](_Out_ LPSYSTEMTIME lpSystemTime)
// 		{
// 			nt_loc_time.OriginalTargetFunction(lpSystemTime);
// 			printf("GetLocalTime hits %u\n", hits_cc);
// 		};
// 		static auto nt_sys_time = FastHook(EvaluateJmp(GetSystemTime));
// 		nt_sys_time = [](_Out_ LPSYSTEMTIME lpSystemTime)
// 		{
// 			nt_sys_time.OriginalTargetFunction(lpSystemTime);
// 			printf("GetSystemTime hits\n");
// 		};
// 		static auto nt_fs_time = FastHook(EvaluateJmp(FileTimeToSystemTime));
// 		nt_fs_time = [](_In_ CONST FILETIME * lpFileTime, _Out_ LPSYSTEMTIME lpSystemTime)->BOOL
// 		{
// 			BOOL ret = nt_fs_time.OriginalTargetFunction(lpFileTime, lpSystemTime);
// 			printf("FileTimeToSystemTime hits %d %d %d\n", ret, lpSystemTime->wYear, lpSystemTime->wMonth);	
// 			return ret;
// 		};
	} else if (_Reason == DLL_PROCESS_DETACH) {
		MH_Uninitialize();
	} //if

	return TRUE;
}