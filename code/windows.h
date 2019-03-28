#ifndef __COMMON_WINDOWS_H_
#define __COMMON_WINDOWS_H_

#pragma warning(disable: 4201)

#define NTDDI_VERSION 0x05010300
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN 1

#define _WIN32_IE 0x0700

#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>

#include <process.h>
#include <signal.h>
#include <sys/stat.h>
#include <windows.h>
#include <windowsx.h>
#include <Ole2.h>
#include <shobjidl.h>
#include <imagehlp.h>
#include <stdio.h>
#include <psapi.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <Sddl.h>
#include <Tlhelp32.h>
#include <ShellAPI.h>
#include <Pstore.h>
#include <urlhist.h> 
#include <WinCred.h>
#include <Msi.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <winhttp.h>
#include <WinSvc.h>
#include <WinNls.h>
#include <d3d9.h>
#include <olectl.h>
#include <Shobjidl.h>
#include <WinIoCtl.h>
#include <objbase.h>
#include <time.h>
#include <stdarg.h>
#include <winperf.h>
#include <tlhelp32.h>
//#include <wchar.h>

#include "platform.h"
#include "types.h"
#include "ntdll.h"

// Architecture-dependent pointer size
#define POINTER_SIZE sizeof(void*)

#include <pshpack4.h>
// Kernel-user shared data

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
	StandardDesign,
	NEC98x86,
	EndAlternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;


typedef struct _KSYSTEM_TIME
{
	ULONG LowPart;
	LONG High1Time;
	LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

#define PROCESSOR_FEATURE_MAX 64

#ifndef MAXIMUM_XSTATE_FEATURES

#define MAXIMUM_XSTATE_FEATURES 64

//
// Extended processor state configuration
//

typedef struct _XSTATE_FEATURE {
	DWORD Offset;
	DWORD Size;
} XSTATE_FEATURE, *PXSTATE_FEATURE;

typedef struct _XSTATE_CONFIGURATION {
	// Mask of enabled features
	DWORD64 EnabledFeatures;

	// Total size of the save area
	DWORD Size;

	DWORD OptimizedSave : 1;

	// List of features (
	XSTATE_FEATURE Features[MAXIMUM_XSTATE_FEATURES];

} XSTATE_CONFIGURATION, *PXSTATE_CONFIGURATION;

#endif // MAXIMUM_XSTATE_FEATURES

typedef struct _KUSER_SHARED_DATA
{
	ULONG TickCountLowDeprecated;
	ULONG TickCountMultiplier;

	volatile KSYSTEM_TIME InterruptTime;
	volatile KSYSTEM_TIME SystemTime;
	volatile KSYSTEM_TIME TimeZoneBias;

	USHORT ImageNumberLow;
	USHORT ImageNumberHigh;

	wchar_t NtSystemRoot[260];

	ULONG MaxStackTraceDepth;

	ULONG CryptoExponent;

	ULONG TimeZoneId;
	ULONG LargePageMinimum;
	ULONG AitSamplingValue;
	ULONG AppCompatFlag;
	ULONGLONG RNGSeedVersion;
	ULONG GlobalValidationRunlevel;
	LONG TimeZoneBiasStamp;
	ULONG Reserved2;

	ULONG NtProductType;
	BOOLEAN ProductTypeIsValid;
	UCHAR Reserved0[1];
	USHORT NativeProcessorArchitecture;

	ULONG NtMajorVersion;
	ULONG NtMinorVersion;

	BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];

	ULONG Reserved1;
	ULONG Reserved3;

	volatile ULONG TimeSlip;

	ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
	ULONG AltArchitecturePad[1];

	LARGE_INTEGER SystemExpirationDate;

	ULONG SuiteMask;

	BOOLEAN KdDebuggerEnabled;
	union
	{
		UCHAR MitigationPolicies;
		struct
		{
			UCHAR NXSupportPolicy : 2;
			UCHAR SEHValidationPolicy : 2;
			UCHAR CurDirDevicesSkippedForDlls : 2;
			UCHAR Reserved : 2;
		};
	};
	UCHAR Reserved6[2];

	volatile ULONG ActiveConsoleId;

	volatile ULONG DismountCount;

	ULONG ComPlusPackage;

	ULONG LastSystemRITEventTickCount;

	ULONG NumberOfPhysicalPages;

	BOOLEAN SafeBootMode;
	UCHAR Reserved12[3];

	union
	{
		ULONG SharedDataFlags;
		struct
		{
			ULONG DbgErrorPortPresent : 1;
			ULONG DbgElevationEnabled : 1;
			ULONG DbgVirtEnabled : 1;
			ULONG DbgInstallerDetectEnabled : 1;
			ULONG DbgLkgEnabled : 1;
			ULONG DbgDynProcessorEnabled : 1;
			ULONG DbgConsoleBrokerEnabled : 1;
			ULONG DbgSecureBootEnabled : 1;
			ULONG SpareBits : 24;
		};
	};
	ULONG DataFlagsPad[1];

	ULONGLONG TestRetInstruction;
	ULONGLONG QpcFrequency;
	ULONGLONG SystemCallPad[3];

	union
	{
		volatile KSYSTEM_TIME TickCount;
		volatile ULONG64 TickCountQuad;
		ULONG ReservedTickCountOverlay[3];
	};
	ULONG TickCountPad[1];

	ULONG Cookie;
	ULONG CookiePad[1];

	LONGLONG ConsoleSessionForegroundProcessId;
	ULONGLONG TimeUpdateSequence;
	ULONGLONG BaselineSystemTimeQpc;
	ULONGLONG BaselineInterruptTimeQpc;
	ULONGLONG QpcSystemTimeIncrement;
	ULONGLONG QpcInterruptTimeIncrement;
	ULONG QpcSystemTimeIncrement32;
	ULONG QpcInterruptTimeIncrement32;
	UCHAR QpcSystemTimeIncrementShift;
	UCHAR QpcInterruptTimeIncrementShift;
	UCHAR Reserved8[14];

	USHORT UserModeGlobalLogger[16];
	ULONG ImageFileExecutionOptions;

	ULONG LangGenerationCount;
	ULONGLONG Reserved4;
	volatile ULONG64 InterruptTimeBias;
	volatile ULONG64 TscQpcBias;

	volatile ULONG ActiveProcessorCount;
	volatile UCHAR ActiveGroupCount;
	UCHAR Reserved9;
	union
	{
		USHORT TscQpcData;
		struct
		{
			UCHAR TscQpcEnabled : 1;
			UCHAR TscQpcShift : 1;
		};
	};

	LARGE_INTEGER TimeZoneBiasEffectiveStart;
	LARGE_INTEGER TimeZoneBiasEffectiveEnd;
	XSTATE_CONFIGURATION XState;
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;
#include <poppack.h>


#endif // __COMMON_WINDOWS_H_
