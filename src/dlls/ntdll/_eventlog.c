/*
28-Nov-2020 moyefi moves following Win32 APIs to NTDLL.DLL
	EtwEventWriteTransfer
    EtwEventRegister
	EtwEventUnregister
	EtwEventWrite
	EtwEventWriteTransfer
	EtwEventWriteEx
*/

#include "ldrp.h"
#include <ntos.h>
#include <_sal.h>
#include <winerror.h>

#pragma warning(disable : 4100) //supress: unreferenced formal parameter

//https://chromium.googlesource.com/chromium/src/+/28ad5e6b1100a7f0d25a5e6741f7241a86cf61bd/base/trace_event/trace_event_etw_export_win.cc
//https://www.geoffchappell.com/studies/windows/win32/advapi32/api/etw/index.htm
//https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/misc.c
//ADVAPI32 also exports the following ETW functions as forwards to NTDLL. Some of these functions have implementions in ADVAPI32 in early versions. 
//Some have never existed except as forwards to NTDLL.
//Function: EventRegister
//Entry Point: ntdll.EtwEventRegister	

//defnitions from evntprov.h
#define PVOID void *


typedef struct _EVENT_DESCRIPTOR
{
    USHORT    Id;
    UCHAR     Version;
    UCHAR     Channel;
    UCHAR     Level;
    UCHAR     Opcode;
    USHORT    Task;
    ULONGLONG Keyword;
} EVENT_DESCRIPTOR;

typedef       EVENT_DESCRIPTOR *PEVENT_DESCRIPTOR;

typedef const EVENT_DESCRIPTOR *PCEVENT_DESCRIPTOR;

typedef ULONGLONG REGHANDLE, *PREGHANDLE;

typedef struct _EVENT_DATA_DESCRIPTOR
{
    ULONGLONG   Ptr;
    ULONG       Size;
    ULONG       Reserved;
} EVENT_DATA_DESCRIPTOR, *PEVENT_DATA_DESCRIPTOR;

typedef struct _EVENT_FILTER_DESCRIPTOR
{
    ULONGLONG   Ptr;
    ULONG       Size;
    ULONG       Type;

} EVENT_FILTER_DESCRIPTOR, *PEVENT_FILTER_DESCRIPTOR;

typedef VOID (NTAPI *PENABLECALLBACK)(LPCGUID,ULONG,UCHAR,ULONGLONG,ULONGLONG,PEVENT_FILTER_DESCRIPTOR,PVOID);

typedef enum _EVENT_INFO_CLASS
{
    EventProviderBinaryTrackInfo = 0,
    EventProviderSetTraits,
    EventProviderUseDescriptorType,
    MaxEventInfo
} EVENT_INFO_CLASS;

ULONG
EtwEventWriteEx(
    _In_ REGHANDLE RegHandle,
    _In_ PCEVENT_DESCRIPTOR EventDescriptor,
    _In_ ULONG64 Filter,
    _In_ ULONG Flags,
    _In_opt_ LPCGUID ActivityId,
    _In_opt_ LPCGUID RelatedActivityId,
    _In_range_(0, MAX_EVENT_DATA_DESCRIPTORS) ULONG UserDataCount,
    _In_reads_opt_(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
	)
{
	return ERROR_SUCCESS;
}

ULONG 
EtwEventWriteTransfer( 
    _In_ REGHANDLE RegHandle,
    _In_ PCEVENT_DESCRIPTOR EventDescriptor,
    _In_opt_ LPCGUID ActivityId,
    _In_opt_ LPCGUID RelatedActivityId,
    _In_range_(0, MAX_EVENT_DATA_DESCRIPTORS) ULONG UserDataCount,
    _In_reads_opt_(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
)
{
    return EtwEventWriteEx(RegHandle, EventDescriptor, 0, 0, ActivityId, RelatedActivityId, UserDataCount, UserData);
}

ULONG 
EtwEventRegister(
    _In_ LPCGUID ProviderId,
    _In_opt_ PENABLECALLBACK EnableCallback,
    _In_opt_ PVOID CallbackContext,
    _Out_ PREGHANDLE RegHandle
    )
{
	if (!RegHandle) return ERROR_INVALID_PARAMETER;
    *RegHandle = 0xdeadbeef;
    return ERROR_SUCCESS;
}

ULONG
EtwEventUnregister(REGHANDLE RegHandle) {
	return ERROR_SUCCESS;
}

ULONG
EtwEventWrite(
    _In_ REGHANDLE RegHandle,
    _In_ PCEVENT_DESCRIPTOR EventDescriptor,
    _In_range_(0, MAX_EVENT_DATA_DESCRIPTORS) ULONG UserDataCount,
    _In_reads_opt_(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
    )
{
	return EtwEventWriteTransfer(RegHandle, EventDescriptor, NULL, NULL, UserDataCount, UserData);
}

ULONG
EtwEventSetInformation(
    _In_ REGHANDLE RegHandle,
    _In_ EVENT_INFO_CLASS InformationClass,
    _In_reads_bytes_(InformationLength) PVOID EventInformation,
    _In_ ULONG InformationLength
    )
{
	return ERROR_SUCCESS;
}