/*
28-Nov-2020 moyefi implements the following Win32 APIs

SetErrorMode
GetErrorMode

23-Nov-2020 moyefi implements the following Win32 APIs

GetActiveProcessorCount

22-Nov-2020 moyefi implements the following Win32 APIs

RegisterApplicationRestart
ApplicationRecoveryFinished
ApplicationRecoveryInProgress
RegisterApplicationRecoveryCallback 
UnregisterApplicationRecoveryCallback

*/
#include <basedll.h>
#include <_memory.h>

//from winnt.h
//
// Application restart and data recovery callback
//
typedef DWORD (WINAPI *APPLICATION_RECOVERY_CALLBACK)(PVOID pvParameter);

//from Wine process.c - but implemented as stubs...
/***********************************************************************
 *           RegisterApplicationRestart       (KERNEL32.@)
 */
HRESULT
RegisterApplicationRestart (
  PCWSTR pwzCommandline,
  DWORD  dwFlags
)
{
    //FIXME("(%s,%d)\n", debugstr_w(pwzCommandLine), dwFlags);

    return S_OK;
}

/**********************************************************************
 *           ApplicationRecoveryFinished     (KERNEL32.@)
 */
VOID
ApplicationRecoveryFinished(
  BOOL bSuccess
)
{
}

HRESULT
ApplicationRecoveryInProgress(
  PBOOL pbCancelled
)
{
	return S_OK;
}

HRESULT RegisterApplicationRecoveryCallback(
  APPLICATION_RECOVERY_CALLBACK pRecoveyCallback,
  PVOID                         pvParameter,
  DWORD                         dwPingInterval,
  DWORD                         dwFlags
)
{
	return S_OK;
}

HRESULT UnregisterApplicationRecoveryCallback()
{
	return S_OK;
}