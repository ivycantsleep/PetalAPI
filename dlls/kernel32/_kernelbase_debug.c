/*
22-Nov-2020 moyefi implements the following Win32 APIs

QueryFullProcessImageNameW
QueryFullProcessImageNameA
*/

#include <basedll.h>
#include <_security.h>

#define ARRAY_SIZE( x ) (sizeof( x ) / sizeof( (x)[0] ))

//from Wine winnt.h
#define PROCESS_NAME_NATIVE        1

//from Wine kernelbase/debug.c

/******************************************************************
 *         QueryFullProcessImageNameW   (kernelbase.@)
 */
BOOL QueryFullProcessImageNameW(
  HANDLE hProcess,
  DWORD  dwFlags,
  LPWSTR lpExeName,
  PDWORD lpdwSize
)
{
    BYTE buffer[sizeof(UNICODE_STRING) + MAX_PATH*sizeof(WCHAR)];  /* this buffer should be enough */
    UNICODE_STRING *dynamic_buffer = NULL;
    UNICODE_STRING *result = NULL;
    NTSTATUS status;
    DWORD needed;

    /* FIXME: On Windows, ProcessImageFileName return an NT path. In Wine it
     * is a DOS path and we depend on this. */
    status = NtQueryInformationProcess( hProcess, ProcessImageFileName, buffer,
                                        sizeof(buffer) - sizeof(WCHAR), &needed );
    if (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        dynamic_buffer = RtlAllocateHeap( GetProcessHeap(), 0, needed + sizeof(WCHAR) );
        status = NtQueryInformationProcess( hProcess, ProcessImageFileName, dynamic_buffer,
                                            needed, &needed );
        result = dynamic_buffer;
    }
    else
        result = (UNICODE_STRING *)buffer;

    if (status) goto cleanup;

    if (dwFlags & PROCESS_NAME_NATIVE)
    {
        WCHAR drive[3];
        WCHAR device[1024];
        DWORD ntlen, devlen;

        if (result->Buffer[1] != ':' || result->Buffer[0] < 'A' || result->Buffer[0] > 'Z')
        {
            /* We cannot convert it to an NT device path so fail */
            status = STATUS_NO_SUCH_DEVICE;
            goto cleanup;
        }

        /* Find this drive's NT device path */
        drive[0] = result->Buffer[0];
        drive[1] = ':';
        drive[2] = 0;
        if (!QueryDosDeviceW(drive, device, ARRAY_SIZE(device)))
        {
            status = STATUS_NO_SUCH_DEVICE;
            goto cleanup;
        }

        devlen = lstrlenW(device);
        ntlen = devlen + (result->Length/sizeof(WCHAR) - 2);
        if (ntlen + 1 > *lpdwSize)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            goto cleanup;
        }
        *lpdwSize = ntlen;

        memcpy( lpExeName, device, devlen * sizeof(*device) );
        memcpy( lpExeName + devlen, result->Buffer + 2, result->Length - 2 * sizeof(WCHAR) );
        lpExeName[*lpdwSize] = 0;
        //TRACE( "NT path: %s\n", debugstr_w(lpExeName) );
    }
    else
    {
        if (result->Length/sizeof(WCHAR) + 1 > *lpdwSize)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            goto cleanup;
        }

        *lpdwSize = result->Length/sizeof(WCHAR);
        memcpy( lpExeName, result->Buffer, result->Length );
        lpExeName[*lpdwSize] = 0;
    }

cleanup:
    RtlFreeHeap( GetProcessHeap(), 0, dynamic_buffer );
    return set_ntstatus( status );
}

/******************************************************************
 *         QueryFullProcessImageNameA   (kernelbase.@)
 */
BOOL QueryFullProcessImageNameA(
  HANDLE hProcess,
  DWORD  dwFlags,
  LPSTR  lpExeName,
  PDWORD lpdwSize
)
{
    BOOL ret;
    DWORD sizeW = *lpdwSize;
    WCHAR *nameW = RtlAllocateHeap( GetProcessHeap(), 0, *lpdwSize * sizeof(WCHAR) );

    ret = QueryFullProcessImageNameW( hProcess, dwFlags, nameW, &sizeW );
    if (ret) ret = (WideCharToMultiByte( CP_ACP, 0, nameW, -1, lpExeName, *lpdwSize, NULL, NULL) > 0);
    if (ret) *lpdwSize = strlen( lpExeName );
    RtlFreeHeap( GetProcessHeap(), 0, nameW );
    return ret;
}