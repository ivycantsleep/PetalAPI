/*
28-Nov-2020 moyefi tests and fixes the following Win32 APIs
GetFinalPathNameByHandleA
GetFinalPathNameByHandleW

22-Nov-2020 moyefi implements the following Win32 APIs

GetFileInformationByHandleEx
GetFinalPathNameByHandleA
GetFinalPathNameByHandleW
*/

#include <basedll.h>
#include <_security.h>
#include <_file.h>
#include <_kernelbase_locale.h>

//from Wine file.c

/***********************************************************************
 *	GetFileInformationByHandleEx   (kernelbase.@)
 */
BOOL GetFileInformationByHandleEx(
  HANDLE                    hFile,
  FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
  LPVOID                    lpFileInformation,
  DWORD                     dwBufferSize
)
{
    NTSTATUS status;
    IO_STATUS_BLOCK io;

    switch (FileInformationClass)
    {
    case FileStreamInfo:
    case FileCompressionInfo:
    case FileRemoteProtocolInfo:
    case FileFullDirectoryInfo:
    case FileFullDirectoryRestartInfo:
    case FileStorageInfo:
    case FileAlignmentInfo:
    case FileIdExtdDirectoryInfo:
    case FileIdExtdDirectoryRestartInfo:
	case FileIdInfo:
        //FIXME( "%p, %u, %p, %u\n", hFile, FileInformationClass, lpFileInformation, dwBufferSize );
        SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
        return FALSE;

    case FileAttributeTagInfo:
        status = NtQueryInformationFile( hFile, &io, lpFileInformation, dwBufferSize, FileAttributeTagInformation );
        break;

    case FileBasicInfo:
        status = NtQueryInformationFile( hFile, &io, lpFileInformation, dwBufferSize, FileBasicInformation );
        break;

    case FileStandardInfo:
        status = NtQueryInformationFile( hFile, &io, lpFileInformation, dwBufferSize, FileStandardInformation );
        break;

    case FileNameInfo:
        status = NtQueryInformationFile( hFile, &io, lpFileInformation, dwBufferSize, FileNameInformation );
        break;
    case FileIdBothDirectoryRestartInfo:
    case FileIdBothDirectoryInfo:
        status = NtQueryDirectoryFile( hFile, NULL, NULL, NULL, &io, lpFileInformation, dwBufferSize,
                                       FileIdBothDirectoryInformation, FALSE, NULL,
                                       (FileInformationClass == FileIdBothDirectoryRestartInfo) );
        break;

    case FileRenameInfo:
    case FileDispositionInfo:
    case FileAllocationInfo:
    case FileIoPriorityHintInfo:
    case FileEndOfFileInfo:
    default:
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    return set_ntstatus( status );
}


/***********************************************************************
 *           file_name_WtoA
 *
 * Convert a file name back to OEM/Ansi. Returns number of bytes copied.
 */
ULONG file_name_WtoA( PWSTR src, ULONG srclen, LPSTR dest, INT destlen )
{
    ULONG ret;
	//TRACE("srclen=%d\n",srclen);

    if (!destlen)
    {
		//TRACE("RtlUnicodeToMultiByteSize OUTLEN %ls %d\n", src, srclen * sizeof(WCHAR) );
		RtlUnicodeToMultiByteSize( 
			&ret, 
			src, 
			srclen * sizeof(WCHAR) 
		);
			
    }
    else
    {
		/*TRACE("RtlUnicodeToMultiByteN %s %d %d %ls %d\n",dest, 
			destlen, 
			&ret, 
			src, 
			srclen * sizeof(WCHAR) );*/
        RtlUnicodeToMultiByteN(
			dest, 
			destlen, 
			&ret, 
			src, 
			srclen * sizeof(WCHAR)
		);
    }
	//TRACE("LENOUT=%d\n",ret);
    return ret;
}

//https://stackoverflow.com/questions/65170/how-to-get-name-associated-with-open-handle

// converts
// "\Device\HarddiskVolume3"                                -> "E:"
// "\Device\HarddiskVolume3\Temp"                           -> "E:\Temp"
// "\Device\HarddiskVolume3\Temp\transparent.jpeg"          -> "E:\Temp\transparent.jpeg"
// "\Device\Harddisk1\DP(1)0-0+6\foto.jpg"                  -> "I:\foto.jpg"
// "\Device\TrueCryptVolumeP\Data\Passwords.txt"            -> "P:\Data\Passwords.txt"
// "\Device\Floppy0\Autoexec.bat"                           -> "A:\Autoexec.bat"
// "\Device\CdRom1\VIDEO_TS\VTS_01_0.VOB"                   -> "H:\VIDEO_TS\VTS_01_0.VOB"
// "\Device\Serial1"                                        -> "COM1"
// "\Device\USBSER000"                                      -> "COM4"
// "\Device\Mup\ComputerName\C$\Boot.ini"                   -> "\\ComputerName\C$\Boot.ini"
// "\Device\LanmanRedirector\ComputerName\C$\Boot.ini"      -> "\\ComputerName\C$\Boot.ini"
// "\Device\LanmanRedirector\ComputerName\Shares\Dance.m3u" -> "\\ComputerName\Shares\Dance.m3u"
// returns the length of the drive part, other
#define LSTATUS LONG 
typedef LSTATUS (*_RegOpenKeyExA)(HKEY hKey,LPCSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY  phkResult);
typedef LSTATUS (*_RegQueryValueExW) (HKEY hKey,LPCWSTR lpValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData, LPDWORD lpcbData);
typedef LSTATUS (*_RegCloseKey)(HKEY hKey);

DWORD GetDosPathFromNtPath(const wchar_t * u16_NTPath, wchar_t* ps_DosPath)
{
    DWORD u32_Error;
    if (wcsncmp(u16_NTPath, L"\\Device\\Serial", 14) == 0 || // e.g. "Serial1"
        wcsncmp(u16_NTPath, L"\\Device\\UsbSer", 14) == 0)   // e.g. "USBSER000"
    {
        HKEY h_Key; 
		wchar_t u16_ComPort[50];

        DWORD u32_Type;
        DWORD u32_Size = sizeof(u16_ComPort); 
		
		//only need for COM ports - not used at the moment...
		
		HMODULE advapi32=LoadLibrary("advapi32.dll");
		_RegOpenKeyExA __RegOpenKeyExA = (_RegOpenKeyExA)GetProcAddress(advapi32,"RegOpenKeyExA");
        if (u32_Error = __RegOpenKeyExA(HKEY_LOCAL_MACHINE, TEXT("Hardware\\DeviceMap\\SerialComm"), 0, KEY_QUERY_VALUE, &h_Key))
            return u32_Error;
		{
			_RegQueryValueExW __RegQueryValueExW = (_RegQueryValueExW)GetProcAddress(advapi32,"RegQueryValueExW");
			_RegCloseKey __RegCloseKey = (_RegCloseKey)GetProcAddress(advapi32,"RegCloseKey");
			if (
				u32_Error = __RegQueryValueExW(
						h_Key, 
						u16_NTPath, 
						0, 
						&u32_Type, 
						(BYTE*)u16_ComPort, 
						&u32_Size)
					)
			{
				__RegCloseKey(h_Key);
				FreeLibrary(advapi32);
				return ERROR_UNKNOWN_PORT;
			}
			wcsncpy(ps_DosPath, u16_ComPort, wcslen(u16_ComPort));
			__RegCloseKey(h_Key);
			FreeLibrary(advapi32);
			return 0;
		}
    }
	
    if (wcsncmp(u16_NTPath, L"\\Device\\LanmanRedirector\\", 25) == 0) // Win XP
    {
		wcsncpy(ps_DosPath, L"\\\\", 2);
		wcsncat(ps_DosPath, (u16_NTPath + 25), wcslen(u16_NTPath) - 25); 
        return 0;
    }

    if (wcsncmp(u16_NTPath, L"\\Device\\Mup\\", 12) == 0) // Win 7
    {
		wcsncpy(ps_DosPath, L"\\\\", 2);
		wcsncat(ps_DosPath, (u16_NTPath + 12), wcslen(u16_NTPath) - 22); 
        return 0;
    }
	{
		wchar_t u16_Drives[300];
		if (!GetLogicalDriveStringsW(300, &u16_Drives[0]))
			return GetLastError();
		{
			wchar_t* u16_Drv = &u16_Drives[0];
			while (u16_Drv[0])
			{
				wchar_t* u16_Next = u16_Drv + wcslen(u16_Drv) + 1;

				u16_Drv[2] = 0; // the backslash is not allowed for QueryDosDevice()
				{
					DWORD result;
					wchar_t u16_NtVolume[1000];
					u16_NtVolume[0] = 0;

					// may return multiple strings!
					// returns very weird strings for network shares
					result = QueryDosDeviceW(u16_Drv, &u16_NtVolume[0], sizeof(u16_NtVolume) /2);
					if (result==0) {				
						return GetLastError();
					}
					{
						size_t s32_Len = wcslen(u16_NtVolume);												
						if (s32_Len > 0 && wcsncmp(u16_NTPath, u16_NtVolume, s32_Len) == 0)
						{
							wcsncpy(ps_DosPath, u16_Drv, result);
							wcsncat(ps_DosPath, (u16_NTPath + s32_Len), wcslen(u16_NTPath) - s32_Len); 
							return 0;
						}
					}
					u16_Drv = u16_Next;
				}
			}
		}
	}
    return ERROR_BAD_PATHNAME;
}

DWORD GetFinalPathNameByHandleW(
  HANDLE hFile,
  LPWSTR lpszFilePath,
  DWORD  cchFilePath,
  DWORD  dwFlags
)
{
    NTSTATUS status;

	if (lpszFilePath)
		lpszFilePath[0] = 0;
	
	// FILE_NAME_OPENED is not supported yet, and would require Wineserver changes 
	if (dwFlags & FILE_NAME_OPENED)
	{
		//FIXME("FILE_NAME_OPENED not supported\n");
		dwFlags &= ~FILE_NAME_OPENED;
	}
			
    if (dwFlags & ~(FILE_NAME_OPENED | VOLUME_NAME_GUID | VOLUME_NAME_NONE | VOLUME_NAME_NT))
    {
        //WARN("Unknown flags: %x\n", dwFlags);
        SetLastError( ERROR_INVALID_PARAMETER );
        return 0;
    }
	{
		wchar_t dos_path[MAX_PATH];
		wchar_t buffer[sizeof(OBJECT_NAME_INFORMATION) + MAX_PATH + 1];
		OBJECT_NAME_INFORMATION *info = (OBJECT_NAME_INFORMATION*)&buffer;
		DWORD ReturnLength;
		DWORD result;
		void * ptr;
		 /* get object name */
		status = NtQueryObject( hFile, ObjectNameInformation, &buffer, sizeof(buffer) - sizeof(WCHAR), &ReturnLength );
		if (!set_ntstatus( status )) return 0;

		if (!info->Name.Buffer)
		{
			SetLastError( ERROR_INVALID_HANDLE );
			return 0;
		}
		//  hFile belonging to c:\WINDOWS\win.ini
		//  Info->Name.Buffer is like \Device\HarddiskVolume1\WINDOWS\win.ini
		if (info->Name.Length < 4 * sizeof(WCHAR) || info->Name.Buffer[0] != '\\')
		{
			
			//FIXME("Unexpected object name: %s\n", debugstr_wn(info->Name.Buffer, info->Name.Length / sizeof(WCHAR)));
			SetLastError( ERROR_GEN_FAILURE );
			return 0;
		}
		
		if (dwFlags == VOLUME_NAME_NT) {
			if (lpszFilePath)
				wcsncpy(lpszFilePath, info->Name.Buffer,  info->Name.Length);
			return info->Name.Length;
		}
		result = GetDosPathFromNtPath(info->Name.Buffer,dos_path);
							
		if (result) {
			SetLastError( result );
			return 0;
		}

		if (dwFlags == VOLUME_NAME_DOS) { //returns as C:\WINDOWS\win.ini for \\?\C:\WINDOWS\win.ini
			if (lpszFilePath) {
				wcsncpy(lpszFilePath, L"\\\\?\\", 4);
				lpszFilePath[4] = 0;
				wcsncat(lpszFilePath, dos_path, cchFilePath); 
				lpszFilePath[cchFilePath] = 0;
			}
			return wcslen(dos_path)+4;
		}
		if (dwFlags == VOLUME_NAME_NONE) //returns as \WINDOWS\win.ini for C:\WINDOWS\win.ini
		{
			ptr = dos_path + 2;
			result = wcslen(ptr);
			if (lpszFilePath) {
				if (result < cchFilePath) {
					wcsncpy(lpszFilePath, ptr, result);
					lpszFilePath[result] = 0;
				} else {
					SetLastError(ERROR_NOT_ENOUGH_MEMORY);
					return 0;
				}
			}
			return result;
		}
		else if (dwFlags == VOLUME_NAME_GUID) //returns as \\?\Volume{e5f98bad-0fc0-11eb-badc-8064chan63}\WINDOWS\win.ini for C:\WINDOWS\win.ini
		{
			wchar_t volume_prefix[51];
			wchar_t temp;
			/* terminate dos_path behind drive:\  ->  C:\WINDOWS\win.ini --> C:\ */
			temp = dos_path[3];
			dos_path[3] = 0;
			
			// GetVolumeNameForVolumeMountPointW sets error code on failure
			if (!GetVolumeNameForVolumeMountPointW( dos_path, volume_prefix, 50 )) return 0;
			dos_path[3] = temp;
			ptr = dos_path + 3;
			result = wcslen(volume_prefix) + wcslen(ptr);			
			if (lpszFilePath) {
				if (result < cchFilePath)
				{
					wcsncpy(lpszFilePath, volume_prefix, wcslen(volume_prefix));
					lpszFilePath[wcslen(volume_prefix)] = 0;
					wcsncat(lpszFilePath, ptr, wcslen(ptr));
				} else {
					SetLastError(ERROR_NOT_ENOUGH_MEMORY);
					return 0;
				}
			}
			return result;
		}
		// Windows crashes here, but we prefer returning ERROR_INVALID_PARAMETER 
		//WARN("Invalid combination of flags: %x\n", dwFlags);
		SetLastError( ERROR_INVALID_PARAMETER );
		return 0;
	}
}

/***********************************************************************
 *	GetFinalPathNameByHandleA   (kernelbase.@)
 */
DWORD GetFinalPathNameByHandleA(
  HANDLE hFile,
  LPSTR  lpszFilePath,
  DWORD  cchFilePath,
  DWORD  dwFlags
)
{
    wchar_t* str;
    DWORD result, len;

    //TRACE( "(%p,%p,%d,%x)\n", hFile, lpszFilePath, cchFilePath, dwFlags);
   
    len = GetFinalPathNameByHandleW(hFile, NULL, 0, dwFlags);
    if (len == 0) return 0;

    str = RtlAllocateHeap(GetProcessHeap(), 0, len * sizeof(wchar_t));
    if (!str)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
		
    result = GetFinalPathNameByHandleW(hFile, str, len+1, dwFlags);
    if (result != len)
    {
        RtlFreeHeap(GetProcessHeap(), 0, str);
        return 0;
    }

    len = file_name_WtoA( str, wcslen(str) +1, NULL, 0 );
	
    if (cchFilePath < len)
    {
        RtlFreeHeap(GetProcessHeap(), 0, str);
        return len - 1;
    }
    file_name_WtoA( str, wcslen(str)+1, lpszFilePath, len );
    RtlFreeHeap(GetProcessHeap(), 0, str);
    return len - 1;
}