/*
18-Nov-2020 moyefi implements the following Win32 APIs

LCIDToLocaleName
LocaleNameToLCID
IsValidLocaleName 

CompareStringEx
CompareStringOrdinal
FindNLSString
FindNLSStringEx
FindStringOrdinal

*/

#include <basedll.h>
#include <_apiset.h>
#include <_apisetcconv.h>
#include <_list.h>
#include <_security.h>
#include <_utils.h>
#include <_kernelbase_locale.h>

LCID LocaleNameToLCID(
  LPCWSTR lpName,
  DWORD   dwFlags
)
{
	LCID lcid;
	
	HMODULE mlang=LoadLibrary("mlang.dll");
	
	LcidToRfc1766AProc GetLcidFromRfc1766Addr = (LcidToRfc1766AProc)GetProcAddress(mlang,"GetLcidFromRfc1766");
	
	HMODULE OleAut32=LoadLibrary("OleAut32.dll");
    
	SysAllocStringProc SysAllocStringAddr = (SysAllocStringProc)GetProcAddress(OleAut32,"SysAllocString");
	SysFreeStringProc SysFreeStringAddr = (SysFreeStringProc)GetProcAddress(OleAut32,"SysFreeString");
	
    BSTR bstr = SysAllocStringAddr(lpName);
	
	GetLcidFromRfc1766Addr(&lcid,bstr);
	
	SysFreeStringAddr(bstr);
	
	FreeLibrary(mlang);
	FreeLibrary(OleAut32);
	return lcid;
}

/******************************************************************************
 *	RtlCompareUnicodeStrings   (NTDLL.@)
 */
LONG CompareUnicodeStrings( const WCHAR *s1, SIZE_T len1, const WCHAR *s2, SIZE_T len2,
                                      BOOL case_insensitive )
{
	LONG ret;
    if (case_insensitive) {
		ret = _wcsicmp(s1, s2);
	} else {
		ret = wcscmp(s1, s2);
	}
	return ret;
}

/******************************************************************************
 *	IsValidLocaleName   (kernelbase.@)
 */
BOOL IsValidLocaleName(
  LPCWSTR lpLocaleName
)
{
    return !(LocaleNameToLCID( lpLocaleName, 0 ) == 0);
}

/***********************************************************************
 *	LCIDToLocaleName   (kernelbase.@)
 */
int LCIDToLocaleName(
  LCID   Locale,
  LPWSTR lpName,
  int    cchName,
  DWORD  dwFlags
)
{
    //static int once;
    //if (dwFlags && !once++) FIXME( "unsupported flags %x\n", dwFlags );

    return GetLocaleInfoW( Locale, LOCALE_SNAME | LOCALE_NOUSEROVERRIDE, lpName, cchName );
}
/******************************************************************************
 *	CompareStringOrdinal   (kernelbase.@)
 */
int CompareStringOrdinal(
  _In_NLS_string_(cchCount1)LPCWCH lpString1,
  int                              cchCount1,
  _In_NLS_string_(cchCount2)LPCWCH lpString2,
  int                              cchCount2,
  BOOL                             bIgnoreCase
)
{
    int ret;

    if (!lpString1 || !cchCount2)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return 0;
    }
    if (cchCount1 < 0) cchCount1 = lstrlenW( lpString1 );
    if (cchCount2 < 0) cchCount2 = lstrlenW( lpString2 );

    ret = CompareUnicodeStrings( lpString1, cchCount1, lpString2, cchCount2, bIgnoreCase );
    if (ret < 0) return CSTR_LESS_THAN;
    if (ret > 0) return CSTR_GREATER_THAN;
    return CSTR_EQUAL;
}

/******************************************************************************
 *	CompareStringEx   (kernelbase.@)
 */
 int CompareStringEx(
  LPCWSTR                          lpLocaleName,
  DWORD                            dwCmpFlags,
  _In_NLS_string_(cchCount1)LPCWCH lpString1,
  int                              cchCount1,
  _In_NLS_string_(cchCount2)LPCWCH lpString2,
  int                              cchCount2,
  LPNLSVERSIONINFO                 lpVersionInformation,
  LPVOID                           lpReserved,
  LPARAM                           lParam
)
{
	//simplified Wine had to much dependencies
	
    DWORD supported_flags = NORM_IGNORECASE /*| NORM_IGNORENONSPACE | NORM_IGNORESYMBOLS | SORT_STRINGSORT |
                            NORM_IGNOREKANATYPE | NORM_IGNOREWIDTH | LOCALE_USE_CP_ACP*/;
    DWORD semistub_flags = 0;//NORM_LINGUISTIC_CASING | LINGUISTIC_IGNORECASE | 0x10000000;
    /* 0x10000000 is related to diacritics in Arabic, Japanese, and Hebrew */
    INT ret;
    static int once;

    if (!lpString1 || !lpString2)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return 0;
    }

    if (dwCmpFlags & ~(supported_flags | semistub_flags))
    {
        SetLastError( ERROR_INVALID_FLAGS );
        return 0;
    }

	if (dwCmpFlags & NORM_IGNORECASE) {
		ret = _wcsicmp(lpString1, lpString2);
	} else {
		ret = wcscmp(lpString1, lpString2);
	}
    if (!ret) return CSTR_EQUAL;
    return (ret < 0) ? CSTR_LESS_THAN : CSTR_GREATER_THAN;
}

/**************************************************************************
 *	FindNLSStringEx   (kernelbase.@)
 */
int FindNLSStringEx(
  LPCWSTR          lpLocaleName,
  DWORD            dwFindNLSStringFlags,
  LPCWSTR          lpStringSource,
  int              cchSource,
  LPCWSTR          lpStringValue,
  int              cchValue,
  LPINT            pcchFound,
  LPNLSVERSIONINFO lpVersionInformation,
  LPVOID           lpReserved,
  LPARAM           sortHandle
)
{
    /* FIXME: this function should normalize strings before calling CompareStringEx() */
    DWORD mask = dwFindNLSStringFlags;
    int offset, inc, count;

    /* TRACE( "%s %x %s %d %s %d %p %p %p %ld\n", wine_dbgstr_w(lpLocaleName), dwFindNLSStringFlags,
           wine_dbgstr_w(lpStringSource), cchSource, wine_dbgstr_w(lpStringValue), cchValue, pcchFound,
           lpVersionInformation, lpReserved, sortHandle );*/

    if (lpVersionInformation || lpReserved || sortHandle || !IsValidLocaleName(lpLocaleName) ||
        !lpStringSource || !cchSource || cchSource < -1 || !lpStringValue || !cchValue || cchValue < -1)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return -1;
    }
    if (cchSource == -1) cchSource = lstrlenW(lpStringSource);
    if (cchValue == -1) cchValue = lstrlenW(lpStringValue);

    cchSource -= cchValue;
    if (cchSource < 0) return -1;

    mask = dwFindNLSStringFlags & ~(FIND_FROMSTART | FIND_FROMEND | FIND_STARTSWITH | FIND_ENDSWITH);
    count = dwFindNLSStringFlags & (FIND_FROMSTART | FIND_FROMEND) ? cchSource + 1 : 1;
    offset = dwFindNLSStringFlags & (FIND_FROMSTART | FIND_STARTSWITH) ? 0 : cchSource;
    inc = dwFindNLSStringFlags & (FIND_FROMSTART | FIND_STARTSWITH) ? 1 : -1;
    while (count--)
    {
        if (CompareStringEx( lpLocaleName, mask, lpStringSource + offset, cchValue,
                             lpStringValue, cchValue, NULL, NULL, 0 ) == CSTR_EQUAL)
        {
            if (pcchFound) *pcchFound = cchValue;
            return offset;
        }
        offset += inc;
    }
    return -1;
}

/**************************************************************************
 *	FindNLSString   (kernelbase.@)
 */
int FindNLSString(
  LCID    Locale,
  DWORD   dwFindNLSStringFlags,
  LPCWSTR lpStringSource,
  int     cchSource,
  LPCWSTR lpStringValue,
  int     cchValue,
  LPINT   pcchFound
)
{
    WCHAR locale[LOCALE_NAME_MAX_LENGTH];

    LCIDToLocaleName( Locale, locale, ARRAY_SIZE(locale), 0 );
    return FindNLSStringEx( locale, dwFindNLSStringFlags, lpStringSource, cchSource, lpStringValue, cchValue, pcchFound, NULL, NULL, 0 );
}


/******************************************************************************
 *	FindStringOrdinal   (kernelbase.@)
 */
int FindStringOrdinal(
  DWORD   dwFindStringOrdinalFlags,
  LPCWSTR lpStringSource,
  int     cchSource,
  LPCWSTR lpStringValue,
  int     cchValue,
  BOOL    bIgnoreCase
)
{
    INT offset, inc, count;

   /* TRACE( "%#x %s %d %s %d %d\n", dwFindStringOrdinalFlags, wine_dbgstr_w(src), cchSource,
           wine_dbgstr_w(lpStringValue), cchValue, bIgnoreCase );*/

    if (!lpStringSource || !lpStringValue)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return -1;
    }

    if (dwFindStringOrdinalFlags != FIND_FROMSTART && dwFindStringOrdinalFlags != FIND_FROMEND && dwFindStringOrdinalFlags != FIND_STARTSWITH && dwFindStringOrdinalFlags != FIND_ENDSWITH)
    {
        SetLastError( ERROR_INVALID_FLAGS );
        return -1;
    }

    if (cchSource == -1) cchSource = lstrlenW( lpStringSource );
    if (cchValue == -1) cchValue = lstrlenW( lpStringValue );

    SetLastError( ERROR_SUCCESS );
    cchSource -= cchValue;
    if (cchSource < 0) return -1;

    count = dwFindStringOrdinalFlags & (FIND_FROMSTART | FIND_FROMEND) ? cchSource + 1 : 1;
    offset = dwFindStringOrdinalFlags & (FIND_FROMSTART | FIND_STARTSWITH) ? 0 : cchSource;
    inc = dwFindStringOrdinalFlags & (FIND_FROMSTART | FIND_STARTSWITH) ? 1 : -1;
    while (count--)
    {
        if (CompareStringOrdinal( lpStringSource + offset, cchValue, lpStringValue, cchValue, bIgnoreCase ) == CSTR_EQUAL)
            return offset;
        offset += inc;
    }
    return -1;
}
