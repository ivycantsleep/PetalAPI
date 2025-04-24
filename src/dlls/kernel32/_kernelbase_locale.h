#ifndef KERNELBASE_LOCALE_EXTRA_H // [

#define KERNELBASE_LOCALE_EXTRA_H

#include <_sal.h>
#include <_specstrings.h>

//from \base\fs\fastfat\splayup.c

typedef enum _COMPARISON {
    IsLessThan,
    IsGreaterThan,
    IsEqual
} COMPARISON;

/* CompareString results */
#define CSTR_LESS_THAN    1
#define CSTR_EQUAL        2
#define CSTR_GREATER_THAN 3

//from ReactOS lang.c
 struct locale_name
 {
     WCHAR  win_name[128];   /* Windows name ("en-US") */
     WCHAR  lang[128];       /* language ("en") (note: buffer contains the other strings too) */
     WCHAR *country;         /* country ("US") */
     WCHAR *charset;         /* charset ("UTF-8") for Unix format only */
     WCHAR *script;          /* script ("Latn") for Windows format only */
     WCHAR *modifier;        /* modifier or sort order */
     LCID   lcid;            /* corresponding LCID */
     int    matches;         /* number of elements matching LCID (0..4) */
     UINT   codepage;        /* codepage corresponding to charset */
 };
 
#define strpbrkW(str, accept) wcspbrk((str),(accept))
#define strcmpW(s1,s2) wcscmp((s1),(s2))
#define strncpyW(s1,s2,n) wcsncpy((s1),(s2),(n))
#define strlenW(s) wcslen((s))
#define strcpyW(d,s) wcscpy((d),(s))
//from Wine kernelbase/locale.c
#define strchrW(s,c) wcschr((s),(c))
//from Wine winnt.h
#define LOCALE_NAME_MAX_LENGTH     85

//from Wine winnls.h
#define FIND_STARTSWITH            0x00100000
#define FIND_ENDSWITH              0x00200000
#define FIND_FROMSTART             0x00400000
#define FIND_FROMEND               0x00800000
#define LOCALE_NAME_USER_DEFAULT    NULL
#define NORM_IGNORECASE            0x00000001
#define NORM_IGNORENONSPACE        0x00000002
#define NORM_IGNORESYMBOLS         0x00000004
#define SORT_DIGITSASNUMBERS       0x00000008
#define LINGUISTIC_IGNORECASE      0x00000010
#define LINGUISTIC_IGNOREDIACRITIC 0x00000020
#define SORT_STRINGSORT            0x00001000 /* Take punctuation into account */
#define NORM_IGNOREKANATYPE        0x00010000
#define NORM_IGNOREWIDTH           0x00020000
#define NORM_LINGUISTIC_CASING     0x08000000
#define LOCALE_SNAME                0x005C

static NLSTABLEINFO nls_info;

/***********************************************************************
 *	LocaleNameToLCID   (kernelbase.@) //https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/aa741018(v=vs.85)?redirectedfrom=MSDN
 */
typedef HRESULT (*LcidToRfc1766AProc)(LCID*,BSTR);
typedef BSTR (*SysAllocStringProc)(const OLECHAR*);
typedef VOID (*SysFreeStringProc)(BSTR);

int CompareStringOrdinal(
  _In_NLS_string_(cchCount1)LPCWCH lpString1,
  int                              cchCount1,
  _In_NLS_string_(cchCount2)LPCWCH lpString2,
  int                              cchCount2,
  BOOL                             bIgnoreCase
);

#endif