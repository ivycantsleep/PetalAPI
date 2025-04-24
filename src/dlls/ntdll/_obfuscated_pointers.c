/*
01-Dec-2020 moyefe uses the Vista version of 
	EncodePointer
	EncodePointer
	see https://source.winehq.org/patches/data/194622

28-Nov-2020 moyefi moves following Win32 APIs to NTDLL.DLL
	EncodePointer
	DecodePointer

28-Nov-2020 moyefi tests the following Win32 APIs
	EncodePointer
	DecodePointer

*/

#include "ldrp.h"
#include <ntos.h>

static DWORD_PTR pointer_obfuscator;

/***********************************************************************
 * rotl_ptr (internal)
 */
#ifdef _WIN64
#define ROT_BITS 64
#else
#define ROT_BITS 32
#endif

static DWORD_PTR rotl_ptr( DWORD_PTR num, int shift )
{
    shift &= ROT_BITS - 1;
    return (num << shift) | (num >> (ROT_BITS-shift));
}

/***********************************************************************
 * rotr_ptr (internal)
 */
static DWORD_PTR rotr_ptr( DWORD_PTR num, int shift )
{
    shift &= ROT_BITS - 1;
    return (num >> shift) | (num << (ROT_BITS-shift));
}

static DWORD_PTR get_pointer_obfuscator( void )
{
    if (!pointer_obfuscator)
    {
        ULONG seed = NtGetTickCount();
        ULONG_PTR rand;
        /* generate a random value for the obfuscator */
        rand = RtlUniform( &seed );

        /* handle 64bit pointers */
        rand ^= RtlUniform( &seed ) << ((sizeof (DWORD_PTR) - sizeof (ULONG))*8);
		
        /* set the high bits so dereferencing obfuscated pointers will (usually) crash */
        rand |= 0xc0000000 << ((sizeof (DWORD_PTR) - sizeof (ULONG))*8);

		InterlockedCompareExchangePointer( (void**) &pointer_obfuscator, (void*) rand, NULL );
    }
    return pointer_obfuscator;
}

/*************************************************************************
 * RtlEncodePointer   [NTDLL.@]
 */
PVOID
RtlEncodePointer(
  IN PVOID Ptr
)
{
    DWORD_PTR ptrval = (DWORD_PTR) Ptr;
    DWORD_PTR cookie = get_pointer_obfuscator();
    /* http://blogs.msdn.com/b/michael_howard/archive/2006/08/16/702707.aspx */
    ptrval = (ptrval ^ cookie);
    return (PVOID)rotr_ptr(ptrval, cookie);
}

PVOID 
RtlDecodePointer(
   PVOID Ptr
)
{
    DWORD_PTR ptrval = (DWORD_PTR) Ptr;
    DWORD_PTR cookie = get_pointer_obfuscator();
    ptrval = rotl_ptr(ptrval, cookie);
    return (PVOID)(ptrval ^ cookie);
}