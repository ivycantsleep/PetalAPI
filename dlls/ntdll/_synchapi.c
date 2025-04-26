/*
30-Nov-2020 moyefi moves the following Win32 APIs to NTDLL.DLL

	RtlInitializeSRWLock
    RtlAcquireSRWLockExclusive
	RtlAcquireSRWLockShared
	RtlTryAcquireSRWLockExclusive
	RtlReleaseSRWLockExclusive
	RtlReleaseSRWLockShared
	RtlWakeByAddressAll
	RtlWakeAllConditionVariable
	RtlWakeConditionVariable
*/

#include "ldrp.h"
#include <ntos.h>
#include <windef.h>
#include <winbase.h>

typedef struct _RTL_SRWLOCK {
    PVOID Ptr;
} RTL_SRWLOCK, *PRTL_SRWLOCK;

#define RTL_SRWLOCK_INIT {0}

#define SRWLOCK_MASK_IN_EXCLUSIVE     0x80000000
#define SRWLOCK_MASK_EXCLUSIVE_QUEUE  0x7fff0000
#define SRWLOCK_MASK_SHARED_QUEUE     0x0000ffff
#define SRWLOCK_RES_EXCLUSIVE         0x00010000
#define SRWLOCK_RES_SHARED            0x00000001

#define srwlock_key_exclusive(lock)   ((void *)(((ULONG_PTR)&lock->Ptr + 3) & ~1))
#define srwlock_key_shared(lock)      ((void *)(((ULONG_PTR)&lock->Ptr + 1) & ~1))

typedef struct _RTL_CONDITION_VARIABLE {                    
        PVOID Ptr;                                       
} RTL_CONDITION_VARIABLE, *PRTL_CONDITION_VARIABLE;
typedef RTL_CONDITION_VARIABLE CONDITION_VARIABLE, *PCONDITION_VARIABLE;

#define RTL_CONDITION_VARIABLE_INIT {0}                 
#define RTL_CONDITION_VARIABLE_LOCKMODE_SHARED  0x1    

//from Wine ntddll\sync.c
#define RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO 0x1000000
#define RTL_CRITICAL_SECTION_FLAG_DYNAMIC_SPIN  0x2000000
#define RTL_CRITICAL_SECTION_FLAG_STATIC_INIT   0x4000000
#define RTL_CRITICAL_SECTION_ALL_FLAG_BITS      0xFF000000
#define RTL_CRITICAL_SECTION_FLAG_RESERVED      (RTL_CRITICAL_SECTION_ALL_FLAG_BITS & ~0x7000000)

/* one-time initialisation API */
typedef union _RTL_RUN_ONCE {
    PVOID Ptr;
} RTL_RUN_ONCE, *PRTL_RUN_ONCE;
typedef RTL_RUN_ONCE  INIT_ONCE;
typedef PRTL_RUN_ONCE PINIT_ONCE;
typedef PRTL_RUN_ONCE LPINIT_ONCE;
#define RTL_RUN_ONCE_INIT {0}
#define RTL_RUN_ONCE_CHECK_ONLY     0x00000001
#define RTL_RUN_ONCE_ASYNC          0x00000002
#define RTL_RUN_ONCE_INIT_FAILED    0x00000004
typedef DWORD WINAPI RTL_RUN_ONCE_INIT_FN(PRTL_RUN_ONCE, PVOID, PVOID*);
typedef RTL_RUN_ONCE_INIT_FN *PRTL_RUN_ONCE_INIT_FN;


//from Wine crtsecion.c
void *no_debug_info_marker = (void *)(ULONG_PTR)-1;

static LARGE_INTEGER zero_timeout = {0};

static PRTL_CRITICAL_SECTION addr_mutex = {0};

void srwlock_check_invalid( unsigned int val )
{
    /* Throw exception if it's impossible to acquire/release this lock. */
    if ((val & SRWLOCK_MASK_EXCLUSIVE_QUEUE) == SRWLOCK_MASK_EXCLUSIVE_QUEUE ||
            (val & SRWLOCK_MASK_SHARED_QUEUE) == SRWLOCK_MASK_SHARED_QUEUE)
        RtlRaiseStatus(STATUS_RESOURCE_NOT_OWNED);
}

void srwlock_leave_exclusive( RTL_SRWLOCK *lock, unsigned int val )
{
    /* Used when a thread leaves an exclusive section. If there are other
     * exclusive access threads they are processed first, followed by
     * the shared waiters. */
    if (val & SRWLOCK_MASK_EXCLUSIVE_QUEUE)
        NtReleaseKeyedEvent( 0, srwlock_key_exclusive(lock), FALSE, NULL );
    else
    {
        val &= SRWLOCK_MASK_SHARED_QUEUE; /* remove SRWLOCK_MASK_IN_EXCLUSIVE */
        while (val--)
            NtReleaseKeyedEvent( 0, srwlock_key_shared(lock), FALSE, NULL );
    }
}

unsigned int srwlock_unlock_exclusive( unsigned int *dest, int incr )
{
    unsigned int val, tmp;
    /* Atomically modifies the value of *dest by adding incr. If the queue of
     * threads waiting for exclusive access is empty, then remove the
     * SRWLOCK_MASK_IN_EXCLUSIVE flag (only the shared queue counter will
     * remain). */
    for (val = *dest;; val = tmp)
    {
        tmp = val + incr;
        srwlock_check_invalid( tmp );
        if (!(tmp & SRWLOCK_MASK_EXCLUSIVE_QUEUE))
            tmp &= SRWLOCK_MASK_SHARED_QUEUE;
        if ((tmp = InterlockedCompareExchange( (LONG *)dest, tmp, val)) == val)
            break;
    }
    return val;
}

unsigned int srwlock_lock_exclusive( unsigned int *dest, int incr )
{
    unsigned int val, tmp;
    /* Atomically modifies the value of *dest by adding incr. If the shared
     * queue is empty and there are threads waiting for exclusive access, then
     * sets the mark SRWLOCK_MASK_IN_EXCLUSIVE to signal other threads that
     * they are allowed again to use the shared queue counter. */
    for (val = *dest;; val = tmp)
    {
        tmp = val + incr;
        srwlock_check_invalid( tmp );
        if ((tmp & SRWLOCK_MASK_EXCLUSIVE_QUEUE) && !(tmp & SRWLOCK_MASK_SHARED_QUEUE))
            tmp |= SRWLOCK_MASK_IN_EXCLUSIVE;
        if ((tmp = InterlockedCompareExchange( (LONG *)dest, tmp, val )) == val)
            break;
    }
    return val;
}

void srwlock_leave_shared( RTL_SRWLOCK *lock, unsigned int val )
{
    /* Wake up one exclusive thread as soon as the last shared access thread
     * has left. */
    if ((val & SRWLOCK_MASK_EXCLUSIVE_QUEUE) && !(val & SRWLOCK_MASK_SHARED_QUEUE))
        NtReleaseKeyedEvent( 0, srwlock_key_exclusive(lock), FALSE, NULL );
}

//
// Define the slim r/w lock
//

typedef RTL_SRWLOCK SRWLOCK, *PSRWLOCK;

#define SRWLOCK_INIT RTL_SRWLOCK_INIT

void
RtlInitializeSRWLock(
  PSRWLOCK SRWLock
)
{
	memset(&SRWLock, 0, sizeof(SRWLock));
}

void 
RtlAcquireSRWLockExclusive(
	RTL_SRWLOCK *SRWLock
	)
{
    if (srwlock_lock_exclusive( (unsigned int *)&SRWLock->Ptr, SRWLOCK_RES_EXCLUSIVE ))
        NtWaitForKeyedEvent( 0, srwlock_key_exclusive(SRWLock), FALSE, NULL );
}

void
RtlAcquireSRWLockShared(
      PSRWLOCK SRWLock
    )
{
	unsigned int val, tmp;

    /* Acquires a shared lock. If it's currently not possible to add elements to
     * the shared queue, then request exclusive access instead. */
    for (val = *(unsigned int *)&SRWLock->Ptr;; val = tmp)
    {
        if ((val & SRWLOCK_MASK_EXCLUSIVE_QUEUE) && !(val & SRWLOCK_MASK_IN_EXCLUSIVE))
            tmp = val + SRWLOCK_RES_EXCLUSIVE;
        else
            tmp = val + SRWLOCK_RES_SHARED;
        if ((tmp = InterlockedCompareExchange( (LONG *)&SRWLock->Ptr, tmp, val )) == val)
            break;
    }

    /* Drop exclusive access again and instead requeue for shared access. */
    if ((val & SRWLOCK_MASK_EXCLUSIVE_QUEUE) && !(val & SRWLOCK_MASK_IN_EXCLUSIVE))
    {
        NtWaitForKeyedEvent( 0, srwlock_key_exclusive(SRWLock), FALSE, NULL );
        val = srwlock_unlock_exclusive( (unsigned int *)&SRWLock->Ptr, (SRWLOCK_RES_SHARED
                                        - SRWLOCK_RES_EXCLUSIVE) ) - SRWLOCK_RES_EXCLUSIVE;
        srwlock_leave_exclusive( SRWLock, val );
    }

    if (val & SRWLOCK_MASK_EXCLUSIVE_QUEUE)
        NtWaitForKeyedEvent( 0, srwlock_key_shared(SRWLock), FALSE, NULL );
}

void
RtlReleaseSRWLockExclusive(
	PSRWLOCK SRWLock
	)
{
    srwlock_leave_exclusive( SRWLock, srwlock_unlock_exclusive( (unsigned int *)&SRWLock->Ptr,
                             - SRWLOCK_RES_EXCLUSIVE ) - SRWLOCK_RES_EXCLUSIVE );
}

void
RtlReleaseSRWLockShared(
	PSRWLOCK SRWLock
)
{
    srwlock_leave_shared( SRWLock, srwlock_lock_exclusive( (unsigned int *)&SRWLock->Ptr,
                          - SRWLOCK_RES_SHARED ) - SRWLOCK_RES_SHARED );
}

/***********************************************************************
 *              RtlTryAcquireSRWLockExclusive (NTDLL.@)
 *
 * NOTES
 *  Similarly to AcquireSRWLockExclusive, recursive calls are not allowed
 *  and will fail with a FALSE return value.
 */
BOOLEAN 
RtlTryAcquireSRWLockExclusive(
  PSRWLOCK SRWLock
)
{
    return (BOOLEAN)InterlockedCompareExchange( (LONG *)&SRWLock->Ptr, SRWLOCK_MASK_IN_EXCLUSIVE |
                                       SRWLOCK_RES_EXCLUSIVE, 0 ) == 0;
}

/***********************************************************************
 *           RtlInitializeConditionVariable   (NTDLL.@)
 *
 * Initializes the condition variable with NULL.
 *
 * PARAMS
 *  variable [O] condition variable
 *
 * RETURNS
 *  Nothing.
 */
void 
RtlInitializeConditionVariable( RTL_CONDITION_VARIABLE *variable )
{
    variable->Ptr = NULL;
}

//https://www.embedded-computing.com/guest-blogs/thread-synchronization-in-linux-and-windows-systems-part-3
//rewitten from unix functions of Wine
/***********************************************************************
 *           RtlWakeAddressAll    (NTDLL.@)
 */
void
RtlWakeByAddressAll ( PVOID addr )
{
	if (!addr_mutex)
		RtlInitializeCriticalSection( addr_mutex );
    RtlEnterCriticalSection( addr_mutex );
    while (NtReleaseKeyedEvent( 0, addr, 0, &zero_timeout ) == STATUS_SUCCESS) {}
    RtlLeaveCriticalSection( addr_mutex );
}

/***********************************************************************
 *           RtlWakeAddressSingle (NTDLL.@)
 */
void
RtlWakeAddressSingle( PVOID addr )
{
    if (!addr_mutex)
		RtlInitializeCriticalSection( addr_mutex );
    RtlEnterCriticalSection( addr_mutex );
    NtReleaseKeyedEvent( 0, addr, 0, &zero_timeout );
    RtlLeaveCriticalSection( addr_mutex );
}
//until here

/***********************************************************************
 *           RtlWakeConditionVariable   (NTDLL.@)
 *
 * Wakes up one thread waiting on the condition variable.
 *
 * PARAMS
 *  variable [I/O] condition variable to wake up.
 *
 * RETURNS
 *  Nothing.
 *
 * NOTES
 *  The calling thread does not have to own any lock in order to call
 *  this function.
 */
void 
RtlWakeConditionVariable( RTL_CONDITION_VARIABLE *variable )
{
	InterlockedIncrement( (LONG *)&variable->Ptr );
    RtlWakeAddressSingle( variable );
}

/***********************************************************************
 *           RtlWakeAllConditionVariable   (NTDLL.@)
 *
 * See WakeConditionVariable, wakes up all waiting threads.
 */
void 
RtlWakeAllConditionVariable( RTL_CONDITION_VARIABLE *variable )
{
    InterlockedIncrement( (LONG *)&variable->Ptr );
    RtlWakeByAddressAll ( variable );
}



/***********************************************************************
 *           RtlInitializeCriticalSectionEx   (NTDLL.@)
 *
 * Initialises a new critical section with a given spin count and flags.
 *
 * PARAMS
 *   crit      [O] Critical section to initialise.
 *   spincount [I] Number of times to spin upon contention.
 *   flags     [I] RTL_CRITICAL_SECTION_FLAG_ flags from winnt.h.
 *
 * RETURNS
 *  STATUS_SUCCESS.
 *
 * NOTES
 *  Available on Vista or later.
 *
 * SEE
 *  RtlInitializeCriticalSection(), RtlDeleteCriticalSection(),
 *  RtlEnterCriticalSection(), RtlLeaveCriticalSection(),
 *  RtlTryEnterCriticalSection(), RtlSetCriticalSectionSpinCount()
 */
BOOL
RtlInitializeCriticalSectionEx (
    PRTL_CRITICAL_SECTION lpCriticalSection,
	DWORD             dwSpinCount,
	DWORD             Flags
)
{ 
    //if (Flags & (RTL_CRITICAL_SECTION_FLAG_DYNAMIC_SPIN|RTL_CRITICAL_SECTION_FLAG_STATIC_INIT))
      //  FIXME("(%p,%u,0x%08x) semi-stub\n", lpCriticalSection, dwSpinCount, Flags);

    /* FIXME: if RTL_CRITICAL_SECTION_FLAG_STATIC_INIT is given, we should use
     * memory from a static pool to hold the debug info. Then heap.c could pass
     * this flag rather than initialising the process heap CS by hand. If this
     * is done, then debug info should be managed through Rtlp[Allocate|Free]DebugInfo
     * so (e.g.) MakeCriticalSectionGlobal() doesn't free it using HeapFree().
     */
    if (Flags & RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO)
        lpCriticalSection->DebugInfo = no_debug_info_marker;
    else
    {
        lpCriticalSection->DebugInfo = RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(RTL_CRITICAL_SECTION_DEBUG));
        if (lpCriticalSection->DebugInfo)
        {
            lpCriticalSection->DebugInfo->Type = 0;
            lpCriticalSection->DebugInfo->CreatorBackTraceIndex = 0;
            lpCriticalSection->DebugInfo->CriticalSection = lpCriticalSection;
            lpCriticalSection->DebugInfo->ProcessLocksList.Blink = &(lpCriticalSection->DebugInfo->ProcessLocksList);
            lpCriticalSection->DebugInfo->ProcessLocksList.Flink = &(lpCriticalSection->DebugInfo->ProcessLocksList);
            lpCriticalSection->DebugInfo->EntryCount = 0;
            lpCriticalSection->DebugInfo->ContentionCount = 0;
            memset( lpCriticalSection->DebugInfo->Spare, 0, sizeof(lpCriticalSection->DebugInfo->Spare) );
        }
    }
    lpCriticalSection->LockCount      = -1;
    lpCriticalSection->RecursionCount = 0;
    lpCriticalSection->OwningThread   = 0;
    lpCriticalSection->LockSemaphore  = 0;
    if (NtCurrentTeb()->ProcessEnvironmentBlock->NumberOfProcessors <= 1) dwSpinCount = 0;
    lpCriticalSection->SpinCount = dwSpinCount & ~0x80000000;
    return STATUS_SUCCESS;
}


/******************************************************************
 *              RtlRunOnceBeginInitialize (NTDLL.@)
 */
//adjusted for Windows NT
NTSTATUS RtlRunOnceBeginInitialize(
  PRTL_RUN_ONCE RunOnce,
  ULONG         Flags,
  PVOID         *Context
)
{
    if (Flags & RTL_RUN_ONCE_CHECK_ONLY)
    {
        ULONG_PTR val = (ULONG_PTR)RunOnce->Ptr;

        if (Flags & RTL_RUN_ONCE_ASYNC) return STATUS_INVALID_PARAMETER;
        if ((val & 3) != 2) return STATUS_UNSUCCESSFUL;
        if (Context) *Context = (void *)(val & ~3);
        return STATUS_SUCCESS;
    }

    for (;;)
    {
        ULONG_PTR next, val = (ULONG_PTR)RunOnce->Ptr;

        switch (val & 3)
        {
        case 0:  /* first time */
            if (!InterlockedCompareExchangePointer(
				&RunOnce->Ptr,
                (PVOID)((Flags & RTL_RUN_ONCE_ASYNC) ? 3 : 1), 
				NULL )
				)
                return STATUS_PENDING;
            break;

        case 1:  /* in progress, wait */
            if (Flags & RTL_RUN_ONCE_ASYNC) return STATUS_INVALID_PARAMETER;
            next = val & ~3;
            if (InterlockedCompareExchangePointer( &RunOnce->Ptr, (void *)((ULONG_PTR)&next | 1),
                                                   (void *)val ) == (void *)val)
                NtWaitForKeyedEvent( 0, &next, FALSE, NULL );
            break;

        case 2:  /* done */
            if (Context) *Context = (void *)(val & ~3);
            return STATUS_SUCCESS;

        case 3:  /* in progress, async */
            if (!(Flags & RTL_RUN_ONCE_ASYNC)) return STATUS_INVALID_PARAMETER;
            return STATUS_PENDING;
        }
    }
}


/******************************************************************
 *              RtlRunOnceComplete (NTDLL.@)
 */
//adjusted for Windows API
NTSTATUS RtlRunOnceComplete(
  PRTL_RUN_ONCE RunOnce,
  ULONG         Flags,
  PVOID         Context
)
{
    if ((ULONG_PTR)Context & 3) return STATUS_INVALID_PARAMETER;

    if (Flags & RTL_RUN_ONCE_INIT_FAILED)
    {
        if (Context) return STATUS_INVALID_PARAMETER;
        if (Flags & RTL_RUN_ONCE_ASYNC) return STATUS_INVALID_PARAMETER;
    }
    else Context = (void *)((ULONG_PTR)Context | 2);

    for (;;)
    {
        ULONG_PTR val = (ULONG_PTR)RunOnce->Ptr;

        switch (val & 3)
        {
        case 1:  /* in progress */
            if (InterlockedCompareExchangePointer( &RunOnce->Ptr, Context, (void *)val ) != (void *)val) break;
            val &= ~3;
            while (val)
            {
                ULONG_PTR next = *(ULONG_PTR *)val;
                NtReleaseKeyedEvent( 0, (void *)val, FALSE, NULL );
                val = next;
            }
            return STATUS_SUCCESS;

        case 3:  /* in progress, async */
            if (!(Flags & RTL_RUN_ONCE_ASYNC)) return STATUS_INVALID_PARAMETER;
            if (InterlockedCompareExchangePointer( &RunOnce->Ptr, Context, (void *)val ) != (void *)val) break;
            return STATUS_SUCCESS;

        default:
            return STATUS_UNSUCCESSFUL;
        }
    }
}

/******************************************************************
 *              RtlRunOnceExecuteOnce (NTDLL.@)
 */
//adjusted for Windows API 
 
NTSTATUS RtlRunOnceExecuteOnce(
  PRTL_RUN_ONCE         RunOnce,
  PRTL_RUN_ONCE_INIT_FN InitFn,
  PVOID                 Parameter,
  PVOID                 *Context
)
{
    DWORD ret = RtlRunOnceBeginInitialize( RunOnce, 0, Context );

    if (ret != STATUS_PENDING) return ret;

    if (!InitFn( RunOnce, Parameter, Context ))
    {
        RtlRunOnceComplete( RunOnce, RTL_RUN_ONCE_INIT_FAILED, NULL );
        return STATUS_UNSUCCESSFUL;
    }

    return RtlRunOnceComplete( RunOnce, 0, Context ? *Context : NULL );
}
