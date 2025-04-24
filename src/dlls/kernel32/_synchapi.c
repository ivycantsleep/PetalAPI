/*
01-Dec-2020 moyefi moves the following Win32 APIs to NTDLL.DLL

	InitializeSRWLock = NTDLL.RtlInitializeSRWLock
    AcquireSRWLockExclusive = NTDLL.RtlAcquireSRWLockExclusive
	AcquireSRWLockShared = NTDLL.RtlAcquireSRWLockShared
	TryAcquireSRWLockExclusive = NTDLL.RtlTryAcquireSRWLockExclusive
	ReleaseSRWLockExclusive = NTDLL.RtlReleaseSRWLockExclusive
	ReleaseSRWLockShared = NTDLL.RtlReleaseSRWLockShared
	WakeConditionVariable = NTDLL.WakeConditionVariable
	InitializeCriticalSectionEx = NTDLL.RtlInitializeCriticalSectionEx

24-Nov-2020 moyefi implements the following Win32 APIs

	InitializeSRWLock

23-Nov-2020 moyefi implements the following Win32 APIs

	InitializeProcThreadAttributeList
	UpdateProcThreadAttribute
	DeleteProcThreadAttributeList

22-Nov-2020 moyefi implements the following Win32 APIs

	GetTickCount64
	TryAcquireSRWLockExclusive

21-Nov-2020 moyefi implements the following Win32 APIs

	AcquireSRWLockExclusive
	AcquireSRWLockShared

	ReleaseSRWLockExclusive
	ReleaseSRWLockShared

	InitializeCriticalSectionEx
	CreateSemaphoreExW

	CreateEventExW

	CreateMutexExA
	CreateMutexExW

	CreateThreadpoolTimer
	SetThreadpoolTimer
	CloseThreadpoolTimer
	WaitForThreadpoolTimerCallbacks

	WakeByAddressAll
	WakeAllConditionVariable

*/

#include <basedll.h>
#include <_sal.h>
#include <_list.h>
#include <_security.h>
#include <_utils.h>
#include <_synchapi.h>
#include <_system.h>

//from NTDLL.DLL
extern void RtlWakeConditionVariable( RTL_CONDITION_VARIABLE *variable );
extern void RtlWakeAllConditionVariable( RTL_CONDITION_VARIABLE *variable );
extern void RtlInitializeConditionVariable( RTL_CONDITION_VARIABLE *variable );

//https://source.winehq.org/git/wine.git/blob/2db497e89e8e4a37a8bd569b8691b9b87ae63606:/dlls/kernel32/sync.c
//https://www.winehq.org/pipermail/wine-bugs/2010-February/217476.html
//When the app calls CreateMutexA(), the call sequence is as follows: CreateMutexA -> CreateMutexExA -> CreateMutexExW -> NtCreateMutant


static void CALLBACK threadpool_worker_proc( void *param );
/* global default_threadpool object */
static struct threadpool *default_threadpool = NULL;

/* global timerqueue object */
static RTL_CRITICAL_SECTION_DEBUG timerqueue_debug;

static struct
{
    CRITICAL_SECTION        cs;
    LONG                    objcount;
    BOOL                    thread_running;
    struct list             pending_timers;
    RTL_CONDITION_VARIABLE  update_event;
}
timerqueue =
{
    { &timerqueue_debug, -1, 0, 0, 0, 0 },      /* cs */
    0,                                          /* objcount */
    FALSE,                                      /* thread_running */
    LIST_INIT( timerqueue.pending_timers ),     /* pending_timers */
    RTL_CONDITION_VARIABLE_INIT                 /* update_event */
};

static RTL_CRITICAL_SECTION_DEBUG timerqueue_debug =
{
    0, 0, &timerqueue.cs,
    { &timerqueue_debug.ProcessLocksList, &timerqueue_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": timerqueue.cs") }
};

/* returns directory handle to \\BaseNamedObjects */
HANDLE get_BaseNamedObjects_handle(void)
{
      static HANDLE handle = NULL;
      static const WCHAR basenameW[] =
          {'\\','B','a','s','e','N','a','m','e','d','O','b','j','e','c','t','s',0};
      UNICODE_STRING str;
      OBJECT_ATTRIBUTES attr;
  
       if (!handle)
       {
          HANDLE dir;
  
          RtlInitUnicodeString(&str, basenameW);
          InitializeObjectAttributes(&attr, &str, 0, 0, NULL);
          NtOpenDirectoryObject(&dir, DIRECTORY_CREATE_OBJECT|DIRECTORY_TRAVERSE,
                                &attr);
          if (InterlockedCompareExchangePointer( &handle, dir, 0 ) != 0)
          {
              /* someone beat us here... */
              CloseHandle( dir );
           }
      }
      return handle;
}

void get_create_object_attributes( OBJECT_ATTRIBUTES *attr, UNICODE_STRING *nameW,
                                          SECURITY_ATTRIBUTES *sa, const WCHAR *name )
{
    attr->Length                   = sizeof(*attr);
    attr->RootDirectory            = 0;
    attr->ObjectName               = NULL;
    attr->Attributes               = OBJ_OPENIF | ((sa && sa->bInheritHandle) ? OBJ_INHERIT : 0);
    attr->SecurityDescriptor       = sa ? sa->lpSecurityDescriptor : NULL;
    attr->SecurityQualityOfService = NULL;
    if (name)
    {
        RtlInitUnicodeString( nameW, name );
        attr->ObjectName = nameW;
        attr->RootDirectory = BaseGetNamedObjectDirectory();
    }
}

HANDLE
CreateMutexExW(
    LPSECURITY_ATTRIBUTES lpMutexAttributes,
    LPCWSTR lpName,
    DWORD dwFlags,
    DWORD dwDesiredAccess
    )
{
	HANDLE ret;
    UNICODE_STRING nameW;
    OBJECT_ATTRIBUTES attr;
    NTSTATUS status;
    attr.Length                   = sizeof(attr);
    attr.RootDirectory            = 0;
    attr.ObjectName               = NULL;
    attr.Attributes               = OBJ_OPENIF | ((lpMutexAttributes && lpMutexAttributes->bInheritHandle) ? OBJ_INHERIT : 0);
    attr.SecurityDescriptor       = lpMutexAttributes ? lpMutexAttributes->lpSecurityDescriptor : NULL;
    attr.SecurityQualityOfService = NULL;
    if (lpName)
    {
        RtlInitUnicodeString( &nameW, lpName );
        attr.ObjectName = &nameW;
        attr.RootDirectory = get_BaseNamedObjects_handle();
    }
 
    status = NtCreateMutant( &ret, dwDesiredAccess, &attr, (dwFlags & CREATE_MUTEX_INITIAL_OWNER) != 0 );
    if (status == STATUS_OBJECT_NAME_EXISTS)
        SetLastError( ERROR_ALREADY_EXISTS );
    else
        SetLastError( RtlNtStatusToDosError(status) );
    return ret;
}

HANDLE
CreateMutexExA(
      LPSECURITY_ATTRIBUTES lpMutexAttributes,
      LPCSTR lpName,
     DWORD dwFlags,
      DWORD dwDesiredAccess
    )
{
	ANSI_STRING nameA;
    NTSTATUS status;
  
    if (!lpName) return CreateMutexExW( lpMutexAttributes, NULL, dwFlags, dwDesiredAccess );
  
    RtlInitAnsiString( &nameA, lpName );
    status = RtlAnsiStringToUnicodeString( &NtCurrentTeb()->StaticUnicodeString, &nameA, FALSE );
    if (status != STATUS_SUCCESS)
    {
        SetLastError( ERROR_FILENAME_EXCED_RANGE );
        return 0;
    }
    return CreateMutexExW( lpMutexAttributes, NtCurrentTeb()->StaticUnicodeString.Buffer, dwFlags, dwDesiredAccess );
}

/***********************************************************************
 *           tp_threadpool_alloc    (internal)
 *
 * Allocates a new threadpool object.
 */
static NTSTATUS tp_threadpool_alloc( struct threadpool **out )
{
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( NtCurrentTeb()->ProcessEnvironmentBlock->ImageBaseAddress );
    struct threadpool *pool;
    unsigned int i;

    pool = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*pool) );
    if (!pool)
        return STATUS_NO_MEMORY;

    pool->refcount              = 1;
    pool->objcount              = 0;
    pool->shutdown              = FALSE;

    RtlInitializeCriticalSection( &pool->cs );
    pool->cs.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": threadpool.cs");

    for (i = 0; i < ARRAY_SIZE(pool->pools); ++i)
        list_init( &pool->pools[i] );
    RtlInitializeConditionVariable( &pool->update_event );

    pool->max_workers             = 500;
    pool->min_workers             = 0;
    pool->num_workers             = 0;
    pool->num_busy_workers        = 0;
    pool->stack_info.StackReserve = nt->OptionalHeader.SizeOfStackReserve;
    pool->stack_info.StackCommit  = nt->OptionalHeader.SizeOfStackCommit;

    //TRACE( "allocated threadpool %p\n", pool );

    *out = pool;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           tp_threadpool_shutdown    (internal)
 *
 * Prepares the shutdown of a threadpool object and notifies all worker
 * threads to terminate (after all remaining work items have been
 * processed).
 */
static void tp_threadpool_shutdown( struct threadpool *pool )
{
    //assert( pool != default_threadpool );
    pool->shutdown = TRUE;
    RtlWakeAllConditionVariable( &pool->update_event );
}

HANDLE
CreateSemaphoreExW(
      LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
      LONG lInitialCount,
      LONG lMaximumCount,
      LPCWSTR lpName,
      DWORD dwFlags,
      DWORD dwDesiredAccess
    )
{
	HANDLE ret = 0;
    UNICODE_STRING nameW;
    OBJECT_ATTRIBUTES attr;
    NTSTATUS status;

    get_create_object_attributes( &attr, &nameW, lpSemaphoreAttributes, lpName );

    status = NtCreateSemaphore( &ret, dwDesiredAccess, &attr, lInitialCount, lMaximumCount );
    if (status == STATUS_OBJECT_NAME_EXISTS)
        SetLastError( ERROR_ALREADY_EXISTS );
    else
        SetLastError( RtlNtStatusToDosError(status) );
    return ret;
}
                   
void tp_timerqueue_unlock( struct threadpool_object *timer )
{
    //assert( timer->type == TP_OBJECT_TYPE_TIMER );

    RtlEnterCriticalSection( &timerqueue.cs );
    if (timer->u.timer.timer_initialized)
    {
        // If timer was pending, remove it.
        if (timer->u.timer.timer_pending)
        {
            list_remove( &timer->u.timer.timer_entry );
            timer->u.timer.timer_pending = FALSE;
        }

        // If the last timer object was destroyed, then wake up the thread.
        if (!--timerqueue.objcount)
        {
           // assert( list_empty( &timerqueue.pending_timers ) );
            RtlWakeAllConditionVariable( &timerqueue.update_event );
        }

        timer->u.timer.timer_initialized = FALSE;
    }
    RtlLeaveCriticalSection( &timerqueue.cs );
}

// global waitqueue object
static RTL_CRITICAL_SECTION_DEBUG waitqueue_debug;

static struct
{
    CRITICAL_SECTION        cs;
    LONG                    num_buckets;
    struct list             buckets;
}
waitqueue =
{
    { &waitqueue_debug, -1, 0, 0, 0, 0 },       // cs
    0,                                          // num_buckets 
    LIST_INIT( waitqueue.buckets )              // buckets
};

static RTL_CRITICAL_SECTION_DEBUG waitqueue_debug =
{
    0, 0, &waitqueue.cs,
    { &waitqueue_debug.ProcessLocksList, &waitqueue_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": waitqueue.cs") }
};

void tp_waitqueue_unlock( struct threadpool_object *wait )
{
    //assert( wait->type == TP_OBJECT_TYPE_WAIT );

    RtlEnterCriticalSection( &waitqueue.cs );
    if (wait->u.wait.bucket)
    {
        struct waitqueue_bucket *bucket = wait->u.wait.bucket;
        //assert( bucket->objcount > 0 );

        list_remove( &wait->u.wait.wait_entry );
        wait->u.wait.bucket = NULL;
        bucket->objcount--;

        NtSetEvent( bucket->update_event, NULL );
    }
    RtlLeaveCriticalSection( &waitqueue.cs );
}

// global I/O completion queue object
static RTL_CRITICAL_SECTION_DEBUG ioqueue_debug;

static struct
{
    CRITICAL_SECTION        cs;
    LONG                    objcount;
    BOOL                    thread_running;
    HANDLE                  port;
    RTL_CONDITION_VARIABLE  update_event;
}
ioqueue =
{
    { &ioqueue_debug, -1, 0, 0, 0, 0 } // cs
};

static RTL_CRITICAL_SECTION_DEBUG ioqueue_debug =
{
    0, 0, &ioqueue.cs,
    { &ioqueue_debug.ProcessLocksList, &ioqueue_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": ioqueue.cs") }
};

static void tp_ioqueue_unlock( struct threadpool_object *io )
{
    //assert( io->type == TP_OBJECT_TYPE_IO );

    RtlEnterCriticalSection( &ioqueue.cs );

    if (!--ioqueue.objcount)
        NtSetIoCompletion( ioqueue.port, 0, 0, STATUS_SUCCESS, 0 );

    RtlLeaveCriticalSection( &ioqueue.cs );
}

BOOL tp_threadpool_release( struct threadpool *pool )
{
    unsigned int i;

    if (InterlockedDecrement( &pool->refcount ))
        return FALSE;

    //TRACE( "destroying threadpool %p\n", pool );

    //assert( pool->shutdown );
    //assert( !pool->objcount );
    //for (i = 0; i < ARRAY_SIZE(pool->pools); ++i)
        //assert( list_empty( &pool->pools[i] ) );

    pool->cs.DebugInfo->Spare[0] = 0;
    RtlDeleteCriticalSection( &pool->cs );

    RtlFreeHeap( GetProcessHeap(), 0, pool );
    return TRUE;
}

void tp_threadpool_unlock( struct threadpool *pool )
{
    RtlEnterCriticalSection( &pool->cs );
    pool->objcount--;
    RtlLeaveCriticalSection( &pool->cs );
    tp_threadpool_release( pool );
}

BOOL tp_group_release( struct threadpool_group *group )
{
    if (InterlockedDecrement( &group->refcount ))
        return FALSE;

    //TRACE( "destroying group %p\n", group );

    //assert( group->shutdown );
    //assert( list_empty( &group->members ) );

    group->cs.DebugInfo->Spare[0] = 0;
    RtlDeleteCriticalSection( &group->cs );

    RtlFreeHeap( GetProcessHeap(), 0, group );
    return TRUE;
}

void tp_object_prepare_shutdown( struct threadpool_object *object )
{
    if (object->type == TP_OBJECT_TYPE_TIMER)
        tp_timerqueue_unlock( object );
    else if (object->type == TP_OBJECT_TYPE_WAIT)
        tp_waitqueue_unlock( object );
    else if (object->type == TP_OBJECT_TYPE_IO)
        tp_ioqueue_unlock( object );
}

BOOL tp_object_release( struct threadpool_object *object )
{
    if (InterlockedDecrement( &object->refcount ))
        return FALSE;
    //assert( object->shutdown );
    //assert( !object->num_pending_callbacks );
    //assert( !object->num_running_callbacks );
    //assert( !object->num_associated_callbacks );

    // release reference to the group
    if (object->group)
    {
        struct threadpool_group *group = object->group;

        RtlEnterCriticalSection( &group->cs );
        if (object->is_group_member)
        {
            list_remove( &object->group_entry );
            object->is_group_member = FALSE;
        }
        RtlLeaveCriticalSection( &group->cs );

        tp_group_release( group );
    }

    tp_threadpool_unlock( object->pool );

    if (object->race_dll)
        LdrUnloadDll( object->race_dll );

    RtlFreeHeap( GetProcessHeap(), 0, object );
    return TRUE;
}


struct threadpool_object *impl_from_TP_TIMER( TP_TIMER *timer )
{
    struct threadpool_object *object = (struct threadpool_object *)timer;
    //assert( object->type == TP_OBJECT_TYPE_TIMER );
    return object;
}

VOID
TpReleaseTimer(
	TP_TIMER *timer 
)
{
    struct threadpool_object *this = impl_from_TP_TIMER( timer );

    tp_object_prepare_shutdown( this );
    this->shutdown = TRUE;
    tp_object_release( this );
}

/***********************************************************************
 *           tp_new_worker_thread    (internal)
 *
 * Create and account a new worker thread for the desired pool.
 */
static NTSTATUS tp_new_worker_thread( struct threadpool *pool )
{
    HANDLE Handle;
    NTSTATUS status;
	
	/*
	RtlCreateUserThread(
    HANDLE Process,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    BOOLEAN CreateSuspended,
    ULONG StackZeroBits,
    SIZE_T MaximumStackSize ,
    SIZE_T InitialStackSize ,
    PUSER_THREAD_START_ROUTINE StartAddress,
    PVOID Parameter,
    PHANDLE Thread,
    PCLIENT_ID ClientId
    );

	*/

    status = RtlCreateUserThread(
		NtCurrentProcess(), //HANDLE Process
		NULL,               //PSECURITY_DESCRIPTOR ThreadSecurityDescriptor
		FALSE,              //BOOLEAN CreateSuspended
		0,                  //ULONG StackZeroBits
		0,                  //SIZE_T MaximumStackSize
		0,                  //SIZE_T InitialStackSize
        (PUSER_THREAD_START_ROUTINE)threadpool_worker_proc, //PUSER_THREAD_START_ROUTINE StartAddress
		pool,               //PVOID Parameter
		&Handle,            //PHANDLE Thread
		NULL                //PCLIENT_ID ClientId
	);
    if (status == STATUS_SUCCESS)
    {
        InterlockedIncrement( &pool->refcount );
        pool->num_workers++;
        NtClose( Handle );
    }
    return status;
}

static void tp_object_prio_queue( struct threadpool_object *object )
{
    ++object->pool->num_busy_workers;
    list_add_tail( &object->pool->pools[object->priority], &object->pool_entry );
}

/***********************************************************************
 *           tp_object_submit    (internal)
 *
 * Submits a threadpool object to the associated threadpool. This
 * function has to be VOID because TpPostWork can never fail on Windows.
 */
static void tp_object_submit( struct threadpool_object *object, BOOL signaled )
{
    struct threadpool *pool = object->pool;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    //assert( !object->shutdown );
    //assert( !pool->shutdown );

    RtlEnterCriticalSection( &pool->cs );

    /* Start new worker threads if required. */
    if (pool->num_busy_workers >= pool->num_workers &&
        pool->num_workers < pool->max_workers)
        status = tp_new_worker_thread( pool );

    /* Queue work item and increment refcount. */
    InterlockedIncrement( &object->refcount );
    if (!object->num_pending_callbacks++)
        tp_object_prio_queue( object );

    /* Count how often the object was signaled. */
    if (object->type == TP_OBJECT_TYPE_WAIT && signaled)
        object->u.wait.signaled++;

    /* No new thread started - wake up one existing thread. */
    if (status != STATUS_SUCCESS)
    {
        //assert( pool->num_workers > 0 );
        RtlWakeConditionVariable( &pool->update_event );
    }

    RtlLeaveCriticalSection( &pool->cs );
}

static struct threadpool_group *impl_from_TP_CLEANUP_GROUP( TP_CLEANUP_GROUP *group )
{
    return (struct threadpool_group *)group;
}

/***********************************************************************
 *           tp_object_initialize    (internal)
 *
 * Initializes members of a threadpool object.
 */
 
static void tp_object_initialize( struct threadpool_object *object, struct threadpool *pool,
                                  PVOID userdata, TP_CALLBACK_ENVIRON *environment )
{
    BOOL is_simple_callback = (object->type == TP_OBJECT_TYPE_SIMPLE);

    object->refcount                = 1;
    object->shutdown                = FALSE;

    object->pool                    = pool;
    object->group                   = NULL;
    object->userdata                = userdata;
    object->group_cancel_callback   = NULL;
    object->finalization_callback   = NULL;
    object->may_run_long            = 0;
    object->race_dll                = NULL;
    object->priority                = TP_CALLBACK_PRIORITY_NORMAL;

    memset( &object->group_entry, 0, sizeof(object->group_entry) );
    object->is_group_member         = FALSE;

    memset( &object->pool_entry, 0, sizeof(object->pool_entry) );
    RtlInitializeConditionVariable( &object->finished_event );
    RtlInitializeConditionVariable( &object->group_finished_event );
    object->num_pending_callbacks   = 0;
    object->num_running_callbacks   = 0;
    object->num_associated_callbacks = 0;

    if (environment)
    {
        //if (environment->Version != 1 && environment->Version != 3)
          //  FIXME( "unsupported environment version %u\n", environment->Version );

        object->group = impl_from_TP_CLEANUP_GROUP( environment->CleanupGroup );
        object->group_cancel_callback   = environment->CleanupGroupCancelCallback;
        object->finalization_callback   = environment->FinalizationCallback;
        object->may_run_long            = ((TP_CALLBACK_ENVIRON_V3*)environment)->u.s.LongFunction != 0;
        object->race_dll                = environment->RaceDll;
        if (environment->Version == 3)
        {
            TP_CALLBACK_ENVIRON_V3 *environment_v3 = (TP_CALLBACK_ENVIRON_V3 *)environment;

            object->priority = environment_v3->CallbackPriority;
         //   assert( object->priority < ARRAY_SIZE(pool->pools) );
        }

        //if (environment->ActivationContext)
          //  FIXME( "activation context not supported yet\n" );

        //if (environment->u.s.Persistent)
          //  FIXME( "persistent threads not supported yet\n" );
    }

    if (object->race_dll)
        LdrAddRefDll( 0, object->race_dll );

    //TRACE( "allocated object %p of type %u\n", object, object->type );

    // For simple callbacks we have to run tp_object_submit before adding this object
    // to the cleanup group. As soon as the cleanup group members are released ->shutdown
    // will be set, and tp_object_submit would fail with an assertion. 

    if (is_simple_callback)
        tp_object_submit( object, FALSE );

    if (object->group)
    {
        struct threadpool_group *group = object->group;
        InterlockedIncrement( &group->refcount );

        RtlEnterCriticalSection( &group->cs );
        list_add_tail( &group->members, &object->group_entry );
        object->is_group_member = TRUE;
        RtlLeaveCriticalSection( &group->cs );
    }

    if (is_simple_callback)
        tp_object_release( object );
}

typedef union _RTL_RUN_ONCE {
    PVOID Ptr;
} RTL_RUN_ONCE, *PRTL_RUN_ONCE;

typedef RTL_RUN_ONCE  INIT_ONCE;
typedef PRTL_RUN_ONCE PINIT_ONCE;
typedef PRTL_RUN_ONCE LPINIT_ONCE;

#define RTL_RUN_ONCE_INIT {0}

typedef DWORD WINAPI RTL_RUN_ONCE_INIT_FN(PRTL_RUN_ONCE, PVOID, PVOID*);
typedef RTL_RUN_ONCE_INIT_FN *PRTL_RUN_ONCE_INIT_FN;

extern NTSTATUS RtlRunOnceExecuteOnce(PRTL_RUN_ONCE RunOnce,PRTL_RUN_ONCE_INIT_FN InitFn,PVOID Parameter,PVOID *Context);

static HANDLE woa_event;
static RTL_RUN_ONCE init_once_woa = RTL_RUN_ONCE_INIT;
static DWORD init_woa( RTL_RUN_ONCE *once, void *param, void **context )
{
    NtCreateKeyedEvent( &woa_event, GENERIC_READ|GENERIC_WRITE, NULL, 0 );
    return TRUE;
} 

/***********************************************************************
 *           WaitOnAddress   (kernelbase.@)
 */
BOOL WaitOnAddress( volatile VOID *Address, PVOID CompareAddress, SIZE_T AddressSize, DWORD dwMilliseconds )
{
    LARGE_INTEGER to;

	switch (AddressSize)
    {
        case 1:
            if (*(const UCHAR *)Address != *(const UCHAR *)CompareAddress)
                return STATUS_SUCCESS;
            break;
        case 2:
            if (*(const USHORT *)Address != *(const USHORT *)CompareAddress)
                return STATUS_SUCCESS;
            break;
        case 4:
            if (*(const ULONG *)Address != *(const ULONG *)CompareAddress)
                return STATUS_SUCCESS;
            break;
        case 8:
            if (*(const ULONG64 *)Address != *(const ULONG64 *)CompareAddress)
                return STATUS_SUCCESS;
            break;
        default:
            return STATUS_INVALID_PARAMETER;
    }

    RtlRunOnceExecuteOnce(
		&init_once_woa, //PRTL_RUN_ONCE         RunOnce
		init_woa,       //PRTL_RUN_ONCE_INIT_FN InitFn
		NULL, 			//PVOID                 Parameter
		NULL			//PVOID                 *Context
	);
	
	
	if (dwMilliseconds != INFINITE)
    {
        to.QuadPart = -(LONGLONG)dwMilliseconds * 10000;
        return NtWaitForKeyedEvent( 
			woa_event, //IN HANDLE KeyedEventHandle
			(PVOID)Address,   //IN PVOID KeyValue
			0,         //IN BOOLEAN Alertable
			 &to    //IN PLARGE_INTEGER Timeout OPTIONAL
		); 
    }
	return NtWaitForKeyedEvent( 
		woa_event, //IN HANDLE KeyedEventHandle
		(PVOID)Address,   //IN PVOID KeyValue
		0,         //IN BOOLEAN Alertable
		 NULL    //IN PLARGE_INTEGER Timeout OPTIONAL
	);   
}
/***********************************************************************
 *           RtlSleepConditionVariableCS   (NTDLL.@)
 *
 * Atomically releases the critical section and suspends the thread,
 * waiting for a Wake(All)ConditionVariable event. Afterwards it enters
 * the critical section again and returns.
 *
 * PARAMS
 *  ConditionVariable  [I/O] condition variable
 *  CriticalSection      [I/O] critical section to leave temporarily
 *  dwMilliseconds   [I]   timeout
 *
 * RETURNS
 *  see NtWaitForKeyedEvent for all possible return values.
 */
 //modifitied Wine code to match windows api
BOOL 
SleepConditionVariableCS(
	PCONDITION_VARIABLE ConditionVariable, 
	PCRITICAL_SECTION CriticalSection,
    DWORD dwMilliseconds )
{
    void *value = ConditionVariable->Ptr;
    NTSTATUS status;

    RtlLeaveCriticalSection( CriticalSection );
    status = WaitOnAddress( &ConditionVariable->Ptr, &value, sizeof(value), dwMilliseconds );
    RtlEnterCriticalSection( CriticalSection );
    return status == STATUS_SUCCESS;
}

/***********************************************************************
 *           timerqueue_thread_proc    (internal)
 */
static void CALLBACK timerqueue_thread_proc( void *param )
{
    LONGLONG timeout, new_timeout;
    struct threadpool_object *other_timer;
    LARGE_INTEGER now;
    struct list *ptr;
//must get rid of LARGE_INTEGER timeout
    //TRACE( "starting timer queue thread\n" );

    RtlEnterCriticalSection( &timerqueue.cs );
    for (;;)
    {
        NtQuerySystemTime( &now );

        /* Check for expired timers. */
        while ((ptr = list_head( &timerqueue.pending_timers )))
        {
            struct threadpool_object *timer = LIST_ENTRY( ptr, struct threadpool_object, u.timer.timer_entry );
            //assert( timer->type == TP_OBJECT_TYPE_TIMER );
            //assert( timer->u.timer.timer_pending );
            if (timer->u.timer.timeout > now.QuadPart)
                break;

            /* Queue a new callback in one of the worker threads. */
            list_remove( &timer->u.timer.timer_entry );
            timer->u.timer.timer_pending = FALSE;
            tp_object_submit( timer, FALSE );

            /* Insert the timer back into the queue, except it's marked for shutdown. */
            if (timer->u.timer.period && !timer->shutdown)
            {
                timer->u.timer.timeout += (ULONGLONG)timer->u.timer.period * 10000;
                if (timer->u.timer.timeout <= now.QuadPart)
                    timer->u.timer.timeout = now.QuadPart + 1;

                LIST_FOR_EACH_ENTRY( other_timer, &timerqueue.pending_timers,
                                     struct threadpool_object, u.timer.timer_entry )
                {
//                    assert( other_timer->type == TP_OBJECT_TYPE_TIMER );
                    if (timer->u.timer.timeout < other_timer->u.timer.timeout)
                        break;
                }
                list_add_before( &other_timer->u.timer.timer_entry, &timer->u.timer.timer_entry );
                timer->u.timer.timer_pending = TRUE;
            }
        }

        timeout = INFINITE;

        /* Determine next timeout and use the window length to optimize wakeup times. */
        LIST_FOR_EACH_ENTRY( other_timer, &timerqueue.pending_timers,
                             struct threadpool_object, u.timer.timer_entry )
        {
//            assert( other_timer->type == TP_OBJECT_TYPE_TIMER );
            if (other_timer->u.timer.timeout >= timeout)
                break;

            timeout = other_timer->u.timer.timeout;
           // new_timeout   = timeout_lower + (ULONGLONG)other_timer->u.timer.window_length * 10000;
           // if (new_timeout < timeout_upper)
           //     timeout_upper = new_timeout;
        }

        /* Wait for timer update events or until the next timer expires. */
        if (timerqueue.objcount)
        {
         //   timeout.QuadPart = timeout_lower;
            SleepConditionVariableCS( &timerqueue.update_event, &timerqueue.cs, (DWORD)timeout );
            continue;
        }

        /* All timers have been destroyed, if no new timers are created
         * within some amount of time, then we can shutdown this thread. */
        //timeout.QuadPart = (ULONGLONG)THREADPOOL_WORKER_TIMEOUT * -10000;
		timeout = THREADPOOL_WORKER_TIMEOUT;
        if (SleepConditionVariableCS( &timerqueue.update_event, &timerqueue.cs,
            (DWORD)timeout ) == STATUS_TIMEOUT && !timerqueue.objcount)
        {
            break;
        }
    }

    timerqueue.thread_running = FALSE;
    RtlLeaveCriticalSection( &timerqueue.cs );

    //TRACE( "terminating timer queue thread\n" );
    RtlExitUserThread( 0 );
}


/***********************************************************************
 *           tp_timerqueue_lock    (internal)
 *
 * Acquires a lock on the global timerqueue. When the lock is acquired
 * successfully, it is guaranteed that the timer thread is running.
 */
static NTSTATUS tp_timerqueue_lock( struct threadpool_object *timer )
{
    NTSTATUS status = STATUS_SUCCESS;
    //assert( timer->type == TP_OBJECT_TYPE_TIMER );

    timer->u.timer.timer_initialized    = FALSE;
    timer->u.timer.timer_pending        = FALSE;
    timer->u.timer.timer_set            = FALSE;
    timer->u.timer.timeout              = 0;
    timer->u.timer.period               = 0;
    timer->u.timer.window_length        = 0;

    RtlEnterCriticalSection( &timerqueue.cs );

    /* Make sure that the timerqueue thread is running. */
    if (!timerqueue.thread_running)
    {
        HANDLE thread;
        status = RtlCreateUserThread( GetCurrentProcess(), NULL, FALSE, 0, 0, 0,
                                      (PUSER_THREAD_START_ROUTINE)timerqueue_thread_proc, NULL, &thread, NULL );
        if (status == STATUS_SUCCESS)
        {
            timerqueue.thread_running = TRUE;
            NtClose( thread );
        }
    }

    if (status == STATUS_SUCCESS)
    {
        timer->u.timer.timer_initialized = TRUE;
        timerqueue.objcount++;
    }

    RtlLeaveCriticalSection( &timerqueue.cs );
    return status;
}

/***********************************************************************
 *           tp_threadpool_lock    (internal)
 *
 * Acquires a lock on a threadpool, specified with an TP_CALLBACK_ENVIRON
 * block. When the lock is acquired successfully, it is guaranteed that
 * there is at least one worker thread to process tasks.
 */
static NTSTATUS tp_threadpool_lock( struct threadpool **out, TP_CALLBACK_ENVIRON *environment )
{
    struct threadpool *pool = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (environment)
    {
        /* Validate environment parameters. */
        if (environment->Version == 3)
        {
            TP_CALLBACK_ENVIRON_V3 *environment3 = (TP_CALLBACK_ENVIRON_V3 *)environment;

            switch (environment3->CallbackPriority)
            {
                case TP_CALLBACK_PRIORITY_HIGH:
                case TP_CALLBACK_PRIORITY_NORMAL:
                case TP_CALLBACK_PRIORITY_LOW:
                    break;
                default:
                    return STATUS_INVALID_PARAMETER;
            }
        }

        pool = (struct threadpool *)environment->Pool;
    }

    if (!pool)
    {
        if (!default_threadpool)
        {
            status = tp_threadpool_alloc( &pool );
            if (status != STATUS_SUCCESS)
                return status;

            if (InterlockedCompareExchangePointer( (void *)&default_threadpool, pool, NULL ) != NULL)
            {
                tp_threadpool_shutdown( pool );
                tp_threadpool_release( pool );
            }
        }

        pool = default_threadpool;
    }

    RtlEnterCriticalSection( &pool->cs );

    /* Make sure that the threadpool has at least one thread. */
    if (!pool->num_workers)
        status = tp_new_worker_thread( pool );

    /* Keep a reference, and increment objcount to ensure that the
     * last thread doesn't terminate. */
    if (status == STATUS_SUCCESS)
    {
        InterlockedIncrement( &pool->refcount );
        pool->objcount++;
    }

    RtlLeaveCriticalSection( &pool->cs );

    if (status != STATUS_SUCCESS)
        return status;

    *out = pool;
    return STATUS_SUCCESS;
}

static struct list *threadpool_get_next_item( const struct threadpool *pool )
{
    struct list *ptr;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(pool->pools); ++i)
    {
        if ((ptr = list_head( &pool->pools[i] )))
            break;
    }

    return ptr;
}

static BOOL object_is_finished( struct threadpool_object *object, BOOL group )
{
    if (object->num_pending_callbacks)
        return FALSE;
    if (object->type == TP_OBJECT_TYPE_IO && object->u.io.pending_count)
        return FALSE;

    if (group)
        return !object->num_running_callbacks;
    else
        return !object->num_associated_callbacks;
}

/***********************************************************************
 *           threadpool_worker_proc    (internal)
 */
static void CALLBACK threadpool_worker_proc( void *param )
{
    TP_CALLBACK_INSTANCE *callback_instance;
    struct threadpool_instance instance;
    struct io_completion completion;
    struct threadpool *pool = param;
    TP_WAIT_RESULT wait_result = 0;
    DWORD timeout;
    struct list *ptr;
    NTSTATUS status;

    //TRACE( "starting worker thread for pool %p\n", pool );

    RtlEnterCriticalSection( &pool->cs );
    for (;;)
    {
        while ((ptr = threadpool_get_next_item( pool )))
        {
            struct threadpool_object *object = LIST_ENTRY( ptr, struct threadpool_object, pool_entry );
//            assert( object->num_pending_callbacks > 0 );

            /* If further pending callbacks are queued, move the work item to
             * the end of the pool list. Otherwise remove it from the pool. */
            list_remove( &object->pool_entry );
            if (--object->num_pending_callbacks)
                tp_object_prio_queue( object );

            /* For wait objects check if they were signaled or have timed out. */
            if (object->type == TP_OBJECT_TYPE_WAIT)
            {
                wait_result = object->u.wait.signaled ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
                if (wait_result == WAIT_OBJECT_0) object->u.wait.signaled--;
            }
            else if (object->type == TP_OBJECT_TYPE_IO)
            {
              //  assert( object->u.io.completion_count );
                completion = object->u.io.completions[--object->u.io.completion_count];
                object->u.io.pending_count--;
            }

            /* Leave critical section and do the actual callback. */
            object->num_associated_callbacks++;
            object->num_running_callbacks++;
            RtlLeaveCriticalSection( &pool->cs );

            /* Initialize threadpool instance struct. */
            callback_instance = (TP_CALLBACK_INSTANCE *)&instance;
            instance.object                     = object;
            instance.threadid                   = GetCurrentThreadId();
            instance.associated                 = TRUE;
            instance.may_run_long               = object->may_run_long;
            instance.cleanup.critical_section   = NULL;
            instance.cleanup.mutex              = NULL;
            instance.cleanup.semaphore          = NULL;
            instance.cleanup.semaphore_count    = 0;
            instance.cleanup.event              = NULL;
            instance.cleanup.library            = NULL;

            switch (object->type)
            {
                case TP_OBJECT_TYPE_SIMPLE:
                {
                    //TRACE( "executing simple callback %p(%p, %p)\n",
                    //       object->u.simple.callback, callback_instance, object->userdata );
                    object->u.simple.callback( callback_instance, object->userdata );
                    //TRACE( "callback %p returned\n", object->u.simple.callback );
                    break;
                }

                case TP_OBJECT_TYPE_WORK:
                {
                    //TRACE( "executing work callback %p(%p, %p, %p)\n",
                    //       object->u.work.callback, callback_instance, object->userdata, object );
                    object->u.work.callback( callback_instance, object->userdata, (TP_WORK *)object );
                    //TRACE( "callback %p returned\n", object->u.work.callback );
                    break;
                }

                case TP_OBJECT_TYPE_TIMER:
                {
                    //TRACE( "executing timer callback %p(%p, %p, %p)\n",
                    //       object->u.timer.callback, callback_instance, object->userdata, object );
                    object->u.timer.callback( callback_instance, object->userdata, (TP_TIMER *)object );
                    //TRACE( "callback %p returned\n", object->u.timer.callback );
                    break;
                }

                case TP_OBJECT_TYPE_WAIT:
                {
                    //TRACE( "executing wait callback %p(%p, %p, %p, %u)\n",
                    //       object->u.wait.callback, callback_instance, object->userdata, object, wait_result );
                    object->u.wait.callback( callback_instance, object->userdata, (TP_WAIT *)object, wait_result );
                    //TRACE( "callback %p returned\n", object->u.wait.callback );
                    break;
                }

                case TP_OBJECT_TYPE_IO:
                {
                    //TRACE( "executing I/O callback %p(%p, %p, %#lx, %p, %p)\n",
                    //       object->u.io.callback, callback_instance, object->userdata,
                    //        completion.cvalue, &completion.iosb, (TP_IO *)object );
                    object->u.io.callback( callback_instance, object->userdata,
                            (void *)completion.cvalue, &completion.iosb, (TP_IO *)object );
                    //TRACE( "callback %p returned\n", object->u.io.callback );
                    break;
                }

                default:
                    //assert(0);
                    break;
            }

            /* Execute finalization callback. */
            if (object->finalization_callback)
            {
                //TRACE( "executing finalization callback %p(%p, %p)\n",
                //       object->finalization_callback, callback_instance, object->userdata );
                object->finalization_callback( callback_instance, object->userdata );
                //TRACE( "callback %p returned\n", object->finalization_callback );
            }

            /* Execute cleanup tasks. */
            if (instance.cleanup.critical_section)
            {
                RtlLeaveCriticalSection( instance.cleanup.critical_section );
            }
            if (instance.cleanup.mutex)
            {
                status = NtReleaseMutant( instance.cleanup.mutex, NULL );
                if (status != STATUS_SUCCESS) goto skip_cleanup;
            }
            if (instance.cleanup.semaphore)
            {
                status = NtReleaseSemaphore( instance.cleanup.semaphore, instance.cleanup.semaphore_count, NULL );
                if (status != STATUS_SUCCESS) goto skip_cleanup;
            }
            if (instance.cleanup.event)
            {
                status = NtSetEvent( instance.cleanup.event, NULL );
                if (status != STATUS_SUCCESS) goto skip_cleanup;
            }
            if (instance.cleanup.library)
            {
                LdrUnloadDll( instance.cleanup.library );
            }

        skip_cleanup:
            RtlEnterCriticalSection( &pool->cs );
            //assert(pool->num_busy_workers);
            pool->num_busy_workers--;

            /* Simple callbacks are automatically shutdown after execution. */
            if (object->type == TP_OBJECT_TYPE_SIMPLE)
            {
                tp_object_prepare_shutdown( object );
                object->shutdown = TRUE;
            }

            object->num_running_callbacks--;
            if (object_is_finished( object, TRUE ))
                RtlWakeAllConditionVariable( &object->group_finished_event );

            if (instance.associated)
            {
                object->num_associated_callbacks--;
                if (object_is_finished( object, FALSE ))
                    RtlWakeAllConditionVariable( &object->finished_event );
            }

            tp_object_release( object );
        }

        /* Shutdown worker thread if requested. */
        if (pool->shutdown)
            break;

        /* Wait for new tasks or until the timeout expires. A thread only terminates
         * when no new tasks are available, and the number of threads can be
         * decreased without violating the min_workers limit. An exception is when
         * min_workers == 0, then objcount is used to detect if the last thread
         * can be terminated. */
        timeout = (DWORD)THREADPOOL_WORKER_TIMEOUT;
        if (SleepConditionVariableCS( &pool->update_event, &pool->cs, timeout ) == STATUS_TIMEOUT &&
            !threadpool_get_next_item( pool ) && (pool->num_workers > max( pool->min_workers, 1 ) ||
            (!pool->min_workers && !pool->objcount)))
        {
            break;
        }
    }
    pool->num_workers--;
    RtlLeaveCriticalSection( &pool->cs );

    //TRACE( "terminating worker thread for pool %p\n", pool );
    tp_threadpool_release( pool );
    RtlExitUserThread( 0 );
}

/***********************************************************************
 *           TpAllocTimer    (NTDLL.@)
 */
NTSTATUS
TpAllocTimer
( TP_TIMER **out, PTP_TIMER_CALLBACK callback, PVOID userdata,
                              TP_CALLBACK_ENVIRON *environment )
{
    struct threadpool_object *object;
    struct threadpool *pool;
    NTSTATUS status;

    //TRACE( "%p %p %p %p\n", out, callback, userdata, environment );

    object = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*object) );
    if (!object)
        return STATUS_NO_MEMORY;

    status = tp_threadpool_lock( &pool, environment );
    if (status)
    {
        RtlFreeHeap( GetProcessHeap(), 0, object );
        return status;
    }

    object->type = TP_OBJECT_TYPE_TIMER;
    object->u.timer.callback = callback;

    status = tp_timerqueue_lock( object );
    if (status)
    {
        tp_threadpool_unlock( pool );
        RtlFreeHeap( GetProcessHeap(), 0, object );
        return status;
    }

    tp_object_initialize( object, pool, userdata, environment );

    *out = (TP_TIMER *)object;
    return STATUS_SUCCESS;
}

//https://www.oreilly.com/library/view/windows-via-cc/9780735639904/ch20s04.html
//CloseThreadpoolTimer (forwarded to NTDLL.TpReleaseTimer)
/***********************************************************************
 *           CreateThreadpoolTimer   (kernelbase.@)
*/ 
PTP_TIMER 
CreateThreadpoolTimer(
  PTP_TIMER_CALLBACK   pfnti,
  PVOID                pv,
  PTP_CALLBACK_ENVIRON pcbe
)
{
    PTP_TIMER timer;

    if (!set_ntstatus( TpAllocTimer( &timer, pfnti, pv, pcbe ))) return NULL;
    return timer;
}


//from Wine thread.c

void TpSetTimer( PTP_TIMER Timer, PLARGE_INTEGER timeout, LONG Period, LONG WindowLength )
{	
    struct threadpool_object *this = impl_from_TP_TIMER( Timer );
    struct threadpool_object *other_timer;
    BOOL submit_timer = FALSE;
    ULONGLONG timestamp;

    //TRACE( "%p %p %u %u\n", timer, timeout, Period, WindowLength );

    RtlEnterCriticalSection( &timerqueue.cs );

    //assert( this->u.timer.timer_initialized );
    this->u.timer.timer_set = timeout != NULL;

    /* Convert relative timeout to absolute timestamp and handle a timeout
     * of zero, which means that the timer is submitted immediately. */
    if (timeout)
    {
        timestamp = timeout->QuadPart;
        if ((LONGLONG)timestamp < 0)
        {
            LARGE_INTEGER now;
            NtQuerySystemTime( &now );
            timestamp = now.QuadPart - timestamp;
        }
        else if (!timestamp)
        {
            if (!Period)
                timeout = NULL;
            else
            {
                LARGE_INTEGER now;
                NtQuerySystemTime( &now );
                timestamp = now.QuadPart + (ULONGLONG)Period * 10000;
            }
            submit_timer = TRUE;
        }
    }

    /* First remove existing timeout. */
    if (this->u.timer.timer_pending)
    {
        list_remove( &this->u.timer.timer_entry );
        this->u.timer.timer_pending = FALSE;
    }

    /* If the timer was enabled, then add it back to the queue. */
    if (timeout)
    {
        this->u.timer.timeout       = timestamp;
        this->u.timer.period        = Period;
        this->u.timer.window_length = WindowLength;

        LIST_FOR_EACH_ENTRY( other_timer, &timerqueue.pending_timers,
                             struct threadpool_object, u.timer.timer_entry )
        {
            //assert( other_timer->type == TP_OBJECT_TYPE_TIMER );
            if (this->u.timer.timeout < other_timer->u.timer.timeout)
                break;
        }
        list_add_before( &other_timer->u.timer.timer_entry, &this->u.timer.timer_entry );

        /* Wake up the timer thread when the timeout has to be updated. */
        if (list_head( &timerqueue.pending_timers ) == &this->u.timer.timer_entry )
            RtlWakeAllConditionVariable( &timerqueue.update_event );

        this->u.timer.timer_pending = TRUE;
    }

    RtlLeaveCriticalSection( &timerqueue.cs );

    if (submit_timer)
       tp_object_submit( this, FALSE );
}

/***********************************************************************
 *              SetThreadpoolTimer (KERNEL32.@)
 */
//https://www.winehq.org/pipermail/wine-cvs/2015-July/107539.html

void SetThreadpoolTimer(
  PTP_TIMER pti,
  PFILETIME pftDueTime,
  DWORD     msPeriod,
  DWORD     msWindowLength
)
{
    LARGE_INTEGER timeout;

   // TRACE( "%p, %p, %u, %u\n", pti, pftDueTime, msPeriod, msWindowLength );

    if (pftDueTime)
    {
        timeout.u.LowPart = pftDueTime->dwLowDateTime;
        timeout.u.HighPart = pftDueTime->dwHighDateTime;
    }
   
    TpSetTimer( pti, &timeout, msPeriod, msWindowLength );
}

/***********************************************************************
 *           TpReleaseTimer     (NTDLL.@)
 */
VOID CloseThreadpoolTimer(
  PTP_TIMER pti
)
{
    struct threadpool_object *this = impl_from_TP_TIMER( pti );

    //TRACE( "%p\n", pti );

    tp_object_prepare_shutdown( this );
    this->shutdown = TRUE;
    tp_object_release( this );
}



/***********************************************************************
 *           tp_object_cancel    (internal)
 *
 * Cancels all currently pending callbacks for a specific object.
 */
static void tp_object_cancel( struct threadpool_object *object )
{
    struct threadpool *pool = object->pool;
    LONG pending_callbacks = 0;

    RtlEnterCriticalSection( &pool->cs );
    if (object->num_pending_callbacks)
    {
        pending_callbacks = object->num_pending_callbacks;
        object->num_pending_callbacks = 0;
        list_remove( &object->pool_entry );

        if (object->type == TP_OBJECT_TYPE_WAIT)
            object->u.wait.signaled = 0;
    }
    if (object->type == TP_OBJECT_TYPE_IO)
        object->u.io.pending_count = 0;
    RtlLeaveCriticalSection( &pool->cs );

    while (pending_callbacks--)
        tp_object_release( object );
}


/***********************************************************************
 *           tp_object_wait    (internal)
 *
 * Waits until all pending and running callbacks of a specific object
 * have been processed.
 */
static void tp_object_wait( struct threadpool_object *object, BOOL group_wait )
{
    struct threadpool *pool = object->pool;

    RtlEnterCriticalSection( &pool->cs );
    while (!object_is_finished( object, group_wait ))
    {
        if (group_wait)
            SleepConditionVariableCS( &object->group_finished_event, &pool->cs, (DWORD)NULL );
        else
            SleepConditionVariableCS( &object->finished_event, &pool->cs, (DWORD)NULL );
    }
    RtlLeaveCriticalSection( &pool->cs );
}

/***********************************************************************
 *           TpWaitForTimer    (NTDLL.@)
 */
VOID WaitForThreadpoolTimerCallbacks(
  PTP_TIMER pti,
  BOOL      fCancelPendingCallbacks
)
{
    struct threadpool_object *this = impl_from_TP_TIMER( pti );

    //TRACE( "%p %d\n", pti, fCancelPendingCallbacks );

    if (fCancelPendingCallbacks)
        tp_object_cancel( this );
    tp_object_wait( this, FALSE );
}



/***********************************************************************
 *           CreateEventExW    (kernelbase.@)
 */
HANDLE CreateEventExW(
  LPSECURITY_ATTRIBUTES lpEventAttributes,
  LPCWSTR               lpName,
  DWORD                 dwFlags,
  DWORD                 dwDesiredAccess
)
{
    HANDLE ret = 0;
    UNICODE_STRING nameW;
    OBJECT_ATTRIBUTES attr;
    NTSTATUS status;

    /* one buggy program needs this
     * ("Van Dale Groot woordenboek der Nederlandse taal")
     */
  // removed error handling  needs to be added////  __try
    {
        get_create_object_attributes( &attr, &nameW, lpEventAttributes, lpName );
    }
 /*   __except
    {
        SetLastError( ERROR_INVALID_PARAMETER);
        return 0;
    }*/
    

    status = NtCreateEvent( &ret, dwDesiredAccess, &attr,
                            (dwFlags & CREATE_EVENT_MANUAL_RESET) ? NotificationEvent : SynchronizationEvent,
                            (dwFlags & CREATE_EVENT_INITIAL_SET) != 0 );
    if (status == STATUS_OBJECT_NAME_EXISTS)
        SetLastError( ERROR_ALREADY_EXISTS );
    else
        SetLastError( RtlNtStatusToDosError(status) );
    return ret;
}


/******************************************************************************
 *           GetTickCount64       (KERNEL32.@)
 */
 //https://www.winehq.org/pipermail/wine-cvs/2013-January/093443.html
ULONGLONG GetTickCount64()
{
    LARGE_INTEGER counter, frequency;
 
    NtQueryPerformanceCounter( &counter, &frequency );
    return counter.QuadPart * 1000 / frequency.QuadPart;
}


/***********************************************************************
 * Process/thread attribute lists
 ***********************************************************************/
//from Wine process.c
/***********************************************************************
 *           InitializeProcThreadAttributeList   (kernelbase.@)
 */
BOOL InitializeProcThreadAttributeList(
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
  DWORD                        dwAttributeCount,
  DWORD                        dwFlags,
  PSIZE_T                      lpSize
)
{
    SIZE_T needed;
    BOOL ret = FALSE;

    //TRACE( "(%p %d %x %p)\n", lpAttributeList, dwAttributeCount, dwFlags, lpSize );

    needed = FIELD_OFFSET( struct _PROC_THREAD_ATTRIBUTE_LIST, Entries[dwAttributeCount] );
    if (lpAttributeList && *lpSize >= needed)
    {
        lpAttributeList->dwFlags = 0;
        lpAttributeList->Size = dwAttributeCount;
        lpAttributeList->Count = 0;
        lpAttributeList->Unknown = 0;
        ret = TRUE;
    }
    else SetLastError( ERROR_INSUFFICIENT_BUFFER );

    *lpSize = needed;
    return ret;
}


/***********************************************************************
 *           UpdateProcThreadAttribute   (kernelbase.@)
 */
BOOL UpdateProcThreadAttribute(
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
  DWORD                        dwFlags,
  DWORD_PTR                    Attribute,
  PVOID                        lpValue,
  SIZE_T                       cbSize,
  PVOID                        lpPreviousValue,
  PSIZE_T                      lpReturnSize
)
{
    DWORD mask;
    struct _PROC_THREAD_ATTRIBUTE_ENTRY *entry;

    //TRACE( "(%p %x %08lx %p %ld %p %p)\n", lpAttributeList, dwFlags, Attribute, lpValue, cbSize, lpPreviousValue, lpReturnSize );

    if (lpAttributeList->Count >= lpAttributeList->Size)
    {
        SetLastError( ERROR_GEN_FAILURE );
        return FALSE;
    }

    switch (Attribute)
    {
    case PROC_THREAD_ATTRIBUTE_PARENT_PROCESS:
        if (cbSize != sizeof(HANDLE))
        {
            SetLastError( ERROR_BAD_LENGTH );
            return FALSE;
        }
        break;

    case PROC_THREAD_ATTRIBUTE_HANDLE_LIST:
        if ((cbSize / sizeof(HANDLE)) * sizeof(HANDLE) != cbSize)
        {
            SetLastError( ERROR_BAD_LENGTH );
            return FALSE;
        }
        break;

    case PROC_THREAD_ATTRIBUTE_IDEAL_PROCESSOR:
        if (cbSize != sizeof(PROCESSOR_NUMBER))
        {
            SetLastError( ERROR_BAD_LENGTH );
            return FALSE;
        }
        break;

    case PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY:
       if (cbSize != sizeof(DWORD) && cbSize != sizeof(DWORD64))
       {
           SetLastError( ERROR_BAD_LENGTH );
           return FALSE;
       }
       break;

    case PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY:
        if (cbSize != sizeof(DWORD) && cbSize != sizeof(DWORD64) && cbSize != sizeof(DWORD64) * 2)
        {
            SetLastError( ERROR_BAD_LENGTH );
            return FALSE;
        }
        break;

    case PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE:
       if (cbSize != sizeof(HPCON))
       {
           SetLastError( ERROR_BAD_LENGTH );
           return FALSE;
       }
       break;

    default:
        SetLastError( ERROR_NOT_SUPPORTED );
        //FIXME( "Unhandled attribute %lu\n", Attribute & PROC_THREAD_ATTRIBUTE_NUMBER );
        return FALSE;
    }

    mask = 1 << (Attribute & PROC_THREAD_ATTRIBUTE_NUMBER);
    if (lpAttributeList->dwFlags & mask)
    {
        SetLastError( ERROR_OBJECT_NAME_EXISTS );
        return FALSE;
    }
    lpAttributeList->dwFlags |= mask;

    entry = lpAttributeList->Entries + lpAttributeList->Count;
    entry->Attribute = Attribute;
    entry->cbSize = cbSize;
    entry->lpValue = lpValue;
    lpAttributeList->Count++;
    return TRUE;
}


/***********************************************************************
 *           DeleteProcThreadAttributeList   (kernelbase.@)
 */
void DeleteProcThreadAttributeList(
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
)
{
    return;
}

BOOLEAN CreateSymbolicLinkW(
  LPCWSTR lpSymlinkFileName,
  LPCWSTR lpTargetFileName,
  DWORD   dwFlags
)
{
	//https://github.com/NeoSmart/ln-win
	BOOL result = CreateHardLinkW (
	  lpSymlinkFileName,
	  lpSymlinkFileName,
	  NULL
	);
	if (result) {
		return S_OK;
	} else {
		return ERROR_FILE_NOT_FOUND;
	}
}