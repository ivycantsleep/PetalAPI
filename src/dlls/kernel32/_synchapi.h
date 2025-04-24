#ifndef SYNCHAPI_EXTRA_H // [

#define SYNCHAPI_EXTRA_H

#include <_list.h>

//from WinBase.h

#define ERROR_OBJECT_NAME_EXISTS 0x2BA

#define CREATE_MUTEX_INITIAL_OWNER  0x00000001
#define CREATE_EVENT_MANUAL_RESET 1
#define CREATE_EVENT_INITIAL_SET  2

/* Threadpool things */
typedef DWORD TP_VERSION,*PTP_VERSION;
typedef struct _TP_POOL TP_POOL, *PTP_POOL;
typedef struct _TP_CLEANUP_GROUP TP_CLEANUP_GROUP, *PTP_CLEANUP_GROUP;
typedef struct _ACTIVATION_CONTEXT ACTIVATION_CONTEXT, *PACTIVATION_CONTEXT;
typedef struct _TP_IO TP_IO, *PTP_IO;
typedef DWORD TP_WAIT_RESULT;
typedef struct _TP_WAIT TP_WAIT, *PTP_WAIT;
typedef struct _TP_WORK TP_WORK, *PTP_WORK;
#define THREADPOOL_WORKER_TIMEOUT 5000

typedef struct _TP_CALLBACK_ENVIRON
{
     ULONG Version;
     PTP_POOL Pool;
     PTP_CLEANUP_GROUP CleanupGroup;
     PVOID CleanupGroupCancelCallback;
     PVOID RaceDll;
     PACTIVATION_CONTEXT ActivationContext;
     PVOID FinalizationCallback;
     ULONG u;
} TP_CALLBACK_ENVIRON, *PTP_CALLBACK_ENVIRON;

//from winnt.h
typedef struct _TP_TIMER TP_TIMER, *PTP_TIMER;

typedef struct _RTL_BARRIER {                       
            DWORD Reserved1;                        
            DWORD Reserved2;                        
            ULONG_PTR Reserved3[2];
            DWORD Reserved4;                       
            DWORD Reserved5;                        
} RTL_BARRIER, *PRTL_BARRIER;   
typedef VOID (CALLBACK *PTP_CLEANUP_GROUP_CANCEL_CALLBACK)(PVOID,PVOID);   
typedef VOID (CALLBACK *PTP_SIMPLE_CALLBACK)(PTP_CALLBACK_INSTANCE,PVOID);
typedef VOID (CALLBACK *PTP_WORK_CALLBACK)(PTP_CALLBACK_INSTANCE,PVOID,PTP_WORK);
typedef VOID (CALLBACK *PTP_TIMER_CALLBACK)(PTP_CALLBACK_INSTANCE,PVOID,PTP_TIMER);
typedef VOID (CALLBACK *PTP_WAIT_CALLBACK)(PTP_CALLBACK_INSTANCE,PVOID,PTP_WAIT,TP_WAIT_RESULT);
typedef enum _TP_CALLBACK_PRIORITY
{
	TP_CALLBACK_PRIORITY_HIGH,
	TP_CALLBACK_PRIORITY_NORMAL,
	TP_CALLBACK_PRIORITY_LOW,
	TP_CALLBACK_PRIORITY_INVALID,
	TP_CALLBACK_PRIORITY_COUNT = TP_CALLBACK_PRIORITY_INVALID
} TP_CALLBACK_PRIORITY;
typedef struct _TP_POOL_STACK_INFORMATION
{
	SIZE_T StackReserve;
	SIZE_T StackCommit;
} TP_POOL_STACK_INFORMATION,*PTP_POOL_STACK_INFORMATION;
typedef struct _TP_CALLBACK_INSTANCE TP_CALLBACK_INSTANCE,*PTP_CALLBACK_INSTANCE;


//from winternl.h - modified
typedef VOID (CALLBACK *PTP_IO_CALLBACK)(PTP_CALLBACK_INSTANCE,PVOID,PVOID,PIO_STATUS_BLOCK,PTP_IO);

//from Wine server_protocol.h
typedef __int64 timeout_t;
typedef unsigned int obj_handle_t;
typedef unsigned __int64 client_ptr_t;

enum select_op
{
    SELECT_NONE,
    SELECT_WAIT,
    SELECT_WAIT_ALL,
    SELECT_SIGNAL_AND_WAIT,
    SELECT_KEYED_EVENT_WAIT,
    SELECT_KEYED_EVENT_RELEASE
};

typedef union
{
    enum select_op op;
    struct
    {
        enum select_op  op;
        obj_handle_t    handles[MAXIMUM_WAIT_OBJECTS];
    } wait;
    struct
    {
        enum select_op  op;
        obj_handle_t    wait;
        obj_handle_t    signal;
    } signal_and_wait;
    struct
    {
        enum select_op  op;
        obj_handle_t    handle;
        client_ptr_t    key;
    } keyed_event;
} select_op_t;

typedef struct _RTL_CONDITION_VARIABLE {                    
        PVOID Ptr;                                       
} RTL_CONDITION_VARIABLE, *PRTL_CONDITION_VARIABLE;
typedef RTL_CONDITION_VARIABLE CONDITION_VARIABLE, *PCONDITION_VARIABLE;

#define RTL_CONDITION_VARIABLE_INIT {0}                 
#define RTL_CONDITION_VARIABLE_LOCKMODE_SHARED  0x1  

//from Wine threadpool.c
/* internal threadpool group representation */
struct threadpool_group
{
    LONG                    refcount;
    BOOL                    shutdown;
    CRITICAL_SECTION        cs;
    /* list of group members, locked via .cs */
    struct list             members;
};

/* internal threadpool representation */
struct threadpool
{
    LONG                    refcount;
    LONG                    objcount;
    BOOL                    shutdown;
    CRITICAL_SECTION        cs;
    /* Pools of work items, locked via .cs, order matches TP_CALLBACK_PRIORITY - high, normal, low. */
    struct list             pools[3];
    RTL_CONDITION_VARIABLE  update_event;
    /* information about worker threads, locked via .cs */
    int                     max_workers;
    int                     min_workers;
    int                     num_workers;
    int                     num_busy_workers;
    HANDLE                  compl_port;
    TP_POOL_STACK_INFORMATION stack_info;
};

enum threadpool_objtype
{
    TP_OBJECT_TYPE_SIMPLE,
    TP_OBJECT_TYPE_WORK,
    TP_OBJECT_TYPE_TIMER,
    TP_OBJECT_TYPE_WAIT,
    TP_OBJECT_TYPE_IO,
};

struct io_completion
{
    IO_STATUS_BLOCK iosb;
    ULONG_PTR cvalue;
};

/* internal threadpool object representation */

struct threadpool_object
{
    void                   *win32_callback; /* leave space for kernelbase to store win32 callback */
    LONG                    refcount;
    BOOL                    shutdown;
    /* read-only information */
    enum threadpool_objtype type;
    struct threadpool       *pool;
    struct threadpool_group *group;
    PVOID                   userdata;
    PTP_CLEANUP_GROUP_CANCEL_CALLBACK group_cancel_callback;
    PTP_SIMPLE_CALLBACK     finalization_callback;
    BOOL                    may_run_long;
    HMODULE                 race_dll;
    TP_CALLBACK_PRIORITY    priority;
    /* information about the group, locked via .group->cs */
    struct list             group_entry;
    BOOL                    is_group_member;
    /* information about the pool, locked via .pool->cs */
    struct list             pool_entry;
    RTL_CONDITION_VARIABLE  finished_event;
    RTL_CONDITION_VARIABLE  group_finished_event;
    LONG                    num_pending_callbacks;
    LONG                    num_running_callbacks;
    LONG                    num_associated_callbacks;
    /* arguments for callback */
    union
    {
        struct
        {
            PTP_SIMPLE_CALLBACK callback;
        } simple;
        struct
        {
            PTP_WORK_CALLBACK callback;
        } work;
        struct
        {
            PTP_TIMER_CALLBACK callback;
            /* information about the timer, locked via timerqueue.cs */
            BOOL            timer_initialized;
            BOOL            timer_pending;
            struct list     timer_entry;
            BOOL            timer_set;
            LONGLONG       timeout;
            LONG            period;
            LONG            window_length;
        } timer;
        struct
        {
            PTP_WAIT_CALLBACK callback;
            LONG            signaled;
            /* information about the wait object, locked via waitqueue.cs */
            struct waitqueue_bucket *bucket;
            BOOL            wait_pending;
            struct list     wait_entry;
            LONGLONG       timeout;
            HANDLE          handle;
        } wait;
        struct
        {
            PTP_IO_CALLBACK callback;
            /* locked via .pool->cs */
            unsigned int    pending_count, completion_count, completion_max;
            struct io_completion *completions;
        } io;
    } u;
};


/* internal threadpool instance representation */
struct threadpool_instance
{
    struct threadpool_object *object;
    DWORD                   threadid;
    BOOL                    associated;
    BOOL                    may_run_long;
    struct
    {
        CRITICAL_SECTION    *critical_section;
        HANDLE              mutex;
        HANDLE              semaphore;
        LONG                semaphore_count;
        HANDLE              event;
        HMODULE             library;
    } cleanup;
};


typedef struct _TP_CALLBACK_ENVIRON_V3
{
    TP_VERSION Version;
    PTP_POOL Pool;
    PTP_CLEANUP_GROUP CleanupGroup;
    PTP_CLEANUP_GROUP_CANCEL_CALLBACK CleanupGroupCancelCallback;
    PVOID RaceDll;
    struct _ACTIVATION_CONTEXT *ActivationContext;
    PTP_SIMPLE_CALLBACK FinalizationCallback;
    union
    {
        DWORD Flags;
        struct
        {
            DWORD LongFunction:1;
            DWORD Persistent:1;
            DWORD Private:30;
        } s;
    } u;
    TP_CALLBACK_PRIORITY CallbackPriority;
    DWORD Size;
} TP_CALLBACK_ENVIRON_V3;


struct waitqueue_bucket
{
    struct list             bucket_entry;
    LONG                    objcount;
    struct list             reserved;
    struct list             waiting;
    HANDLE                  update_event;
};


#define PROC_THREAD_ATTRIBUTE_NUMBER   0x0000ffff
#define PROC_THREAD_ATTRIBUTE_THREAD   0x00010000
#define PROC_THREAD_ATTRIBUTE_INPUT    0x00020000
#define PROC_THREAD_ATTRIBUTE_ADDITIVE 0x00040000

typedef enum _PROC_THREAD_ATTRIBUTE_NUM
{
    ProcThreadAttributeParentProcess = 0,
    ProcThreadAttributeHandleList = 2,
    ProcThreadAttributeGroupAffinity = 3,
    ProcThreadAttributePreferredNode = 4,
    ProcThreadAttributeIdealProcessor = 5,
    ProcThreadAttributeUmsThread = 6,
    ProcThreadAttributeMitigationPolicy = 7,
    ProcThreadAttributeSecurityCapabilities = 9,
    ProcThreadAttributeProtectionLevel = 11,
    ProcThreadAttributeJobList = 13,
    ProcThreadAttributeChildProcessPolicy = 14,
    ProcThreadAttributeAllApplicationPackagesPolicy = 15,
    ProcThreadAttributeWin32kFilter = 16,
    ProcThreadAttributeSafeOpenPromptOriginClaim = 17,
    ProcThreadAttributeDesktopAppPolicy = 18,
    ProcThreadAttributePseudoConsole = 22,
} PROC_THREAD_ATTRIBUTE_NUM;

#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS (ProcThreadAttributeParentProcess | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_HANDLE_LIST (ProcThreadAttributeHandleList | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY (ProcThreadAttributeGroupAffinity | PROC_THREAD_ATTRIBUTE_THREAD | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_PREFERRED_NODE (ProcThreadAttributePreferredNode | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_IDEAL_PROCESSOR (ProcThreadAttributeIdealProcessor | PROC_THREAD_ATTRIBUTE_THREAD | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_UMS_THREAD (ProcThreadAttributeUmsThread | PROC_THREAD_ATTRIBUTE_THREAD | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY (ProcThreadAttributeMitigationPolicy | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES (ProcThreadAttributeSecurityCapabilities | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL (ProcThreadAttributeProtectionLevel | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_JOB_LIST (ProcThreadAttributeJobList | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY (ProcThreadAttributeChildProcessPolicy | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY (ProcThreadAttributeAllApplicationPackagesPolicy | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_WIN32K_FILTER (ProcThreadAttributeWin32kFilter | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_DESKTOP_APP_POLICY (ProcThreadAttributeDesktopAppPolicy | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE (ProcThreadAttributePseudoConsole | PROC_THREAD_ATTRIBUTE_INPUT)

// This structure stores the value for each attribute
typedef struct _PROC_THREAD_ATTRIBUTE_ENTRY
{
    DWORD_PTR   Attribute;  // PROC_THREAD_ATTRIBUTE_xxx
    SIZE_T      cbSize;
    PVOID       lpValue;
} PROC_THREAD_ATTRIBUTE_ENTRY, *LPPROC_THREAD_ATTRIBUTE_ENTRY;
 
// This structure contains a list of attributes that have been added using UpdateProcThreadAttribute
typedef struct _PROC_THREAD_ATTRIBUTE_LIST
{
    DWORD                          dwFlags;  /* bitmask of items in list */
    ULONG                          Size; /* max number of items in list */
    ULONG                          Count;  /* number of items in list */
    ULONG                          Reserved;  
    PULONG                         Unknown;
    PROC_THREAD_ATTRIBUTE_ENTRY    Entries[ANYSIZE_ARRAY];
} PROC_THREAD_ATTRIBUTE_LIST, *LPPROC_THREAD_ATTRIBUTE_LIST;

typedef void *HPCON;

#endif