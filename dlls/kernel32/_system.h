#ifndef SYSTEM_EXTRA_H

#define SYSTEM_EXTRA_H

#define ALL_PROCESSOR_GROUPS 0xffff 

typedef struct _PROCESSOR_NUMBER
{
    WORD Group;
    BYTE Number;
    BYTE Reserved;
} PROCESSOR_NUMBER, *PPROCESSOR_NUMBER;

typedef enum _MORE_LOGICAL_PROCESSOR_RELATIONSHIP
{
    /*RelationProcessorCore    = 0, //already defined in LOGICAL_PROCESSOR_RELATIONSHIP -- where is it? so I added MORE prefix for now
    RelationNumaNode         = 1,*/
    RelationCache            = 2,
    RelationProcessorPackage = 3,
    RelationGroup            = 4,
    RelationAll              = 0xffff
} MORE_LOGICAL_PROCESSOR_RELATIONSHIP;

typedef enum _MORE_SYSTEM_INFORMATION_CLASS {  //SYSTEM_INFORMATION_CLASS already defined i- where is it? so I added MORE prefix for now
    SystemLogicalProcessorInformationEx = 107
} MORE_SYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSOR_CACHE_TYPE {
  CacheUnified,
  CacheInstruction,
  CacheData,
  CacheTrace
} PROCESSOR_CACHE_TYPE;

typedef struct _GROUP_AFFINITY {
  KAFFINITY Mask;
  WORD      Group;
  WORD      Reserved[3];
} GROUP_AFFINITY, *PGROUP_AFFINITY;
typedef struct _PROCESSOR_GROUP_INFO {
  BYTE      MaximumProcessorCount;
  BYTE      ActiveProcessorCount;
  BYTE      Reserved[38];
  KAFFINITY ActiveProcessorMask;
} PROCESSOR_GROUP_INFO, *PPROCESSOR_GROUP_INFO;

typedef struct _CACHE_RELATIONSHIP {
  BYTE                 Level;
  BYTE                 Associativity;
  WORD                 LineSize;
  DWORD                CacheSize;
  PROCESSOR_CACHE_TYPE Type;
  BYTE                 Reserved[20];
  GROUP_AFFINITY       GroupMask;
} CACHE_RELATIONSHIP, *PCACHE_RELATIONSHIP;

typedef struct _NUMA_NODE_RELATIONSHIP {
  DWORD          NodeNumber;
  BYTE           Reserved[20];
  GROUP_AFFINITY GroupMask;
} NUMA_NODE_RELATIONSHIP, *PNUMA_NODE_RELATIONSHIP;

typedef struct _PROCESSOR_RELATIONSHIP {
  BYTE           Flags;
  BYTE           EfficiencyClass;
  BYTE           Reserved[20];
  WORD           GroupCount;
  GROUP_AFFINITY GroupMask[ANYSIZE_ARRAY];
} PROCESSOR_RELATIONSHIP, *PPROCESSOR_RELATIONSHIP;

typedef struct _GROUP_RELATIONSHIP {
  WORD                 MaximumGroupCount;
  WORD                 ActiveGroupCount;
  BYTE                 Reserved[20];
  PROCESSOR_GROUP_INFO GroupInfo[ANYSIZE_ARRAY];
} GROUP_RELATIONSHIP, *PGROUP_RELATIONSHIP;

typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX {
  LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
  DWORD                          Size;
  union {
    PROCESSOR_RELATIONSHIP Processor;
    NUMA_NODE_RELATIONSHIP NumaNode;
    CACHE_RELATIONSHIP     Cache;
    GROUP_RELATIONSHIP     Group;
  } DUMMYUNIONNAME;
} SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, *PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX;

/*
NTSTATUS 
NtQuerySystemInformationEx( 
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);
*/
#endif