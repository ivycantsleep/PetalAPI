/*
22-Nov-2020 moyefi implements the following Win32 APIs

NtQuerySystemInformationEx
*/

#include <basedll.h>
#include <_system.h>
//#include <_memory.h>


/******************************************************************************
 *              NtQuerySystemInformationEx  (NTDLL.@)
 */
 /*
 //not used (yet?)
NTSTATUS 
NtQuerySystemInformationEx( 
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
)
{
    ULONG len = 0;
    NTSTATUS ret = STATUS_NOT_IMPLEMENTED;

    //TRACE( "(0x%08x,%p,%u,%p,%u,%p) stub\n", SystemInformationClass, InputBuffer, InputBufferLength, info, SystemInformationLength, ReturnLength );

    switch (SystemInformationClass)
    {
    case SystemLogicalProcessorInformationEx:
    {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *buf;

        if (!InputBuffer || InputBufferLength < sizeof(DWORD))
        {
            ret = STATUS_INVALID_PARAMETER;
            break;
        }

        len = 3 * sizeof(*buf);
        if (!(buf = malloc( len )))
        {
            ret = STATUS_NO_MEMORY;
            break;
        }
        ret = create_logical_proc_info(NULL, &buf, &len, *(DWORD *)InputBuffer);
        if (!ret)
        {
            if (SystemInformationLength >= len)
            {
                if (!SystemInformation) ret = STATUS_ACCESS_VIOLATION;
                else memcpy(SystemInformation, buf, len);
            }
            else ret = STATUS_INFO_LENGTH_MISMATCH;
        }
        free( buf );
        break;
    }

    default:
       // FIXME( "(0x%08x,%p,%u,%p,%u,%p) stub\n", class, query, query_len, SystemInformation, SystemInformationLength, ReturnLength );
        break;
    }
    if (ReturnLength) *ReturnLength = len;
    return ret;
}
*/



/***********************************************************************
 *           GetLogicalProcessorInformationEx   (kernelbase.@)
 */
 //implemented as GetLogicalProcessorInformation call - but not giving out extra information ... needs to be implemented in kernel?
BOOL GetLogicalProcessorInformationEx(
  LOGICAL_PROCESSOR_RELATIONSHIP           RelationshipType,
  PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Buffer,
  PDWORD                                   ReturnedLength
)
{
	NTSTATUS Status;
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION Buffer2;

    if (ReturnedLength == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

	
    Status = NtQuerySystemInformation( SystemLogicalProcessorInformation,
                                       &Buffer2,
                                       *ReturnedLength,
                                       ReturnedLength);
    if (Status == STATUS_INFO_LENGTH_MISMATCH) {
        Status = STATUS_BUFFER_TOO_SMALL;
    } else {
		
		//copy values
		PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX pslpiex;
		//pslpiex.Relationship = RelationProcessorPackage;
		//pslpiex.Size = 0;
		/*
		PBYTE pb;
		do 
		{
			//DumpLPI(pslpi);

			Size = Buffer2->Size;
			pb += Size;

		} while (Buffer2 -= Size);
		//SYSTEM_LOGICAL_PROCESSOR_INFORMATION * buf;
		//int len = 7 * NtCurrentTeb()->ProcessEnvironmentBlock->NumberOfProcessors;
		/*buf = malloc( len * sizeof(*buf) );
		int number_slpi = ReturnedLength / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
		if (!buf)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return FALSE;
		}*/
		//this will fail!...
		//create_logical_proc_info( SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX **dataex, DWORD *max_len, DWORD relation )
		
	}
    if (!NT_SUCCESS(Status)) {
        SetLastError(Status);
        return FALSE;
    } else {
        return TRUE;
    }
}


BOOL GetProcessorGroupInformation(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Buffer, PDWORD ReturnedLength)
{
  /*BOOL result = GetLogicalProcessorInformationEx(
    RelationGroup,
	(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)NULL, 
	ReturnedLength);
  if (!result) {
	SetLastError(ERROR_INVALID_DATA);
	return FALSE;
  }
  int error = GetLastError();
  if (error != ERROR_INSUFFICIENT_BUFFER) {
	return FALSE;
  }
  Buffer = RtlAllocateHeap(Buffer->GROUP_RELATIONSHIP, 0, ReturnedLength);
  if (!Buffer) {
	SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	return FALSE;
  }
  int result = GetLogicalProcessorInformationEx(RelationGroup, Buffer, &ReturnedLength);
  if (!result) {
	RtlFreeHeap(Buffer->GROUP_RELATIONSHIP, 0, Buffer);
	return FALSE;
  }
  return TRUE;*/
  return FALSE;
}

//Windows 10 Ghidra - renamed some shit
DWORD GetActiveProcessorCount(WORD GroupNumber)
{/*
  byte bVar1;
  int iVar2;
  DWORD DVar3;
  uint uVar4;
  byte *pbVar5;
  int in_FS_OFFSET;
  DWORD local_10;
  SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Buffer;
  uint local_8;

  BOOL status = GetProcessorGroupInformation(&Buffer,&local_10);
  if (!status) {
    return 0;
  }
  else {
    if (GroupNumber == ALL_PROCESSOR_GROUPS) {
      uVar4 = (uint)*(ushort *)(logical_processor_information_ex->u + 2);
      local_8 = 0;
      if (*(ushort *)(logical_processor_information_ex->u + 2) != 0) {
        pbVar5 = logical_processor_information_ex->u + 0x19;
        do {
          bVar1 = *pbVar5;
          pbVar5 = pbVar5 + 0x2c;
          local_8 = (uint)(ushort)((short)local_8 + (ushort)bVar1);
          uVar4 = uVar4 - 1;
        } while (uVar4 != 0);
      }
    }
    else {
      if (GroupNumber < *(ushort *)(logical_processor_information_ex->u + 2)) {
        local_8 = (uint)logical_processor_information_ex->u[(uint)GroupNumber * 0x2c + 0x19];
      }
      else {
        local_8 = 0;
        RtlSetLastWin32Error(0x57);
      }
    }
    RtlFreeHeap(Buffer->GROUP_RELATIONSHIP, 0, Buffer);
    DVar3 = local_8 & ALL_PROCESSOR_GROUPS;
  }
  return DVar3;*/
	SYSTEM_INFO siSysInfo;
	GetNativeSystemInfo(&siSysInfo); //switched to GetNativeSystemInfo as it works under Wow64
	return siSysInfo.dwNumberOfProcessors;
}
