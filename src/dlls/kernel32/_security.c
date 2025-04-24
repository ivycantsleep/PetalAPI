#include <basedll.h>

//from Wine seucurity.c

BOOL set_ntstatus(NTSTATUS status)
{
    if (!NT_SUCCESS(status)) SetLastError( RtlNtStatusToDosError( status ));
    return NT_SUCCESS(status);
}