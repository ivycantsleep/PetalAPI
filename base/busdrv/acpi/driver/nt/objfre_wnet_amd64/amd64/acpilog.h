/*++ BUILD Version: 0001    // Increment this if a change has global effects

Copyright (c) 1999  Microsoft Corporation

Module Name:

    acpilog.mc

Abstract:

    Constant definitions for the I/O error code log values.

Revision History:

--*/

#ifndef _ACPILOG_
#define _ACPILOG_

//
//  Status values are 32 bit values layed out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-------------------------+-------------------------------+
//  |Sev|C|       Facility          |               Code            |
//  +---+-+-------------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//

//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//
#define FACILITY_RPC_STUBS               0x3
#define FACILITY_RPC_RUNTIME             0x2
#define FACILITY_IO_ERROR_CODE           0x4
#define FACILITY_ACPI_ERROR_LOG_CODE     0x5


//
// Define the severity codes
//
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_INFORMATIONAL    0x1
#define STATUS_SEVERITY_ERROR            0x3


//
// MessageId: ACPI_ERR_DUPLICATE_ADR
//
// MessageText:
//
// %1: ACPI Name Space Object %2 reports an _ADR (%3) that is already in use.
// Such conflicts are not legal. Please contact your system vendor for
// technical assistance.
//
#define ACPI_ERR_DUPLICATE_ADR           ((NTSTATUS)0xC0050001L)

//
// MessageId: ACPI_ERR_DUPLICATE_HID
//
// MessageText:
//
// %1: ACPI Name Space Object %2 reports an _HID (%3) that is already in use.
// Such conflicts are not legal. Please contact your system vendor for
// technical assistance.
//
#define ACPI_ERR_DUPLICATE_HID           ((NTSTATUS)0xC0050002L)

//
// MessageId: ACPI_ERR_BIOS_FATAL
//
// MessageText:
//
// %1: ACPI BIOS indicates that the machine has suffered a fatal error and needs to
// be shutdown as quickly as possible. Please contact your system vendor for
// technical assistance.
//
#define ACPI_ERR_BIOS_FATAL              ((NTSTATUS)0xC0050003L)

//
// MessageId: ACPI_ERR_AMLI_ILLEGAL_IO_READ_FATAL
//
// MessageText:
//
// %2: ACPI BIOS is attempting to read from an illegal IO port address (%3), which lies in the %4 protected
// address range. This could lead to system instability. Please contact your system vendor for technical assistance.
//
#define ACPI_ERR_AMLI_ILLEGAL_IO_READ_FATAL ((NTSTATUS)0xC0050004L)

//
// MessageId: ACPI_ERR_AMLI_ILLEGAL_IO_WRITE_FATAL
//
// MessageText:
//
// %2: ACPI BIOS is attempting to write to an illegal IO port address (%3), which lies in the %4 protected
// address range. This could lead to system instability. Please contact your system vendor for technical assistance.
//
#define ACPI_ERR_AMLI_ILLEGAL_IO_WRITE_FATAL ((NTSTATUS)0xC0050005L)

//
// MessageId: ACPI_ERR_MISSING_PRT_ENTRY
//
// MessageText:
//
// %2: ACPI BIOS does not contain an IRQ for the device in PCI slot %3, function %4.
// Please contact your system vendor for technical assistance.
//
#define ACPI_ERR_MISSING_PRT_ENTRY       ((NTSTATUS)0xC0050006L)

//
// MessageId: ACPI_ERR_ILLEGAL_IRQ_NUMBER
//
// MessageText:
//
// %2: ACPI BIOS indicates that a device will generate IRQ %3.  ACPI BIOS has also
// indicated that the machine has no IRQ %3.
//
#define ACPI_ERR_ILLEGAL_IRQ_NUMBER      ((NTSTATUS)0xC0050007L)

//
// MessageId: ACPI_ERR_MISSING_LINK_NODE
//
// MessageText:
//
// %2: ACPI BIOS indicates that device on slot %4, function %5 is attached to an
// IRQ routing device named %3.  This device cannot be found.
//
#define ACPI_ERR_MISSING_LINK_NODE       ((NTSTATUS)0xC0050008L)

//
// MessageId: ACPI_ERR_AMBIGUOUS_DEVICE_ADDRESS
//
// MessageText:
//
// %2: ACPI BIOS provided an ambiguous entry in the PCI Routing Table (_PRT.)  Illegal _PRT
// entry is of the form 0x%3%4.
//
#define ACPI_ERR_AMBIGUOUS_DEVICE_ADDRESS ((NTSTATUS)0xC0050009L)

//
// MessageId: ACPI_ERR_ILLEGAL_PCIOPREGION_WRITE
//
// MessageText:
//
// %2: ACPI BIOS is attempting to write to an illegal PCI Operation Region (%3), Please contact
// your system vendor for technical assistance.
//
#define ACPI_ERR_ILLEGAL_PCIOPREGION_WRITE ((NTSTATUS)0xC005000AL)

//
// MessageId: ACPI_ERR_NO_GPE_BLOCK
//
// MessageText:
//
// %2: ACPI BIOS is trying to reference a GPE Index (%3) when there are no GPE
// blocks defined by the BIOS. Please contact your system vendor for technical
// assistance.
//
#define ACPI_ERR_NO_GPE_BLOCK            ((NTSTATUS)0xC005000BL)

//
// MessageId: ACPI_ERR_AMLI_ILLEGAL_MEMORY_OPREGION_FATAL
//
// MessageText:
//
// %2: ACPI BIOS is attempting to create an illegal memory OpRegion, starting at address %3, 
// with a length of %4. This region lies in the Operating system's protected memory address range
// (%5 - %6). This could lead to system instability. 
// Please contact your system vendor for technical assistance.
//
#define ACPI_ERR_AMLI_ILLEGAL_MEMORY_OPREGION_FATAL ((NTSTATUS)0xC005000CL)

#endif /* _ACPILOG_ */
