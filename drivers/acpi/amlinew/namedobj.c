/*** namedobj.c - Parse named object instructions
 *
 *  Copyright (c) 1996,1997 Microsoft Corporation
 *  Author:     Michael Tsang (MikeTs)
 *  Created     09/10/96
 *
 *  MODIFICATION HISTORY
 */

#include "pch.h"

// AcpiInformation re-definition
///////////////////////////////////////////////////
typedef struct _ACPIInformation {

    //
    // Linear address of Root System Description Table
    //
    PRSDT   RootSystemDescTable;

    //
    // Linear address of Fixed ACPI Description Table
    //
    PFADT FixedACPIDescTable;

    //
    // Linear address of the FACS
    //
    PFACS FirmwareACPIControlStructure;

    //
    // Linear address of Differentiated System Description Table
    //
    PDSDT   DiffSystemDescTable;

    //
    // Linear address of Mulitple APIC table
    //
    PMAPIC  MultipleApicTable;

    //
    // Linear address of GlobalLock ULONG_PTR (contained within Firmware ACPI control structure)
    //
    PULONG  GlobalLock;

    //
    // Queue used for waiting on release of the Global Lock.  Also, queue
    // lock and owner info.
    //
    LIST_ENTRY      GlobalLockQueue;
    KSPIN_LOCK      GlobalLockQueueLock;
    PVOID           GlobalLockOwnerContext;
    ULONG           GlobalLockOwnerDepth;

    //
    // Did we find SCI_EN set when we loaded ?
    //
    BOOLEAN ACPIOnly;

    //
    // I/O address of PM1a_BLK
    //
    ULONG_PTR   PM1a_BLK;

    //
    // I/O address of PM1b_BLK
    //
    ULONG_PTR   PM1b_BLK;

    //
    // I/O address of PM1a_CNT_BLK
    //
    ULONG_PTR   PM1a_CTRL_BLK;

    //
    // I/O address of PM1b_CNT_BLK
    //
    ULONG_PTR   PM1b_CTRL_BLK;

    //
    // I/O address of PM2_CNT_BLK
    //
    ULONG_PTR   PM2_CTRL_BLK;

    //
    // I/O address of PM_TMR
    //
    ULONG_PTR   PM_TMR;
    ULONG_PTR   GP0_BLK;
    ULONG_PTR   GP0_ENABLE;

    //
    // Length of GP0 register block (Total, status+enable regs)
    //
    UCHAR   GP0_LEN;

    //
    // Number of GP0 logical registers
    //
    USHORT  Gpe0Size;
    ULONG_PTR   GP1_BLK;
    ULONG_PTR   GP1_ENABLE;

    //
    // Length of GP1 register block
    //
    UCHAR   GP1_LEN;

    //
    // Number of GP1 logical registers
    //
    USHORT  Gpe1Size;
    USHORT  GP1_Base_Index;

    //
    // Total number of GPE logical registers
    //
    USHORT  GpeSize;

    //
    // I/O address of SMI_CMD
    //
    ULONG_PTR SMI_CMD;

    //
    // Bit mask of enabled PM1 events.
    //
    USHORT  pm1_en_bits;
    USHORT  pm1_wake_mask;
    USHORT  pm1_wake_status;
    USHORT  c2_latency;
    USHORT  c3_latency;

    //
    // see below for bit descriptions.
    //
    ULONG   ACPI_Flags;
    ULONG   ACPI_Capabilities;

    BOOLEAN Dockable;

} ACPIInformation, *PACPIInformation;
extern PACPIInformation AcpiInformation;
///////////////////////////////////////////////////

#ifdef  LOCKABLE_PRAGMA
#pragma ACPI_LOCKABLE_DATA
#pragma ACPI_LOCKABLE_CODE
#endif

/***LP  BankField - Parse and execute the BankField instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL BankField(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("BANKFIELD")
    NTSTATUS rc = STATUS_SUCCESS;
    PNSOBJ pnsBase, pnsBank;

    ENTER(2, ("BankField(pctxt=%x,pterm=%x,pbOp=%x)\n",
              pctxt, pterm, pctxt->pbOp));

    if (((rc = GetNameSpaceObject((PSZ)pterm->pdataArgs[0].pbDataBuff,
                                  pctxt->pnsScope, &pnsBase, NSF_WARN_NOTFOUND))
         == STATUS_SUCCESS) &&
        ((rc = GetNameSpaceObject((PSZ)pterm->pdataArgs[1].pbDataBuff,
                                  pctxt->pnsScope, &pnsBank, NSF_WARN_NOTFOUND))
         == STATUS_SUCCESS))
    {
        if (pnsBase->ObjData.dwDataType != OBJTYPE_OPREGION)
        {
            rc = AMLI_LOGERR(AMLIERR_UNEXPECTED_OBJTYPE,
                             ("BankField: %s is not an operation region",
                              pterm->pdataArgs[0].pbDataBuff));
        }
        else if (pnsBank->ObjData.dwDataType != OBJTYPE_FIELDUNIT)
        {
            rc = AMLI_LOGERR(AMLIERR_UNEXPECTED_OBJTYPE,
                             ("BankField: %s is not a field unit",
                              pterm->pdataArgs[1].pbDataBuff));
        }
        else if ((rc = CreateNameSpaceObject(pctxt->pheapCurrent, NULL,
                                             pctxt->pnsScope, pctxt->powner,
                                             &pterm->pnsObj, 0)) ==
                 STATUS_SUCCESS)
        {
            pterm->pnsObj->ObjData.dwDataType = OBJTYPE_BANKFIELD;
            pterm->pnsObj->ObjData.dwDataLen = sizeof(BANKFIELDOBJ);

            if ((pterm->pnsObj->ObjData.pbDataBuff =
                 NEWKFOBJ(pctxt->pheapCurrent,
                          pterm->pnsObj->ObjData.dwDataLen)) == NULL)
            {
                rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                                 ("BankField: failed to allocate BankField object"));
            }
            else
            {
                PBANKFIELDOBJ pbf;

                MEMZERO(pterm->pnsObj->ObjData.pbDataBuff,
                        pterm->pnsObj->ObjData.dwDataLen);
                pbf = (PBANKFIELDOBJ)pterm->pnsObj->ObjData.pbDataBuff;
                pbf->pnsBase = pnsBase;
                pbf->pnsBank = pnsBank;
                pbf->dwBankValue = (ULONG)pterm->pdataArgs[2].uipDataValue;
                rc = ParseFieldList(pctxt, pterm->pbOpEnd, pterm->pnsObj,
                                    (ULONG)pterm->pdataArgs[3].uipDataValue,
                                    ((POPREGIONOBJ)pnsBase->ObjData.pbDataBuff)->dwLen);
            }
        }
    }

    EXIT(2, ("BankField=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //BankField

/***LP  CreateXField - Parse and execute the CreateXField instructions
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *      pdataTarget -> Target object data
 *      ppbf -> to hold created target BuffField object
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL CreateXField(PCTXT pctxt, PTERM pterm, POBJDATA pdataTarget,
                            PBUFFFIELDOBJ *ppbf)
{
    TRACENAME("CREATEXFIELD")
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA pdata = NULL;

    ENTER(2, ("CreateXField(pctxt=%x,pbOp=%x,pterm=%x,pdataTarget=%x,ppbf=%x)\n",
              pctxt, pctxt->pbOp, pterm, pdataTarget, ppbf));

    ASSERT(pdataTarget != NULL);
    ASSERT(pdataTarget->dwDataType == OBJTYPE_STRDATA);
    if (((rc = ValidateArgTypes(pterm->pdataArgs, "BI")) == STATUS_SUCCESS) &&
        ((rc = CreateNameSpaceObject(pctxt->pheapCurrent,
                                     (PSZ)pdataTarget->pbDataBuff,
                                     pctxt->pnsScope, pctxt->powner,
                                     &pterm->pnsObj, 0)) == STATUS_SUCCESS))
    {
        pdata = &pterm->pnsObj->ObjData;
        pdata->dwDataType = OBJTYPE_BUFFFIELD;
        pdata->dwDataLen = sizeof(BUFFFIELDOBJ);
        if ((pdata->pbDataBuff = NEWBFOBJ(pctxt->pheapCurrent,
                                          pdata->dwDataLen)) == NULL)
        {
            rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                             ("CreateXField: failed to allocate BuffField object"));
        }
        else
        {
            MEMZERO(pdata->pbDataBuff, pdata->dwDataLen);
            *ppbf = (PBUFFFIELDOBJ)pdata->pbDataBuff;
            (*ppbf)->pbDataBuff = pterm->pdataArgs[0].pbDataBuff;
            (*ppbf)->dwBuffLen = pterm->pdataArgs[0].dwDataLen;
        }
    }

    EXIT(2, ("CreateXField=%x (pdata=%x)\n", rc, pdata));
    return rc;
}       //CreateXField

/***LP  CreateBitField - Parse and execute the CreateBitField instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL CreateBitField(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("CREATEBITFIELD")
    NTSTATUS rc = STATUS_SUCCESS;
    PBUFFFIELDOBJ pbf;

    ENTER(2, ("CreateBitField(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if ((rc = CreateXField(pctxt, pterm, &pterm->pdataArgs[2], &pbf)) ==
        STATUS_SUCCESS)
    {
        pbf->FieldDesc.dwByteOffset = (ULONG)
                                      (pterm->pdataArgs[1].uipDataValue/8);
        pbf->FieldDesc.dwStartBitPos = (ULONG)
                                       (pterm->pdataArgs[1].uipDataValue -
                                        pbf->FieldDesc.dwByteOffset*8);
        pbf->FieldDesc.dwNumBits = 1;
        pbf->FieldDesc.dwFieldFlags = ACCTYPE_BYTE;
    }

    EXIT(2, ("CreateBitField=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //CreateBitField

/***LP  CreateByteField - Parse and execute the CreateByteField instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL CreateByteField(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("CREATEBYTEFIELD")
    NTSTATUS rc = STATUS_SUCCESS;
    PBUFFFIELDOBJ pbf;

    ENTER(2, ("CreateByteField(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if ((rc = CreateXField(pctxt, pterm, &pterm->pdataArgs[2], &pbf)) ==
        STATUS_SUCCESS)
    {
        pbf->FieldDesc.dwByteOffset = (ULONG)pterm->pdataArgs[1].uipDataValue;
        pbf->FieldDesc.dwStartBitPos = 0;
        pbf->FieldDesc.dwNumBits = 8*sizeof(UCHAR);
        pbf->FieldDesc.dwFieldFlags = ACCTYPE_BYTE;
    }

    EXIT(2, ("CreateByteField=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //CreateByteField

/***LP  CreateWordField - Parse and execute the CreateWordField instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL CreateWordField(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("CREATEWORDFIELD")
    NTSTATUS rc = STATUS_SUCCESS;
    PBUFFFIELDOBJ pbf;

    ENTER(2, ("CreateWordField(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if ((rc = CreateXField(pctxt, pterm, &pterm->pdataArgs[2], &pbf)) ==
        STATUS_SUCCESS)
    {
        pbf->FieldDesc.dwByteOffset = (ULONG)pterm->pdataArgs[1].uipDataValue;
        pbf->FieldDesc.dwStartBitPos = 0;
        pbf->FieldDesc.dwNumBits = 8*sizeof(USHORT);
        pbf->FieldDesc.dwFieldFlags = ACCTYPE_WORD;
    }

    EXIT(2, ("CreateWordField=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //CreateWordField

/***LP  CreateDWordField - Parse and execute the CreateDWordField instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL CreateDWordField(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("CREATEDWORDFIELD")
    NTSTATUS rc = STATUS_SUCCESS;
    PBUFFFIELDOBJ pbf;

    ENTER(2, ("CreateDWordField(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if ((rc = CreateXField(pctxt, pterm, &pterm->pdataArgs[2], &pbf)) ==
        STATUS_SUCCESS)
    {
        pbf->FieldDesc.dwByteOffset = (ULONG)pterm->pdataArgs[1].uipDataValue;
        pbf->FieldDesc.dwStartBitPos = 0;
        pbf->FieldDesc.dwNumBits = 8*sizeof(ULONG);
        pbf->FieldDesc.dwFieldFlags = ACCTYPE_DWORD;
    }

    EXIT(2, ("CreateDWordField=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //CreateDWordField

/***LP  CreateField - Parse and execute the CreateField instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL CreateField(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("CREATEFIELD")
    NTSTATUS rc = STATUS_SUCCESS;
    PBUFFFIELDOBJ pbf;

    ENTER(2, ("CreateField(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if (pterm->pdataArgs[2].dwDataType == OBJTYPE_INTDATA)
    {
        if ((rc = CreateXField(pctxt, pterm, &pterm->pdataArgs[3], &pbf)) ==
            STATUS_SUCCESS)
        {
            pbf->FieldDesc.dwByteOffset = (ULONG)
                                          (pterm->pdataArgs[1].uipDataValue/8);
            pbf->FieldDesc.dwStartBitPos = (ULONG)
                                           (pterm->pdataArgs[1].uipDataValue -
                                            pbf->FieldDesc.dwByteOffset*8);
            pbf->FieldDesc.dwNumBits = (ULONG)pterm->pdataArgs[2].uipDataValue;
            pbf->FieldDesc.dwFieldFlags = ACCTYPE_BYTE | FDF_BUFFER_TYPE;
        }
    }
    else
    {
        rc = AMLI_LOGERR(AMLIERR_UNEXPECTED_ARGTYPE,
                         ("CreateField: NoBits must be evaluated to integer type"));
    }

    EXIT(2, ("CreateField=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //CreateField

/***LP  Device - Parse and execute the Scope instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL Device(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("DEVICE")
    NTSTATUS rc = STATUS_SUCCESS;
    PUCHAR  NextOp, OneByte, TwoByte, ThreeByte, FourByte;
    PUCHAR  DeviceDef;
    ULONG   ProcDefType = 0;
    ULONG   i, DeviceOpSize;

    ENTER(2, ("Device(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    // convert Device(HID=ACPI0007,...) to Processor(...) opcode

    // ACPI0007 Device definition #1:
    // 5B 82 1A 43 30 30 30                             Device (C000)
    // 08 5F 48 49 44 0D 41 43 50 49 30 30 30 37 00     Name (_HID, "ACPI0007") <- OrigOp
    // 08 5F 55 49 44 00                                Name (_UID, Zero)
    // 5B 82 1A XX XX XX XX 08 5F 48 49 44 0D 41 43 50 49 30 30 30 37 00 08 5F 55 49 44 YY

    // ACPI0007 Device definition #2:
    // 5B 82 1B 43 30 30 30                             Device (C000)
    // 08 5F 48 49 44 0D 41 43 50 49 30 30 30 37 00     Name (_HID, "ACPI0007") <- OrigOp
    // 08 5F 55 49 44 0A YY                             Name (_UID, 2)
    // 5B 82 1B XX XX XX XX 08 5F 48 49 44 0D 41 43 50 49 30 30 30 37 00 08 5F 55 49 44 0A YY


    NextOp = pctxt->pbOp;   // next OP
    DeviceDef = NextOp - 7 ;  // 5B 82 1A / 5B 82 1B

    if (NextOp) { // next OP exist 
        if (DeviceDef[0] == 0x5B &&  // 5B 82 1A definition #1
            DeviceDef[1] == 0x82 &&
            DeviceDef[2] == 0x1A ) {
            ProcDefType = 1;
            DeviceOpSize = 28;
            KdPrint(("Try ACPI0007 def #1 \n"));
        } else
        if (DeviceDef[0] == 0x5B &&  // 5B 82 1B definition #2
            DeviceDef[1] == 0x82 &&
            DeviceDef[2] == 0x1B ) {
            ProcDefType = 2;
            DeviceOpSize = 29;
            KdPrint(("Try ACPI0007 def #2 \n"));
        }
    }

    if (ProcDefType == 0 ||
        DeviceDef[13] != 'A' ||
        DeviceDef[14] != 'C' ||
        DeviceDef[15] != 'P' ||
        DeviceDef[16] != 'I' ||
        DeviceDef[17] != '0' ||
        DeviceDef[18] != '0' ||
        DeviceDef[19] != '0' ||
        DeviceDef[20] != '7' )
        ProcDefType = 0;    // not ACPI0007

    if (ProcDefType != 0) {
        CHAR    ProcName[4]; 
        UCHAR   ProcEnum;
        ULONG   dwPBlk, dwPBlkLen;
        UCHAR   *pdwPBlk;

        ProcName[0] = DeviceDef[3];   // N
        ProcName[1] = DeviceDef[4];   // A
        ProcName[2] = DeviceDef[5];   // M
        ProcName[3] = DeviceDef[6];   // E

        // FACP.PM1A_Event_Block + 0x10, https://www.tonymacx86.com/threads/cpu-wrapping-ssdt-cpu-wrap-ssdt-cpur-acpi0007.316894/
        dwPBlk    = (ULONG) AcpiInformation->FixedACPIDescTable->pm1a_evt_blk_io_port + 0x10;

        // 0 or 6 per ACPI spec
        dwPBlkLen = (ULONG) 6;

        // Processor (CPU0, 0x01, 0x00001810, 0x06) (NAME, enum, addr, size)
        // 5B 83 0B 43 50 55 30 01 10 18 00 00 06
        DeviceDef[0] = 0x5B;
        DeviceDef[1] = 0x83;
        DeviceDef[2] = 0x0B;

        DeviceDef[3] = ProcName[0];
        DeviceDef[4] = ProcName[1];
        DeviceDef[5] = ProcName[2];
        DeviceDef[6] = ProcName[3];

        if (ProcDefType == 1)
           DeviceDef[7] = DeviceDef[27]; // YY
        else
        if (ProcDefType == 2)
           DeviceDef[7] = DeviceDef[28]; // YY

        pdwPBlk = (UCHAR *) &dwPBlk;

        DeviceDef[8]  = pdwPBlk[0];
        DeviceDef[9]  = pdwPBlk[1];
        DeviceDef[10] = pdwPBlk[2];
        DeviceDef[11] = pdwPBlk[3];

        DeviceDef[12] = (UCHAR) dwPBlkLen;

        for (i = 13; i < DeviceOpSize; i++) {
            DeviceDef[i] = 0xA3; // Noop 
        }

        pctxt->pbOp = DeviceDef; // reverse OPcode back

        KdPrint(("ACPI0007 CPU=%x PBlk=%x NextOp=%X,%X,%X,%X \n",
                    DeviceDef[7],
                    dwPBlk,
                    DeviceDef[DeviceOpSize],
                    DeviceDef[DeviceOpSize+1],
                    DeviceDef[DeviceOpSize+2],
                    DeviceDef[DeviceOpSize+3]));
    }
    else
    {   // normal Device()
    if ((rc = CreateNameSpaceObject(pctxt->pheapCurrent,
                                    (PSZ)pterm->pdataArgs[0].pbDataBuff,
                                    pctxt->pnsScope, pctxt->powner,
                                    &pterm->pnsObj, 0)) == STATUS_SUCCESS)
    {
        pterm->pnsObj->ObjData.dwDataType = OBJTYPE_DEVICE;
        if (ghCreate.pfnHandler != NULL)
        {
            ((PFNOO)ghCreate.pfnHandler)(OBJTYPE_DEVICE, pterm->pnsObj);
        }
        rc = PushScope(pctxt, pctxt->pbOp, pterm->pbOpEnd, NULL, pterm->pnsObj,
                       pctxt->powner, pctxt->pheapCurrent, pterm->pdataResult);
    }
    else
    if (rc == AMLIERR_OBJ_ALREADY_EXIST) {
        // Doubled device definition workaround, change OpCode pointer to next object
        NextOp = pctxt->pbOp;   // next OP
        OneByte =   NextOp - 7 ;  // 5B 82 (3F)          NN AA MM EE
        TwoByte =   NextOp - 8 ;  // 5B 82 (4F L2)       NN AA MM EE
        ThreeByte = NextOp - 9 ;  // 5B 82 (8F L2 L3)    NN AA MM EE
        FourByte =  NextOp - 10 ; // 5B 82 (CF L3 L3 L4) NN AA MM EE

        rc = STATUS_SUCCESS;

        if (NextOp) { // next OP exist 
            if (OneByte[0]   == 0x5B && OneByte[1]   == 0x82) { // 0x5B 0x82 Device() Opcode
                pctxt->pbOp = OneByte + OneByte[2] + 2;         // start + pkglength + opcodelength
            } else
            if (TwoByte[0]   == 0x5B && TwoByte[1]   == 0x82) {
                pctxt->pbOp = TwoByte + (TwoByte[3] << 4) + (TwoByte[2] & 0x0F) + 2; // pkglength magic
            } else
            if (ThreeByte[0] == 0x5B && ThreeByte[1] == 0x82) {
                pctxt->pbOp = ThreeByte + (ThreeByte[4] << (4+8)) + (ThreeByte[3] << 4) + (ThreeByte[2] & 0x0F) + 2;
            } else
            if (FourByte[0]  == 0x5B && FourByte[1]  == 0x82) {
                pctxt->pbOp = FourByte + (FourByte[5] << (4+8+8)) + (FourByte[4] << (4+8)) + (FourByte[3] << 4) + (FourByte[2] & 0x0F) + 2;
            }
            else
                rc = AMLIERR_OBJ_ALREADY_EXIST;   // unknow Device() opcode coding
        }
    }
    }

    EXIT(2, ("Device=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //Device

/***LP  InitEvent - Initialize an event object
 *
 *  ENTRY
 *      pheap -> HEAP
 *      pns -> event object to be initialized
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL InitEvent(PHEAP pheap, PNSOBJ pns)
{
    TRACENAME("INITEVENT")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("InitEvent(pheap=%x,pns=%x)\n", pheap, pns));

    pns->ObjData.dwDataType = OBJTYPE_EVENT;
    pns->ObjData.dwDataLen = sizeof(EVENTOBJ);

    if ((pns->ObjData.pbDataBuff = NEWEVOBJ(pheap, pns->ObjData.dwDataLen)) ==
        NULL)
    {
        rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                         ("InitEvent: failed to allocate Event object"));
    }
    else
    {
        MEMZERO(pns->ObjData.pbDataBuff, pns->ObjData.dwDataLen);
    }

    EXIT(2, ("InitEvent=%x\n", rc));
    return rc;
}       //InitEvent

/***LP  Event - Parse and execute the Event instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL Event(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("EVENT")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("Event(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    if ((rc = CreateNameSpaceObject(pctxt->pheapCurrent,
                                    (PSZ)pterm->pdataArgs[0].pbDataBuff,
                                    pctxt->pnsScope, pctxt->powner,
                                    &pterm->pnsObj, 0)) == STATUS_SUCCESS)
    {
        rc = InitEvent(pctxt->pheapCurrent, pterm->pnsObj);
    }

    EXIT(2, ("Event=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //Event

/***LP  Field - Parse and execute the Field instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL Field(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("FIELD")
    NTSTATUS rc = STATUS_SUCCESS;
    PNSOBJ pnsBase;

    ENTER(2, ("Field(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    if ((rc = GetNameSpaceObject((PSZ)pterm->pdataArgs[0].pbDataBuff,
                                 pctxt->pnsScope, &pnsBase, NSF_WARN_NOTFOUND))
        == STATUS_SUCCESS)
    {
        if (pnsBase->ObjData.dwDataType != OBJTYPE_OPREGION)
        {
            rc = AMLI_LOGERR(AMLIERR_UNEXPECTED_OBJTYPE,
                             ("Field: %s is not an operation region",
                              pterm->pdataArgs[0].pbDataBuff));
        }
        else if ((rc = CreateNameSpaceObject(pctxt->pheapCurrent, NULL,
                                             pctxt->pnsScope, pctxt->powner,
                                             &pterm->pnsObj, 0)) ==
                 STATUS_SUCCESS)
        {
            pterm->pnsObj->ObjData.dwDataType = OBJTYPE_FIELD;
            pterm->pnsObj->ObjData.dwDataLen = sizeof(FIELDOBJ);

            if ((pterm->pnsObj->ObjData.pbDataBuff =
                 NEWFOBJ(pctxt->pheapCurrent,
                         pterm->pnsObj->ObjData.dwDataLen)) == NULL)
            {
                rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                                 ("Field: failed to allocate Field object"));
            }
            else
            {
                PFIELDOBJ pfd;

                MEMZERO(pterm->pnsObj->ObjData.pbDataBuff,
                        pterm->pnsObj->ObjData.dwDataLen);
                pfd = (PFIELDOBJ)pterm->pnsObj->ObjData.pbDataBuff;
                pfd->pnsBase = pnsBase;
                rc = ParseFieldList(pctxt, pterm->pbOpEnd, pterm->pnsObj,
                                    (ULONG)pterm->pdataArgs[1].uipDataValue,
                                    ((POPREGIONOBJ)pnsBase->ObjData.pbDataBuff)->dwLen);
            }
        }
    }

    EXIT(2, ("Field=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //Field

/***LP  IndexField - Parse and execute the Field instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL IndexField(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("INDEXFIELD")
    NTSTATUS rc = STATUS_SUCCESS;
    PNSOBJ pnsIdx, pnsData;

    ENTER(2, ("IndexField(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if (((rc = GetNameSpaceObject((PSZ)pterm->pdataArgs[0].pbDataBuff,
                                  pctxt->pnsScope, &pnsIdx, NSF_WARN_NOTFOUND))
         == STATUS_SUCCESS) &&
        ((rc = GetNameSpaceObject((PSZ)pterm->pdataArgs[1].pbDataBuff,
                                  pctxt->pnsScope, &pnsData, NSF_WARN_NOTFOUND))
         == STATUS_SUCCESS))
    {
        if (pnsIdx->ObjData.dwDataType != OBJTYPE_FIELDUNIT)
        {
            rc = AMLI_LOGERR(AMLIERR_UNEXPECTED_OBJTYPE,
                             ("IndexField: Index (%s) is not a field unit",
                              pterm->pdataArgs[0].pbDataBuff));
        }
        else if (pnsData->ObjData.dwDataType != OBJTYPE_FIELDUNIT)
        {
            rc = AMLI_LOGERR(AMLIERR_UNEXPECTED_OBJTYPE,
                             ("IndexField: Data (%s) is not a field unit",
                              pterm->pdataArgs[1].pbDataBuff));
        }
        else if ((rc = CreateNameSpaceObject(pctxt->pheapCurrent, NULL,
                                             pctxt->pnsScope, pctxt->powner,
                                             &pterm->pnsObj, 0)) ==
                 STATUS_SUCCESS)
        {
            pterm->pnsObj->ObjData.dwDataType = OBJTYPE_INDEXFIELD;
            pterm->pnsObj->ObjData.dwDataLen = sizeof(INDEXFIELDOBJ);

            if ((pterm->pnsObj->ObjData.pbDataBuff =
                 NEWIFOBJ(pctxt->pheapCurrent,
                          pterm->pnsObj->ObjData.dwDataLen)) == NULL)
            {
                rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                                 ("IndexField: failed to allocate IndexField object"));
            }
            else
            {
                PINDEXFIELDOBJ pif;

                MEMZERO(pterm->pnsObj->ObjData.pbDataBuff,
                        pterm->pnsObj->ObjData.dwDataLen);
                pif = (PINDEXFIELDOBJ)pterm->pnsObj->ObjData.pbDataBuff;
                pif->pnsIndex = pnsIdx;
                pif->pnsData = pnsData;
                rc = ParseFieldList(pctxt, pterm->pbOpEnd, pterm->pnsObj,
                                    (ULONG)pterm->pdataArgs[2].uipDataValue,
                                    0xffffffff);
            }
        }
    }

    EXIT(2, ("IndexField=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //IndexField

/***LP  Method - Parse and execute the Method instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL Method(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("METHOD")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("Method(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if ((rc = CreateNameSpaceObject(pctxt->pheapCurrent,
                                    (PSZ)pterm->pdataArgs[0].pbDataBuff,
                                    pctxt->pnsScope, pctxt->powner,
                                    &pterm->pnsObj, 0)) == STATUS_SUCCESS)
    {
        pterm->pnsObj->ObjData.dwDataType = OBJTYPE_METHOD;
        pterm->pnsObj->ObjData.dwDataLen = (ULONG)(FIELD_OFFSET(METHODOBJ,
                                                                abCodeBuff) +
                                                   pterm->pbOpEnd -
                                                   pctxt->pbOp);

        if ((pterm->pnsObj->ObjData.pbDataBuff =
             NEWMEOBJ(pctxt->pheapCurrent, pterm->pnsObj->ObjData.dwDataLen))
            == NULL)
        {
            rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                             ("Method: failed to allocate method buffer"));
        }
        else
        {
            PMETHODOBJ pm = (PMETHODOBJ)pterm->pnsObj->ObjData.pbDataBuff;

          #ifdef DEBUGGER
            AddObjSymbol(pm->abCodeBuff, pterm->pnsObj);
          #endif
            MEMZERO(pterm->pnsObj->ObjData.pbDataBuff,
                    pterm->pnsObj->ObjData.dwDataLen);
            pm->bMethodFlags = *(pctxt->pbOp - 1);
            MEMCPY(&pm->abCodeBuff, pctxt->pbOp, pterm->pbOpEnd - pctxt->pbOp);
            pctxt->pbOp = pterm->pbOpEnd;
        }
    }

    EXIT(2, ("Method=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //Method

/***LP  InitMutex - Initialize a mutex object
 *
 *  ENTRY
 *      pheap -> HEAP
 *      pns -> mutex object to be initialized
 *      dwLevel - sync level
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL InitMutex(PHEAP pheap, PNSOBJ pns, ULONG dwLevel)
{
    TRACENAME("INITMUTEX")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("InitMutex(pheap=%x,pns=%x,Level=%x)\n", pheap, pns, dwLevel));

    pns->ObjData.dwDataType = OBJTYPE_MUTEX;
    pns->ObjData.dwDataLen = sizeof(MUTEXOBJ);

    if ((pns->ObjData.pbDataBuff = NEWMTOBJ(pheap, pns->ObjData.dwDataLen)) ==
        NULL)
    {
        rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                         ("InitMutex: failed to allocate Mutex object"));
    }
    else
    {
        MEMZERO(pns->ObjData.pbDataBuff, pns->ObjData.dwDataLen);
        ((PMUTEXOBJ)pns->ObjData.pbDataBuff)->dwSyncLevel = dwLevel;
    }

    EXIT(2, ("InitMutex=%x\n", rc));
    return rc;
}       //InitMutex

/***LP  Mutex - Parse and execute the Mutex instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL Mutex(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("MUTEX")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("Mutex(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    if ((rc = CreateNameSpaceObject(pctxt->pheapCurrent,
                                    (PSZ)pterm->pdataArgs[0].pbDataBuff,
                                    pctxt->pnsScope, pctxt->powner,
                                    &pterm->pnsObj, 0)) == STATUS_SUCCESS)
    {
        rc = InitMutex(pctxt->pheapCurrent, pterm->pnsObj,
                       (ULONG)pterm->pdataArgs[1].uipDataValue);
    }

    EXIT(2, ("Mutex=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //Mutex

/***LP  OpRegion - Parse and execute the Field instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL OpRegion(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("OPREGION")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("OpRegion(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));
    if ((rc = CreateNameSpaceObject(pctxt->pheapCurrent,
                                    (PSZ)pterm->pdataArgs[0].pbDataBuff,
                                    pctxt->pnsScope, pctxt->powner,
                                    &pterm->pnsObj, 0)) == STATUS_SUCCESS)
    {
        pterm->pnsObj->ObjData.dwDataType = OBJTYPE_OPREGION;
        pterm->pnsObj->ObjData.dwDataLen = sizeof(OPREGIONOBJ);

        if ((pterm->pnsObj->ObjData.pbDataBuff =
             NEWOROBJ(pctxt->pheapCurrent, pterm->pnsObj->ObjData.dwDataLen))
            == NULL)
        {
            rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                             ("OpRegion: failed to allocate OpRegion object"));
        }
        else
        {
            POPREGIONOBJ pop;

            MEMZERO(pterm->pnsObj->ObjData.pbDataBuff,
                    pterm->pnsObj->ObjData.dwDataLen);
            pop = (POPREGIONOBJ)pterm->pnsObj->ObjData.pbDataBuff;
            pop->bRegionSpace = (UCHAR)pterm->pdataArgs[1].uipDataValue;
            pop->uipOffset = pterm->pdataArgs[2].uipDataValue;
            pop->dwLen = (ULONG)pterm->pdataArgs[3].uipDataValue;
            KeInitializeSpinLock(&pop->listLock);
            if (pop->bRegionSpace == REGSPACE_MEM)
            {
                if(gInitTime)
                {
                    ValidateMemoryOpregionRange(pop->uipOffset, pop->dwLen);
                }

                rc = MapUnmapPhysMem(pctxt, pop->uipOffset, pop->dwLen,
                                     &pop->uipOffset);
            }
            else if (pop->bRegionSpace == REGSPACE_IO)
            {
                PHYSICAL_ADDRESS phyaddr = {0, 0}, XlatedAddr;
                ULONG dwAddrSpace;

                phyaddr.LowPart = (ULONG)pop->uipOffset;
                dwAddrSpace = 1;
                if (HalTranslateBusAddress(Internal, 0, phyaddr, &dwAddrSpace,
                                           &XlatedAddr))
                {
                    pop->uipOffset = (ULONG_PTR)XlatedAddr.LowPart;
                }
                else
                {
                    rc = AMLI_LOGERR(AMLIERR_FAILED_ADDR_XLATE,
                                     ("OpRegion: failed to translate IO address %x",
                                      pop->uipOffset));
                }

            }
            else if (pop->bRegionSpace == REGSPACE_PCIBARTARGET)
            {
                if (ghCreate.pfnHandler != NULL)
                {
                    ((PFNOO)ghCreate.pfnHandler)(OBJTYPE_OPREGION, pterm->pnsObj);
                }
            }
        }
    }
    EXIT(2, ("OpRegion=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //OpRegion

/***LP  PowerRes - Parse and execute the PowerRes instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL PowerRes(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("POWERRES")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("PowerRes(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if ((rc = CreateNameSpaceObject(pctxt->pheapCurrent,
                                    (PSZ)pterm->pdataArgs[0].pbDataBuff,
                                    pctxt->pnsScope, pctxt->powner,
                                    &pterm->pnsObj, 0)) == STATUS_SUCCESS)
    {
        pterm->pnsObj->ObjData.dwDataType = OBJTYPE_POWERRES;
        pterm->pnsObj->ObjData.dwDataLen = sizeof(POWERRESOBJ);

        if ((pterm->pnsObj->ObjData.pbDataBuff =
             NEWPROBJ(pctxt->pheapCurrent, pterm->pnsObj->ObjData.dwDataLen))
            == NULL)
        {
            rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                             ("PowerRes: failed to allocate PowerRes object"));
        }
        else
        {
            PPOWERRESOBJ ppr;

            MEMZERO(pterm->pnsObj->ObjData.pbDataBuff,
                    pterm->pnsObj->ObjData.dwDataLen);
            ppr = (PPOWERRESOBJ)pterm->pnsObj->ObjData.pbDataBuff;
            ppr->bSystemLevel = (UCHAR)pterm->pdataArgs[1].uipDataValue;
            ppr->bResOrder = (UCHAR)pterm->pdataArgs[2].uipDataValue;
            if (ghCreate.pfnHandler != NULL)
            {
                ((PFNOO)ghCreate.pfnHandler)(OBJTYPE_POWERRES, pterm->pnsObj);
            }
            rc = PushScope(pctxt, pctxt->pbOp, pterm->pbOpEnd, NULL,
                           pterm->pnsObj, pctxt->powner, pctxt->pheapCurrent,
                           pterm->pdataResult);
        }
    }

    EXIT(2, ("PowerRes=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //PowerRes

/***LP  Processor - Parse and execute the Processor instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL Processor(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("PROCESSOR")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("Processor(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if ((rc = CreateNameSpaceObject(pctxt->pheapCurrent,
                                    (PSZ)pterm->pdataArgs[0].pbDataBuff,
                                    pctxt->pnsScope, pctxt->powner,
                                    &pterm->pnsObj, 0)) == STATUS_SUCCESS)
    {

        pterm->pnsObj->ObjData.dwDataType = OBJTYPE_PROCESSOR;
        pterm->pnsObj->ObjData.dwDataLen = sizeof(PROCESSOROBJ);

        if ((pterm->pnsObj->ObjData.pbDataBuff =
             NEWPCOBJ(pctxt->pheapCurrent, pterm->pnsObj->ObjData.dwDataLen))
            == NULL)
        {
            rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                             ("Processor: failed to allocate processor object"));
        }
        else
        {
            PPROCESSOROBJ pproc;

            MEMZERO(pterm->pnsObj->ObjData.pbDataBuff,
                    pterm->pnsObj->ObjData.dwDataLen);
            pproc = (PPROCESSOROBJ)pterm->pnsObj->ObjData.pbDataBuff;
            pproc->bApicID = (UCHAR)pterm->pdataArgs[1].uipDataValue;
            pproc->dwPBlk = (ULONG)pterm->pdataArgs[2].uipDataValue;
            pproc->dwPBlkLen = (ULONG)pterm->pdataArgs[3].uipDataValue;
            if (ghCreate.pfnHandler != NULL)
            {
                ((PFNOO)ghCreate.pfnHandler)(OBJTYPE_PROCESSOR, pterm->pnsObj);
            }
            rc = PushScope(pctxt, pctxt->pbOp, pterm->pbOpEnd, NULL,
                           pterm->pnsObj, pctxt->powner, pctxt->pheapCurrent,
                           pterm->pdataResult);
        }
    }

    EXIT(2, ("Processor=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //Processor

/***LP  ThermalZone - Parse and execute the ThermalZone instruction
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      pterm -> TERM
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL ThermalZone(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("ThermalZone")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("ThermalZone(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if ((rc = CreateNameSpaceObject(pctxt->pheapCurrent,
                                    (PSZ)pterm->pdataArgs[0].pbDataBuff,
                                    pctxt->pnsScope, pctxt->powner,
                                    &pterm->pnsObj, 0)) == STATUS_SUCCESS)
    {
        pterm->pnsObj->ObjData.dwDataType = OBJTYPE_THERMALZONE;
        if (ghCreate.pfnHandler != NULL)
        {
            ((PFNOO)ghCreate.pfnHandler)(OBJTYPE_THERMALZONE, pterm->pnsObj);
        }
        rc = PushScope(pctxt, pctxt->pbOp, pterm->pbOpEnd, NULL, pterm->pnsObj,
                       pctxt->powner, pctxt->pheapCurrent, pterm->pdataResult);
    }

    EXIT(2, ("ThermalZone=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //ThermalZone
