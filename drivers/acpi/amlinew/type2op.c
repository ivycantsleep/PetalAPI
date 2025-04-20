/*** type2op.c - Parse type 2 opcodes
 *
 *  Copyright (c) 1996,1997 Microsoft Corporation
 *  Author:     Michael Tsang (MikeTs)
 *  Created     11/16/96
 *
 *  MODIFICATION HISTORY
 */

#include "pch.h"

_CRTIMP unsigned __int64 __cdecl _strtoui64(
    const char * _String,
    char ** _EndPtr,
    int _Radix);

#ifdef	LOCKABLE_PRAGMA
#pragma	ACPI_LOCKABLE_DATA
#pragma	ACPI_LOCKABLE_CODE
#endif

/***LP  Buffer - Parse and execute the Buffer instruction
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

NTSTATUS LOCAL Buffer(PCTXT pctxt, PTERM pterm)
{
    USHORT* wIOBuf;
    TRACENAME("BUFFER")
    NTSTATUS rc = STATUS_SUCCESS;
    ULONG dwInitSize = (ULONG)(pterm->pbOpEnd - pctxt->pbOp);

    ENTER(2, ("Buffer(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if ((rc = ValidateArgTypes(pterm->pdataArgs, "I")) == STATUS_SUCCESS)
    {
      #ifdef DEBUGGER
        if (gDebugger.dwfDebugger & (DBGF_AMLTRACE_ON | DBGF_STEP_MODES))
        {
            PrintBuffData(pctxt->pbOp, dwInitSize);
        }
      #endif

        if ((ULONG)pterm->pdataArgs[0].uipDataValue < dwInitSize)
        {
            rc = AMLI_LOGERR(AMLIERR_BUFF_TOOSMALL,
                             ("Buffer: too many initializers (buffsize=%d,InitSize=%d)",
                              pterm->pdataArgs[0].uipDataValue, dwInitSize));
        }
        else if (pterm->pdataArgs[0].uipDataValue == 0)
        {
            rc = AMLI_LOGERR(AMLIERR_INVALID_BUFFSIZE,
                             ("Buffer: invalid buffer size (size=%d)",
                             pterm->pdataArgs[0].uipDataValue));
            
            // Zero length buffer BSOD workaround
            pterm->pdataResult->pbDataBuff = NEWBDOBJ(gpheapGlobal, 1); // alloc 1 byte fake buffer
            pterm->pdataResult->dwDataType = OBJTYPE_BUFFDATA;
            pterm->pdataResult->dwDataLen = 1;
            MEMZERO(pterm->pdataResult->pbDataBuff, 1);
            pctxt->pbOp = pterm->pbOpEnd;

            rc = STATUS_SUCCESS;
        }
        else if ((pterm->pdataResult->pbDataBuff =
                  NEWBDOBJ(gpheapGlobal,
                           (ULONG)pterm->pdataArgs[0].uipDataValue)) == NULL)
        {
            rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                             ("Buffer: failed to allocate data buffer (size=%d)",
                             pterm->pdataArgs[0].uipDataValue));
        }
        else
        {
            pterm->pdataResult->dwDataType = OBJTYPE_BUFFDATA;
            pterm->pdataResult->dwDataLen = (ULONG)
                                            pterm->pdataArgs[0].uipDataValue;
            MEMZERO(pterm->pdataResult->pbDataBuff,
                    pterm->pdataResult->dwDataLen);
            MEMCPY(pterm->pdataResult->pbDataBuff, pctxt->pbOp, dwInitSize);
            pctxt->pbOp = pterm->pbOpEnd;

            /* IOTRAPS range 0xFF00-0xFFFF vs VGA (10-bit decode!) conflict workaround
             Device (IOTR)
             {
                ...
                Name (BUF0, ResourceTemplate ()
                    {
                        IO (Decode16,
                            0x0000,             // Range Minimum
                            0x0000,             // Range Maximum
                            0x01,               // Alignment
                            0xFF,               // Length           > 1
                            _Y21)
                    }) binary: 11 0D 0A _47 01 00 00 00 00 01 FF 79 00_
                ...
             }
            */

            if (dwInitSize == 10) {
                wIOBuf = (USHORT*) pterm->pdataResult->pbDataBuff;
                if (wIOBuf[0] == 0x0147 &&
                    wIOBuf[1] == 0x0000 &&
                    wIOBuf[2] == 0x0000 &&
                    wIOBuf[3] == 0xFF01 &&
                    wIOBuf[4] == 0x0079 ) {
                        pterm->pdataResult->pbDataBuff[7] = 1;  // limit range to one adress
                }
            }
        }
    }

    EXIT(2, ("Buffer=%x\n", rc));
    return rc;
}       //Buffer

/***LP  Package - Parse and execute the Package instruction
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

NTSTATUS LOCAL Package(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("PACKAGE")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("Package(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if ((rc = ValidateArgTypes(pterm->pdataArgs, "I")) == STATUS_SUCCESS)
    {
        PPACKAGEOBJ ppkgobj;

        pterm->pdataResult->dwDataLen = (ULONG)
                                        (FIELD_OFFSET(PACKAGEOBJ, adata) +
                                         sizeof(OBJDATA)*
                                         pterm->pdataArgs[0].uipDataValue);

        if ((ppkgobj = (PPACKAGEOBJ)NEWPKOBJ(gpheapGlobal,
                                             pterm->pdataResult->dwDataLen)) ==
            NULL)
        {
            rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                             ("Package: failed to allocate package object (size=%d)",
                             pterm->pdataResult->dwDataLen));
        }
        else
        {
            PPACKAGE ppkg;

            pterm->pdataResult->dwDataType = OBJTYPE_PKGDATA;
            MEMZERO(ppkgobj, pterm->pdataResult->dwDataLen);
            pterm->pdataResult->pbDataBuff = (PUCHAR)ppkgobj;
            ppkgobj->dwcElements = (UCHAR)pterm->pdataArgs[0].uipDataValue;

            if ((rc = PushFrame(pctxt, SIG_PACKAGE, sizeof(PACKAGE),
                                ParsePackage, &ppkg)) == STATUS_SUCCESS)
            {
                ppkg->ppkgobj = ppkgobj;
                ppkg->pbOpEnd = pterm->pbOpEnd;
            }
        }
    }

    EXIT(2, ("Package=%x\n", rc));
    return rc;
}       //Package

/***LP  ParsePackage - Parse and evaluate the Package term
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      ppkg -> PACKAGE
 *      rc - status code
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL ParsePackage(PCTXT pctxt, PPACKAGE ppkg, NTSTATUS rc)
{
    TRACENAME("PARSEPACKAGE")
    ULONG dwStage = (rc == STATUS_SUCCESS)?
                    (ppkg->FrameHdr.dwfFrame & FRAMEF_STAGE_MASK): 2;
    int i;

    ENTER(2, ("ParsePackage(Stage=%d,pctxt=%x,pbOp=%x,ppkg=%x,rc=%x)\n",
              dwStage, pctxt, pctxt->pbOp, ppkg, rc));

    ASSERT(ppkg->FrameHdr.dwSig == SIG_PACKAGE);
    switch (dwStage)
    {
        case 0:
            //
            // Stage 0: Do some debugger work here.
            //
            ppkg->FrameHdr.dwfFrame++;
          #ifdef DEBUGGER
            if (gDebugger.dwfDebugger &
                (DBGF_AMLTRACE_ON | DBGF_STEP_MODES))
            {
                PrintIndent(pctxt);
                PRINTF("{");
                gDebugger.iPrintLevel++;
            }
          #endif

        case 1:
        Stage1:
            //
            // Stage 1: Parse package elements
            //
            while ((pctxt->pbOp < ppkg->pbOpEnd) &&
                   (ppkg->iElement < (int)ppkg->ppkgobj->dwcElements))

            {
                i = ppkg->iElement++;
              #ifdef DEBUGGER
                if (gDebugger.dwfDebugger &
                    (DBGF_AMLTRACE_ON | DBGF_STEP_MODES))
                {
                    if (i > 0)
                    {
                        PRINTF(",");
                    }
                }
              #endif

                if ((*pctxt->pbOp == OP_BUFFER) || (*pctxt->pbOp == OP_PACKAGE))
                {
                    if (((rc = ParseOpcode(pctxt, NULL,
                                           &ppkg->ppkgobj->adata[i])) !=
                         STATUS_SUCCESS) ||
                        (&ppkg->FrameHdr !=
                         (PFRAMEHDR)pctxt->LocalHeap.pbHeapEnd))
                    {
                        break;
                    }
                }
                else
                {
                  #ifdef DEBUGGER
                    if (gDebugger.dwfDebugger &
                        (DBGF_AMLTRACE_ON | DBGF_STEP_MODES))
                    {
                        PrintIndent(pctxt);
                    }
                  #endif

                    if (((rc = ParseIntObj(&pctxt->pbOp,
                                           &ppkg->ppkgobj->adata[i], TRUE)) ==
                         AMLIERR_INVALID_OPCODE) &&
                        ((rc = ParseString(&pctxt->pbOp,
                                           &ppkg->ppkgobj->adata[i], TRUE)) ==
                         AMLIERR_INVALID_OPCODE) &&
                        ((rc = ParseObjName(&pctxt->pbOp,
                                            &ppkg->ppkgobj->adata[i], TRUE)) ==
                         AMLIERR_INVALID_OPCODE))
                    {
                        rc = AMLI_LOGERR(rc,
                                         ("ParsePackage: invalid opcode 0x%02x at 0x%08x",
                                          *pctxt->pbOp, pctxt->pbOp));
                        break;
                    }
                    else if (rc != STATUS_SUCCESS)
                    {
                        break;
                    }
                }
            }

            if ((rc == AMLISTA_PENDING) ||
                (&ppkg->FrameHdr != (PFRAMEHDR)pctxt->LocalHeap.pbHeapEnd))
            {
                break;
            }
            else if ((rc == STATUS_SUCCESS) &&
                     (pctxt->pbOp < ppkg->pbOpEnd) &&
                     (ppkg->iElement < (int)ppkg->ppkgobj->dwcElements))
            {
                goto Stage1;
            }

            ppkg->FrameHdr.dwfFrame++;

        case 2:
            //
            // Stage 2: Clean up.
            //
          #ifdef DEBUGGER
            if (gDebugger.dwfDebugger &
                (DBGF_AMLTRACE_ON | DBGF_STEP_MODES))
            {
                gDebugger.iPrintLevel--;
                PrintIndent(pctxt);
                PRINTF("}");
                gDebugger.iPrintLevel--;
            }
          #endif
            PopFrame(pctxt);
    }

    EXIT(2, ("ParsePackage=%x\n", rc));
    return rc;
}       //ParsePackage

/***LP  Acquire - Parse and execute the Acquire instruction
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

NTSTATUS LOCAL Acquire(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("ACQUIRE")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("Acquire(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if ((rc = ValidateArgTypes(pterm->pdataArgs, "OI")) == STATUS_SUCCESS)
    {
        PACQUIRE pacq;

        pterm->pnsObj = pterm->pdataArgs[0].pnsAlias;
        if (pterm->pnsObj->ObjData.dwDataType != OBJTYPE_MUTEX)
        {
            rc = AMLI_LOGERR(AMLIERR_UNEXPECTED_OBJTYPE,
                             ("Acquire: object is not mutex type (obj=%s,type=%s)",
                              GetObjectPath(pterm->pnsObj),
                              GetObjectTypeName(pterm->pnsObj->ObjData.dwDataType)));
        }
        else if ((rc = PushFrame(pctxt, SIG_ACQUIRE, sizeof(ACQUIRE),
                                 ParseAcquire, &pacq)) == STATUS_SUCCESS)
        {
            pacq->pmutex = (PMUTEXOBJ)pterm->pnsObj->ObjData.pbDataBuff;
            pacq->FrameHdr.dwfFrame = (pterm->pnsObj->ObjData.dwfData &
                                       DATAF_GLOBAL_LOCK)?
                                        ACQF_SET_RESULT | ACQF_NEED_GLOBALLOCK:
                                        ACQF_SET_RESULT;
            pacq->wTimeout = (USHORT)pterm->pdataArgs[1].uipDataValue;
            pacq->pdataResult = pterm->pdataResult;
        }
    }

    EXIT(2, ("Acquire=%x\n", rc));
    return rc;
}       //Acquire

/***LP  Concat - Parse and execute the Concatenate instruction
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

NTSTATUS LOCAL Concat(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("CONCAT")
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA pdata;

    ENTER(2, ("Concat(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if (((rc = ValidateArgTypes(pterm->pdataArgs, "DD")) == STATUS_SUCCESS) &&
        ((rc = ValidateTarget(&pterm->pdataArgs[2], OBJTYPE_DATAOBJ, &pdata))
         == STATUS_SUCCESS))
    {
        if (pterm->pdataArgs[0].dwDataType != pterm->pdataArgs[1].dwDataType)
        {
            rc = AMLI_LOGERR(AMLIERR_UNEXPECTED_OBJTYPE,
                             ("Concat: Source1 and Source2 are different types (Type1=%s,Type2=%s)",
                              GetObjectTypeName(pterm->pdataArgs[0].dwDataType),
                              GetObjectTypeName(pterm->pdataArgs[1].dwDataType)));
        }
        else
        {
            if (pterm->pdataArgs[0].dwDataType == OBJTYPE_INTDATA)
            {
                pterm->pdataResult->dwDataType = OBJTYPE_BUFFDATA;
                pterm->pdataResult->dwDataLen = sizeof(ULONG)*2;
            }
            else
            {
                pterm->pdataResult->dwDataType = pterm->pdataArgs[0].dwDataType;
                pterm->pdataResult->dwDataLen = pterm->pdataArgs[0].dwDataLen +
                                                pterm->pdataArgs[1].dwDataLen;
                //
                // If object is string, take one NULL off
                //
                if (pterm->pdataResult->dwDataType == OBJTYPE_STRDATA)
                    pterm->pdataResult->dwDataLen--;
            }

            if ((pterm->pdataResult->pbDataBuff =
                     (pterm->pdataResult->dwDataType == OBJTYPE_STRDATA)?
                     NEWSDOBJ(gpheapGlobal,
                              pterm->pdataResult->dwDataLen):
                     NEWBDOBJ(gpheapGlobal,
                              pterm->pdataResult->dwDataLen)) == NULL)
            {
                rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                                 ("Concat: failed to allocate target buffer"));
            }
            else if (pterm->pdataArgs[0].dwDataType == OBJTYPE_INTDATA)
            {
                MEMCPY(pterm->pdataResult->pbDataBuff,
                       &pterm->pdataArgs[0].uipDataValue, sizeof(ULONG));
                MEMCPY(pterm->pdataResult->pbDataBuff + sizeof(ULONG),
                       &pterm->pdataArgs[1].uipDataValue, sizeof(ULONG));
            }
            else if (pterm->pdataArgs[0].dwDataType == OBJTYPE_STRDATA)
            {
                MEMCPY(pterm->pdataResult->pbDataBuff,
                       pterm->pdataArgs[0].pbDataBuff,
                       pterm->pdataArgs[0].dwDataLen - 1);
                MEMCPY(pterm->pdataResult->pbDataBuff +
                       pterm->pdataArgs[0].dwDataLen - 1,
                       pterm->pdataArgs[1].pbDataBuff,
                       pterm->pdataArgs[1].dwDataLen);
            }
            else
            {
                MEMCPY(pterm->pdataResult->pbDataBuff,
                       pterm->pdataArgs[0].pbDataBuff,
                       pterm->pdataArgs[0].dwDataLen);
                MEMCPY(pterm->pdataResult->pbDataBuff +
                       pterm->pdataArgs[0].dwDataLen,
                       pterm->pdataArgs[1].pbDataBuff,
                       pterm->pdataArgs[1].dwDataLen);
            }

            if (rc == STATUS_SUCCESS)
            {
                rc = WriteObject(pctxt, pdata, pterm->pdataResult);
            }
        }
    }

    EXIT(2, ("Concat=%x\n", rc));
    return rc;
}       //Concat

/***LP  DerefOf - Parse and execute the DerefOf instruction
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

NTSTATUS LOCAL DerefOf(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("DEREFOF")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("DerefOf(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if ((rc = ValidateArgTypes(pterm->pdataArgs, "R")) == STATUS_SUCCESS)
    {
        POBJDATA pdata;

        pdata = &pterm->pdataArgs[0];
        if (pdata->dwDataType == OBJTYPE_OBJALIAS)
            pdata = &GetBaseObject(pdata->pnsAlias)->ObjData;
        else if (pdata->dwDataType == OBJTYPE_DATAALIAS)
            pdata = GetBaseData(pdata->pdataAlias);

        rc = ReadObject(pctxt, pdata, pterm->pdataResult);
    }

    EXIT(2, ("DerefOf=%x (type=%s,value=%x,len=%d,buff=%x)\n",
             rc, GetObjectTypeName(pterm->pdataResult->dwDataType),
             pterm->pdataResult->uipDataValue, pterm->pdataResult->dwDataLen,
             pterm->pdataResult->pbDataBuff));
    return rc;
}       //DerefOf

/***LP  ExprOp1 - Parse and execute the 1-operand expression instructions
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

NTSTATUS LOCAL ExprOp1(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("EXPROP1")
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA pdata;
    ULONG dwResult = 0;

    ENTER(2, ("ExprOp1(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if (((rc = ValidateArgTypes(pterm->pdataArgs, "I")) == STATUS_SUCCESS) &&
        ((rc = ValidateTarget(&pterm->pdataArgs[1], OBJTYPE_DATAOBJ, &pdata))
         == STATUS_SUCCESS))
    {
        int i;
        ULONG dwData1, dwData2;

        switch (pterm->pamlterm->dwOpcode)
        {
            case OP_FINDSETLBIT:
                ENTER(2, ("FindSetLeftBit(Value=%x)\n",
                          pterm->pdataArgs[0].uipDataValue));
                for (i = 31; i >= 0; --i)
                {
                    if (pterm->pdataArgs[0].uipDataValue & (1 << i))
                    {
                        dwResult = i + 1;
                        break;
                    }
                }
                EXIT(2, ("FindSetLeftBit=%x (Result=%x)\n", rc, dwResult));
                break;

            case OP_FINDSETRBIT:
                ENTER(2, ("FindSetRightBit(Value=%x)\n",
                          pterm->pdataArgs[0].uipDataValue));
                for (i = 0; i <= 31; ++i)
                {
                    if (pterm->pdataArgs[0].uipDataValue & (1 << i))
                    {
                        dwResult = i + 1;
                        break;
                    }
                }
                EXIT(2, ("FindSetRightBit=%x (Result=%x)\n", rc, dwResult));
                break;

            case OP_FROMBCD:
                ENTER(2, ("FromBCD(Value=%x)\n",
                          pterm->pdataArgs[0].uipDataValue));
                for (dwData1 = (ULONG)pterm->pdataArgs[0].uipDataValue,
                     dwData2 = 1;
                     dwData1 != 0;
                     dwData2 *= 10, dwData1 >>= 4)
                {
                    dwResult += (dwData1 & 0x0f)*dwData2;
                }
                EXIT(2, ("FromBCD=%x (Result=%x)\n", rc, dwResult));
                break;

            case OP_TOBCD:
                ENTER(2, ("ToBCD(Value=%x)\n",
                          pterm->pdataArgs[0].uipDataValue));
                for (i = 0, dwData1 = (ULONG)pterm->pdataArgs[0].uipDataValue;
                     dwData1 != 0;
                     ++i, dwData1 /= 10)
                {
                    dwResult |= (dwData1%10) << (4*i);
                }
                EXIT(2, ("ToBCD=%x (Result=%x)\n", rc, dwResult));
                break;

            case OP_NOT:
                ENTER(2, ("Not(Value=%x)\n",
                          pterm->pdataArgs[0].uipDataValue));
                dwResult = ~(ULONG)pterm->pdataArgs[0].uipDataValue;
                EXIT(2, ("Not=%x (Result=%x)\n", rc, dwResult));
        }

        pterm->pdataResult->dwDataType = OBJTYPE_INTDATA;
        pterm->pdataResult->uipDataValue = (ULONG_PTR)dwResult;
        rc = WriteObject(pctxt, pdata, pterm->pdataResult);
    }

    EXIT(2, ("ExprOp1=%x (value=%x)\n", rc, dwResult));
    return rc;
}       //ExprOp1

/***LP  ExprOp2 - Parse and execute 2-operands expression instructions
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

NTSTATUS LOCAL ExprOp2(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("EXPROP2")
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA pdata;

    ENTER(2, ("ExprOp2(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if (((rc = ValidateArgTypes(pterm->pdataArgs, "II")) == STATUS_SUCCESS) &&
        ((rc = ValidateTarget(&pterm->pdataArgs[2], OBJTYPE_DATAOBJ, &pdata))
         == STATUS_SUCCESS))
    {
        pterm->pdataResult->dwDataType = OBJTYPE_INTDATA;
        switch (pterm->pamlterm->dwOpcode)
        {
            case OP_ADD:
                ENTER(2, ("Add(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                pterm->pdataResult->uipDataValue =
                    pterm->pdataArgs[0].uipDataValue +
                    pterm->pdataArgs[1].uipDataValue;
                EXIT(2, ("Add=%x (Result=%x)\n",
                         rc, pterm->pdataResult->uipDataValue));
                break;

            case OP_AND:
                ENTER(2, ("And(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                pterm->pdataResult->uipDataValue =
                    pterm->pdataArgs[0].uipDataValue &
                    pterm->pdataArgs[1].uipDataValue;
                EXIT(2, ("And=%x (Result=%x)\n",
                         rc, pterm->pdataResult->uipDataValue));
                break;

            case OP_MULTIPLY:
                ENTER(2, ("Multiply(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                pterm->pdataResult->uipDataValue =
                    pterm->pdataArgs[0].uipDataValue *
                    pterm->pdataArgs[1].uipDataValue;
                EXIT(2, ("Multiply=%x (Result=%x)\n",
                         rc, pterm->pdataResult->uipDataValue));
                break;

            case OP_NAND:
                ENTER(2, ("NAnd(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                pterm->pdataResult->uipDataValue =
                    ~(pterm->pdataArgs[0].uipDataValue &
                      pterm->pdataArgs[1].uipDataValue);
                EXIT(2, ("NAnd=%x (Result=%x)\n",
                         rc, pterm->pdataResult->uipDataValue));
                break;

            case OP_NOR:
                ENTER(2, ("NOr(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                pterm->pdataResult->uipDataValue =
                    ~(pterm->pdataArgs[0].uipDataValue |
                      pterm->pdataArgs[1].uipDataValue);
                EXIT(2, ("NOr=%x (Result=%x)\n",
                         rc, pterm->pdataResult->uipDataValue));
                break;

            case OP_OR:
                ENTER(2, ("Or(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                pterm->pdataResult->uipDataValue =
                    pterm->pdataArgs[0].uipDataValue |
                    pterm->pdataArgs[1].uipDataValue;
                EXIT(2, ("Or=%x (Result=%x)\n",
                         rc, pterm->pdataResult->uipDataValue));
                break;

            case OP_SHIFTL:
                ENTER(2, ("ShiftLeft(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                pterm->pdataResult->uipDataValue =
                    SHIFTLEFT(pterm->pdataArgs[0].uipDataValue,
                              pterm->pdataArgs[1].uipDataValue);
                EXIT(2, ("ShiftLeft=%x (Result=%x)\n",
                         rc, pterm->pdataResult->uipDataValue));
                break;

            case OP_SHIFTR:
                ENTER(2, ("ShiftRight(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                pterm->pdataResult->uipDataValue =
                    SHIFTRIGHT(pterm->pdataArgs[0].uipDataValue,
                               pterm->pdataArgs[1].uipDataValue);
                EXIT(2, ("ShiftRight=%x (Result=%x)\n",
                         rc, pterm->pdataResult->uipDataValue));
                break;

            case OP_SUBTRACT:
                ENTER(2, ("Subtract(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                pterm->pdataResult->uipDataValue =
                    pterm->pdataArgs[0].uipDataValue -
                    pterm->pdataArgs[1].uipDataValue;
                EXIT(2, ("Subtract=%x (Result=%x)\n",
                         rc, pterm->pdataResult->uipDataValue));
                break;

            case OP_XOR:
                ENTER(2, ("XOr(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                pterm->pdataResult->uipDataValue =
                    pterm->pdataArgs[0].uipDataValue ^
                    pterm->pdataArgs[1].uipDataValue;
                EXIT(2, ("XOr=%x (Result=%x)\n",
                         rc, pterm->pdataResult->uipDataValue));
                break;
                
            case OP_MOD:
                ENTER(2, ("Mod(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                pterm->pdataResult->uipDataValue =
                    pterm->pdataArgs[0].uipDataValue %
                    pterm->pdataArgs[1].uipDataValue;
                EXIT(2, ("Mod=%x (Result=%x)\n",
                         rc, pterm->pdataResult->uipDataValue));
        }

        rc = WriteObject(pctxt, pdata, pterm->pdataResult);
    }

    EXIT(2, ("ExprOp2=%x (value=%x)\n", rc, pterm->pdataResult->uipDataValue));
    return rc;
}       //ExprOp2

/***LP  Divide - Parse and execute the Divide instruction
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

NTSTATUS LOCAL Divide(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("DIVIDE")
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA pdata1, pdata2;
    ULONG dwDividend = 0, dwRemainder = 0;

    ENTER(2, ("Divide(pctxt=%x,pbOp=%x,pterm)\n", pctxt, pctxt->pbOp, pterm));

    if (((rc = ValidateArgTypes(pterm->pdataArgs, "II")) == STATUS_SUCCESS) &&
        ((rc = ValidateTarget(&pterm->pdataArgs[2], OBJTYPE_DATAOBJ, &pdata1))
         == STATUS_SUCCESS) &&
        ((rc = ValidateTarget(&pterm->pdataArgs[3], OBJTYPE_DATAOBJ, &pdata2))
         == STATUS_SUCCESS))
    {
        ENTER(2, ("Divide(Value1=%x,Value2=%x)\n",
                  pterm->pdataArgs[0].uipDataValue,
                  pterm->pdataArgs[1].uipDataValue));
        dwDividend = (ULONG)(pterm->pdataArgs[0].uipDataValue /
                             pterm->pdataArgs[1].uipDataValue);
        dwRemainder = (ULONG)(pterm->pdataArgs[0].uipDataValue %
                              pterm->pdataArgs[1].uipDataValue);
        EXIT(2, ("Divide=%x (Dividend=%x,Remainder=%x)\n",
                 rc, dwDividend, dwRemainder));

        pterm->pdataResult->dwDataType = OBJTYPE_INTDATA;
        pterm->pdataResult->uipDataValue = (ULONG_PTR)dwDividend;

        if ((rc = PushPost(pctxt, ProcessDivide, (ULONG_PTR)pdata2, 0,
                           pterm->pdataResult)) == STATUS_SUCCESS)
        {
            rc = PutIntObjData(pctxt, pdata1, dwRemainder);
        }
    }

    EXIT(2, ("Divide=%x (Dividend=%x,Remainder%x)\n",
             rc, dwDividend, dwRemainder));
    return rc;
}       //Divide

/***LP  ProcessDivide - post processing of Divide
 *
 *  ENTRY
 *      pctxt - CTXT
 *      ppost -> POST
 *      rc - status code
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL ProcessDivide(PCTXT pctxt, PPOST ppost, NTSTATUS rc)
{
    TRACENAME("PROCESSDIVIDE")
    ULONG dwStage = (rc == STATUS_SUCCESS)?
                    (ppost->FrameHdr.dwfFrame & FRAMEF_STAGE_MASK): 1;

    ENTER(2, ("ProcessDivide(Stage=%d,pctxt=%x,pbOp=%x,ppost=%x,rc=%x)\n",
              dwStage, pctxt, pctxt->pbOp, ppost, rc));

    ASSERT(ppost->FrameHdr.dwSig == SIG_POST);

    switch (dwStage)
    {
        case 0:
            //
            // Stage 0: Do the write.
            //
            ppost->FrameHdr.dwfFrame++;
            rc = WriteObject(pctxt, (POBJDATA)ppost->uipData1,
                             ppost->pdataResult);

            if ((rc == AMLISTA_PENDING) ||
                (&ppost->FrameHdr != (PFRAMEHDR)pctxt->LocalHeap.pbHeapEnd))
            {
                break;
            }

        case 1:
            //
            // Stage 1: Clean up.
            //
            PopFrame(pctxt);
    }

    EXIT(2, ("ProcessDivide=%x (value=%x)\n",
             rc, ppost->pdataResult->uipDataValue));
    return rc;
}       //ProcessDivide

/***LP  IncDec - Parse and execute the Increment/Decrement instructions
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

NTSTATUS LOCAL IncDec(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("INCDEC")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("IncDec(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if ((rc = PushPost(pctxt, ProcessIncDec,
                       (ULONG_PTR)pterm->pamlterm->dwOpcode,
                       (ULONG_PTR)&pterm->pdataArgs[0], pterm->pdataResult)) ==
        STATUS_SUCCESS)
    {
        rc = ReadObject(pctxt, &pterm->pdataArgs[0], pterm->pdataResult);
    }

    EXIT(2, ("IncDec=%x\n", rc));
    return rc;
}       //IncDec

/***LP  ProcessIncDec - post processing of IncDec
 *
 *  ENTRY
 *      pctxt - CTXT
 *      ppost -> POST
 *      rc - status code
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL ProcessIncDec(PCTXT pctxt, PPOST ppost, NTSTATUS rc)
{
    TRACENAME("PROCESSINCDEC")
    ULONG dwStage = (rc == STATUS_SUCCESS)?
                    (ppost->FrameHdr.dwfFrame & FRAMEF_STAGE_MASK): 1;

    ENTER(2, ("ProcessIncDec(Stage=%d,pctxt=%x,pbOp=%x,ppost=%x,rc=%x)\n",
              dwStage, pctxt, pctxt->pbOp, ppost, rc));

    ASSERT(ppost->FrameHdr.dwSig == SIG_POST);

    switch (dwStage)
    {
        case 0:
            //
            // Stage 0: do the inc/dec operation.
            //
            ppost->FrameHdr.dwfFrame++;
            if (ppost->pdataResult->dwDataType != OBJTYPE_INTDATA)
            {
                FreeDataBuffs(ppost->pdataResult, 1);
                rc = AMLI_LOGERR(AMLIERR_UNEXPECTED_OBJTYPE,
                                 ("ProcessIncDec: object is not integer type (obj=%x,type=%s)",
                                  ppost->pdataResult,
                                  GetObjectTypeName(ppost->pdataResult->dwDataType)));
            }
            else if (ppost->uipData1 == OP_INCREMENT)
            {
                ENTER(2, ("Increment(Value=%x)\n",
                          ppost->pdataResult->uipDataValue));
                ppost->pdataResult->uipDataValue++;
                EXIT(2, ("Increment=%x (Value=%x)\n",
                         rc, ppost->pdataResult->uipDataValue));
            }
            else
            {
                ENTER(2, ("Decrement(Value=%x)\n",
                          ppost->pdataResult->uipDataValue));
                ppost->pdataResult->uipDataValue--;
                EXIT(2, ("Decrement=%x (Value=%x)\n",
                         rc, ppost->pdataResult->uipDataValue));
            }

            if (rc == STATUS_SUCCESS)
            {
                rc = WriteObject(pctxt, (POBJDATA)ppost->uipData2,
                                 ppost->pdataResult);

                if ((rc == AMLISTA_PENDING) ||
                    (&ppost->FrameHdr != (PFRAMEHDR)pctxt->LocalHeap.pbHeapEnd))
                {
                    break;
                }
            }

        case 1:
            //
            // Stage 1: Clean up.
            //
            PopFrame(pctxt);
    }

    EXIT(2, ("ProcessIncDec=%x (value=%x)\n",
             rc, ppost->pdataResult->uipDataValue));
    return rc;
}       //ProcessIncDec

/***LP  Index - Parse and execute the Index instruction
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

NTSTATUS LOCAL Index(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("INDEX")
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA pdata;

    ENTER(2, ("Index(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    if (((rc = ValidateArgTypes(pterm->pdataArgs, "CI")) == STATUS_SUCCESS) &&
        ((rc = ValidateTarget(&pterm->pdataArgs[2], OBJTYPE_DATA, &pdata)) ==
         STATUS_SUCCESS))
    {
        if (pterm->pdataArgs[0].dwDataType == OBJTYPE_PKGDATA)
        {
            PPACKAGEOBJ ppkg = (PPACKAGEOBJ)pterm->pdataArgs[0].pbDataBuff;

            if ((ULONG)pterm->pdataArgs[1].uipDataValue < ppkg->dwcElements)
            {
                pterm->pdataResult->dwDataType = OBJTYPE_DATAALIAS;
                pterm->pdataResult->pdataAlias =
                    &ppkg->adata[pterm->pdataArgs[1].uipDataValue];
            }
            else
            {
                rc = AMLI_LOGERR(AMLIERR_INDEX_TOO_BIG,
                                 ("Index: index out-of-bound (index=%d,max=%d)",
                                  pterm->pdataArgs[1].uipDataValue,
                                  ppkg->dwcElements));
            }
        }
        else
        {
            ASSERT(pterm->pdataArgs[0].dwDataType == OBJTYPE_BUFFDATA);
            if ((ULONG)pterm->pdataArgs[1].uipDataValue <
                pterm->pdataArgs[0].dwDataLen)
            {
                pterm->pdataResult->dwDataType = OBJTYPE_BUFFFIELD;
                pterm->pdataResult->dwDataLen = sizeof(BUFFFIELDOBJ);
                if ((pterm->pdataResult->pbDataBuff =
                     NEWBFOBJ(pctxt->pheapCurrent,
                              pterm->pdataResult->dwDataLen)) == NULL)
                {
                    rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                                     ("Index: failed to allocate buffer field object"));
                }
                else
                {
                    PBUFFFIELDOBJ pbf = (PBUFFFIELDOBJ)pterm->pdataResult->pbDataBuff;

                    pbf->FieldDesc.dwByteOffset =
                        (ULONG)pterm->pdataArgs[1].uipDataValue;
                    pbf->FieldDesc.dwStartBitPos = 0;
                    pbf->FieldDesc.dwNumBits = 8;
                    pbf->pbDataBuff = pterm->pdataArgs[0].pbDataBuff;
                    pbf->dwBuffLen = pterm->pdataArgs[0].dwDataLen;
                }
            }
            else
            {
                rc = AMLI_LOGERR(AMLIERR_INDEX_TOO_BIG,
                                 ("Index: index out-of-bound (index=%d,max=%d)",
                                  pterm->pdataArgs[1].uipDataValue,
                                  pterm->pdataArgs[0].dwDataLen));
            }
        }

        if (rc == STATUS_SUCCESS)
        {
            rc = WriteObject(pctxt, pdata, pterm->pdataResult);
        }
    }

    EXIT(2, ("Index=%x (Type=%s,Value=%x,Len=%x,Buff=%x)\n",
             rc, GetObjectTypeName(pterm->pdataResult->dwDataType),
             pterm->pdataResult->uipDataValue, pterm->pdataResult->dwDataLen,
             pterm->pdataResult->pbDataBuff));
    return rc;
}       //Index

/***LP  LNot - Parse and execute the LNot instruction
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

NTSTATUS LOCAL LNot(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("LNOT")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("LNot(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    DEREF(pctxt);
    if ((rc = ValidateArgTypes(pterm->pdataArgs, "I")) == STATUS_SUCCESS)
    {
        ENTER(2, ("LNot(Value=%x)\n", pterm->pdataArgs[0].uipDataValue));
        pterm->pdataResult->dwDataType = OBJTYPE_INTDATA;
        if (pterm->pdataArgs[0].uipDataValue == 0)
            pterm->pdataResult->uipDataValue = DATAVALUE_ONES;
        else
            pterm->pdataResult->uipDataValue = DATAVALUE_ZERO;
        EXIT(2, ("LNot=%x (Value=%x)\n", rc, pterm->pdataResult->uipDataValue));
    }

    EXIT(2, ("LNot=%x (value=%x)\n", rc, pterm->pdataResult->uipDataValue));
    return rc;
}       //LNot

/***LP  LogOp2 - Parse and execute 2-operand logical expression instructions
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

NTSTATUS LOCAL LogOp2(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("LOGOP2")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("LogOp2(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    DEREF(pctxt);
    if ((rc = ValidateArgTypes(pterm->pdataArgs, "II")) == STATUS_SUCCESS)
    {
        BOOLEAN fResult = FALSE;

        switch (pterm->pamlterm->dwOpcode)
        {
            case OP_LAND:
                ENTER(2, ("LAnd(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                fResult = (BOOLEAN)(pterm->pdataArgs[0].uipDataValue &&
                                    pterm->pdataArgs[1].uipDataValue);
                EXIT(2, ("LAnd=%x (Result=%x)\n", rc, fResult));
                break;

            case OP_LOR:
                ENTER(2, ("LOr(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                fResult = (BOOLEAN)(pterm->pdataArgs[0].uipDataValue ||
                                    pterm->pdataArgs[1].uipDataValue);
                EXIT(2, ("LOr=%x (Result=%x)\n", rc, fResult));
                break;

            case OP_LG:
                ENTER(2, ("LGreater(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                fResult = (BOOLEAN)(pterm->pdataArgs[0].uipDataValue >
                                    pterm->pdataArgs[1].uipDataValue);
                EXIT(2, ("LGreater=%x (Result=%x)\n", rc, fResult));
                break;

            case OP_LL:
                ENTER(2, ("LLess(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                fResult = (BOOLEAN)(pterm->pdataArgs[0].uipDataValue <
                                    pterm->pdataArgs[1].uipDataValue);
                EXIT(2, ("LLess=%x (Result=%x)\n", rc, fResult));
                break;

            case OP_LEQ:
                ENTER(2, ("LEqual(Value1=%x,Value2=%x)\n",
                          pterm->pdataArgs[0].uipDataValue,
                          pterm->pdataArgs[1].uipDataValue));
                fResult = (BOOLEAN)(pterm->pdataArgs[0].uipDataValue ==
                                    pterm->pdataArgs[1].uipDataValue);
                EXIT(2, ("LEqual=%x (Result=%x)\n", rc, fResult));
        }
        pterm->pdataResult->dwDataType = OBJTYPE_INTDATA;
        pterm->pdataResult->uipDataValue = fResult?
                                              DATAVALUE_ONES: DATAVALUE_ZERO;
    }

    EXIT(2, ("LogOp2=%x (value=%x)\n", rc, pterm->pdataResult->uipDataValue));
    return rc;
}       //LogOp2

/***LP  ObjTypeSizeOf - Parse and execute the ObjectType/SizeOf instructions
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

NTSTATUS LOCAL ObjTypeSizeOf(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("OBJTYPESIZEOF")
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA pdata;

    ENTER(2, ("ObjTypeSizeOf(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    DEREF(pctxt);
    pdata = GetBaseData(&pterm->pdataArgs[0]);
    pterm->pdataResult->dwDataType = OBJTYPE_INTDATA;
    if (pterm->pamlterm->dwOpcode == OP_OBJTYPE)
    {
        ENTER(2, ("ObjectType(pdataObj=%x)\n", pdata));
        pterm->pdataResult->uipDataValue = (ULONG_PTR)pdata->dwDataType;
        EXIT(2, ("ObjectType=%x (Type=%s)\n",
                 rc, GetObjectTypeName(pdata->dwDataType)));
    }
    else
    {
        ENTER(2, ("SizeOf(pdataObj=%x)\n", pdata));
        switch (pdata->dwDataType)
        {
            case OBJTYPE_BUFFDATA:
                pterm->pdataResult->uipDataValue = (ULONG_PTR)pdata->dwDataLen;
                break;

            case OBJTYPE_STRDATA:
                pterm->pdataResult->uipDataValue = (ULONG_PTR)
                                                    (pdata->dwDataLen - 1);
                break;

            case OBJTYPE_PKGDATA:
                pterm->pdataResult->uipDataValue = (ULONG_PTR)
                    ((PPACKAGEOBJ)pdata->pbDataBuff)->dwcElements;
                break;

            default:
                rc = AMLI_LOGERR(AMLIERR_UNEXPECTED_ARGTYPE,
                                 ("SizeOf: expected argument type string/buffer/package (type=%s)",
                                  GetObjectTypeName(pdata->dwDataType)));
        }
        EXIT(2, ("Sizeof=%x (Size=%d)\n", rc, pterm->pdataResult->uipDataValue));
    }

    EXIT(2, ("ObjTypeSizeOf=%x (value=%x)\n",
             rc, pterm->pdataResult->uipDataValue));
    return rc;
}       //ObjTypeSizeOf

/***LP  RefOf - Parse and execute the RefOf instructions
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

NTSTATUS LOCAL RefOf(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("REFOF")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("RefOf(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    DEREF(pctxt);
    MoveObjData(pterm->pdataResult, &pterm->pdataArgs[0]);

    EXIT(2, ("RefOf=%x (ObjAlias=%x)\n", rc, pterm->pdataResult->uipDataValue));
    return rc;
}       //RefOf

/***LP  CondRefOf - Parse and execute the CondRefOf instructions
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

NTSTATUS LOCAL CondRefOf(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("CONDREFOF")
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA pdata;

    ENTER(2, ("CondRefOf(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if ((rc = ValidateTarget(&pterm->pdataArgs[1], OBJTYPE_DATAOBJ, &pdata)) ==
        STATUS_SUCCESS)
    {
        pterm->pdataResult->dwDataType = OBJTYPE_INTDATA;
        if ((pterm->pdataArgs[0].dwDataType == OBJTYPE_OBJALIAS) ||
            (pterm->pdataArgs[0].dwDataType == OBJTYPE_DATAALIAS))
        {
            pterm->pdataResult->uipDataValue = DATAVALUE_ONES;
            rc = WriteObject(pctxt, pdata, &pterm->pdataArgs[0]);
        }
        else
        {
            pterm->pdataResult->uipDataValue = DATAVALUE_ZERO;
        }
    }

    EXIT(2, ("CondRefOf=%x (ObjAlias=%x)\n",
             rc, pterm->pdataResult->uipDataValue));
    return rc;
}       //CondRefOf

/***LP  Store - Parse and execute the Store instruction
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

NTSTATUS LOCAL Store(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("STORE")
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA pdata;

    ENTER(2, ("Store(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    if ((rc = ValidateTarget(&pterm->pdataArgs[1], OBJTYPE_DATAOBJ, &pdata)) ==
        STATUS_SUCCESS)
    {
        MoveObjData(pterm->pdataResult, &pterm->pdataArgs[0]);
        rc = WriteObject(pctxt, pdata, pterm->pdataResult);
    }

    EXIT(2, ("Store=%x (type=%s,value=%x,buff=%x,len=%x)\n",
             rc, GetObjectTypeName(pterm->pdataArgs[0].dwDataType),
             pterm->pdataArgs[0].uipDataValue, pterm->pdataArgs[0].pbDataBuff,
             pterm->pdataArgs[0].dwDataLen));
    return rc;
}       //Store

/***LP  Wait - Parse and execute the Wait instruction
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

NTSTATUS LOCAL Wait(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("WAIT")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("Wait(pctxt=%x,pbOp=%x,pter=%x)\n", pctxt, pctxt->pbOp, pterm));

    if ((rc = ValidateArgTypes(pterm->pdataArgs, "OI")) == STATUS_SUCCESS)
    {
        pterm->pnsObj = pterm->pdataArgs[0].pnsAlias;
        if (pterm->pnsObj->ObjData.dwDataType != OBJTYPE_EVENT)
        {
            rc = AMLI_LOGERR(AMLIERR_UNEXPECTED_OBJTYPE,
                             ("Wait: object is not event type (obj=%s,type=%s)",
                              GetObjectPath(pterm->pnsObj),
                              GetObjectTypeName(pterm->pnsObj->ObjData.dwDataType)));
        }
        else if ((rc = PushPost(pctxt, ProcessWait, 0, 0, pterm->pdataResult))
                 == STATUS_SUCCESS)
        {
            rc = WaitASLEvent(pctxt,
                              (PEVENTOBJ)pterm->pnsObj->ObjData.pbDataBuff,
                              (USHORT)pterm->pdataArgs[1].uipDataValue);
        }
    }

    EXIT(2, ("Wait=%x (value=%x)\n", rc, pterm->pdataResult->uipDataValue));
    return rc;
}       //Wait

/***LP  ProcessWait - post process of Wait
 *
 *  ENTRY
 *      pctxt -> CTXT
 *      ppost -> POST
 *      rc - status code
 *
 *  EXIT-SUCCESS
 *      returns STATUS_SUCCESS
 *  EXIT-FAILURE
 *      returns AMLIERR_ code
 */

NTSTATUS LOCAL ProcessWait(PCTXT pctxt, PPOST ppost, NTSTATUS rc)
{
    TRACENAME("PROCESSWAIT")

    ENTER(2, ("ProcessWait(pctxt=%x,pbOp=%x,ppost=%x,rc=%x)\n",
              pctxt, pctxt->pbOp, ppost, rc));

    ASSERT(ppost->FrameHdr.dwSig == SIG_POST);
    ppost->pdataResult->dwDataType = OBJTYPE_INTDATA;
    if (rc == AMLISTA_TIMEOUT)
    {
        ppost->pdataResult->uipDataValue = DATAVALUE_ONES;
        rc = STATUS_SUCCESS;
    }
    else
    {
        ppost->pdataResult->uipDataValue = DATAVALUE_ZERO;
    }
    PopFrame(pctxt);

    EXIT(2, ("ProcessWait=%x (value=%x)\n",
             rc, ppost->pdataResult->uipDataValue));
    return rc;
}       //ProcessWait

/***LP  Match - Parse and execute the Match instruction
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

NTSTATUS LOCAL Match(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("MATCH")
    NTSTATUS rc = STATUS_SUCCESS;

    ENTER(2, ("Match(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    DEREF(pctxt);
    if ((rc = ValidateArgTypes(pterm->pdataArgs, "PIIIII")) == STATUS_SUCCESS)
    {
        PPACKAGEOBJ ppkgobj = (PPACKAGEOBJ)pterm->pdataArgs[0].pbDataBuff;
        OBJDATA data;
        int i;

        MEMZERO(&data, sizeof(data));
        for (i = (int)pterm->pdataArgs[5].uipDataValue;
             rc == STATUS_SUCCESS;
             ++i)
        {
            FreeDataBuffs(&data, 1);
            //
            // This will never block because package element can only be simple
            // data.
            //
            if (((rc = EvalPackageElement(ppkgobj, i, &data)) ==
                 STATUS_SUCCESS) &&
                (data.dwDataType == OBJTYPE_INTDATA) &&
                MatchData((ULONG)data.uipDataValue,
                          (ULONG)pterm->pdataArgs[1].uipDataValue,
                          (ULONG)pterm->pdataArgs[2].uipDataValue) &&
                MatchData((ULONG)data.uipDataValue,
                          (ULONG)pterm->pdataArgs[3].uipDataValue,
                          (ULONG)pterm->pdataArgs[4].uipDataValue))
            {
                break;
            }
        }

        if (rc == STATUS_SUCCESS)
        {
            pterm->pdataResult->dwDataType = OBJTYPE_INTDATA;
            pterm->pdataResult->uipDataValue = (ULONG_PTR)i;
        }
        else if (rc == AMLIERR_INDEX_TOO_BIG)
        {
            pterm->pdataResult->dwDataType = OBJTYPE_INTDATA;
            pterm->pdataResult->uipDataValue = DATAVALUE_ONES;
            rc = STATUS_SUCCESS;
        }

        FreeDataBuffs(&data, 1);
    }

    EXIT(2, ("Match=%x\n", rc));
    return rc;
}       //Match

/***LP  MatchData - Match data of a package element
 *
 *  ENTRY
 *      dwPkgData - package element data
 *      dwOp - operation
 *      dwData - data
 *
 *  EXIT-SUCCESS
 *      returns TRUE
 *  EXIT-FAILURE
 *      returns FALSE
 */

BOOLEAN LOCAL MatchData(ULONG dwPkgData, ULONG dwOp, ULONG dwData)
{
    TRACENAME("MATCHDATA")
    BOOLEAN rc = FALSE;

    ENTER(2, ("MatchData(PkgData=%x,Op=%x,Data=%x)\n",
              dwPkgData, dwOp, dwData));

    switch (dwOp)
    {
        case MTR:
            rc = TRUE;
            break;

        case MEQ:
            rc = (BOOLEAN)(dwPkgData == dwData);
            break;

        case MLE:
            rc = (BOOLEAN)(dwPkgData <= dwData);
            break;

        case MLT:
            rc = (BOOLEAN)(dwPkgData < dwData);
            break;

        case MGE:
            rc = (BOOLEAN)(dwPkgData >= dwData);
            break;

        case MGT:
            rc = (BOOLEAN)(dwPkgData > dwData);
            break;
    }

    EXIT(2, ("MatchData=%x\n", rc));
    return rc;
}       //MatchData

NTSTATUS LOCAL OSInterface(
                                PCTXT pctxt, 
                                PTERM pterm
                              )
/*++

Routine Description:

    Check if the OS is supported.

Arguments:

    PCTXT pctxt - Pointer to the context structure.
    PTERM pterm - Pointer to the Term structure.

Return Value:

    STATUS_SUCCESS on match.

--*/
{
    TRACENAME("OSInterface")
    NTSTATUS rc;
    // Add future OS strings here.
    char Win2000[] = "Windows 2000";
    char Win2001[] = "Windows 2001";
    char Win2001SP1[] = "Windows 2001 SP1";
    char Win2001SP2[] = "Windows 2001 SP2";
    char* SupportedOSList[] = {
                                    Win2000, 
                                    Win2001,
                                    Win2001SP1,
                                    Win2001SP2
                                };
    ULONG ListSize = sizeof(SupportedOSList) / sizeof(char*);
    ULONG i = 0;
    
    ENTER(2, ("OSInterface(pctxt=%x,pbOp=%x,pterm=%x, Querying for %s)\n",
              pctxt, pctxt->pbOp, pterm, pterm->pdataArgs[0].pbDataBuff));

    if ((rc = ValidateArgTypes(pterm->pdataArgs, "A")) == STATUS_SUCCESS)
    {
        if ((rc = ValidateArgTypes((pterm->pdataArgs)->pdataAlias, "Z")) == STATUS_SUCCESS)
        {
            pterm->pdataResult->dwDataType = OBJTYPE_INTDATA;
            pterm->pdataResult->uipDataValue = DATAVALUE_ZERO;
                    
            for(i=0; i<ListSize; i++)
            {
                if(STRCMPI(SupportedOSList[i], (pterm->pdataArgs)->pdataAlias->pbDataBuff) == 0)
                { 
                    pterm->pdataResult->uipDataValue = DATAVALUE_ONES;
                    rc = STATUS_SUCCESS;

                    //
                    // Save highest OS Version Queried
                    // 0 == Windows 2000
                    // 1 == Windows 2001
                    // 2 == Windows 2001 SP1
                    // 3 == Windows 2001 SP2
                    //
                    if(gdwHighestOSVerQueried < i)
                    {
                        gdwHighestOSVerQueried = i;
                    }
                    
                    break;
                }
            }
        }
    }
    
    EXIT(2, ("OSInterface=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}       //OSInterface



///////////////////////////////////////////////
// ACPI 2.0


NTSTATUS LOCAL ConvertToInteger(POBJDATA In, POBJDATA Out) {
    ULONG   dwDataLen;
    OBJDATA data;

    MEMZERO(&data, sizeof(data));
    data.dwDataType = OBJTYPE_INTDATA;
    switch (In->dwDataType) {
    case OBJTYPE_INTDATA:
        data.dwDataValue = In->dwDataValue;

        FreeDataBuffs(Out, 1);
        MEMCPY(Out, &data, sizeof(data));
        return STATUS_SUCCESS;
        break;
    case OBJTYPE_STRDATA:
        data.dwDataValue = StrToUL((PSZ)In->pbDataBuff, NULL, 0);

        FreeDataBuffs(Out, 1);
        MEMCPY(Out, &data, sizeof(data));
        return STATUS_SUCCESS;
        break;
    case OBJTYPE_BUFFDATA:
        dwDataLen = In->dwDataLen;
        if (dwDataLen > 4)    // 8 - int64
            dwDataLen = 4;
        MEMCPY(&data.dwDataValue, In->pbDataBuff, dwDataLen);

        FreeDataBuffs(Out, 1);
        MEMCPY(Out, &data, sizeof(data));
        return STATUS_SUCCESS;
        break;
    default:
        return AMLIERR_UNEXPECTED_OBJTYPE;
        break;
    }
}


NTSTATUS LOCAL ToInteger(PCTXT pctxt, PTERM pterm)
{
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA pdata;
    TRACENAME("TOINTEGER")
    ENTER(2, ("ToInteger(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    if (((rc = ValidateArgTypes(pterm->pdataArgs, "D"))                       == STATUS_SUCCESS) &&
        ((rc = ValidateTarget(&pterm->pdataArgs[1], OBJTYPE_DATAOBJ, &pdata)) == STATUS_SUCCESS)) {
            if ((rc = ConvertToInteger(pterm->pdataArgs, pterm->pdataResult)) == STATUS_SUCCESS)
                rc = WriteObject(pctxt, pdata, pterm->pdataResult);
    }

    EXIT(2, ("ToInteger=%x (Result=%x)\n", rc, pterm->pdataResult));
    return rc;
}


char HTOALookupTable[]="0123456789ABCDEF";


NTSTATUS LOCAL ToHexString(PCTXT pctxt, PTERM pterm)
{
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA pdata;
    int      StrLen;
    POBJDATA In  = pterm->pdataArgs;
    POBJDATA Out = pterm->pdataResult;
    ULONG    int32;
    ULONG    SrcIdx;
    int      i;
    UCHAR    pair;
    TRACENAME("TOHEXSTRING")
    ENTER(2, ("ToHexString(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    if (((rc = ValidateArgTypes(pterm->pdataArgs, "D"))                       == STATUS_SUCCESS) &&
        ((rc = ValidateTarget(&pterm->pdataArgs[1], OBJTYPE_DATAOBJ, &pdata)) == STATUS_SUCCESS)) {
            StrLen = 2;
            Out->dwDataType = OBJTYPE_STRDATA;
            switch (In->dwDataType) {
            case OBJTYPE_INTDATA:
                int32 = In->dwDataValue;
                do {
                    int32 >>= 4;
                    ++StrLen;
                } while (int32);

                Out->dwDataLen = StrLen + 1;
                Out->pbDataBuff = (PUCHAR) NEWSDOBJ(gpheapGlobal, Out->dwDataLen);

                if (Out->pbDataBuff == NULL) {
                    rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                                 ("ToHexString: failed to allocate target buffer"));
                } else {
                    Out->pbDataBuff[0] = '0';
                    Out->pbDataBuff[1] = 'x';
                    int32 = In->dwDataValue;
                    for (i = StrLen - 1; i >= 2; --i) {
                        Out->pbDataBuff[i] = HTOALookupTable[int32 & 0xF];
                        int32 >>= 4;
                    }

                    Out->pbDataBuff[Out->dwDataLen - 1] = '\0'; // ending zero
                    rc = WriteObject(pctxt, pdata, pterm->pdataResult);
                }
                break;
            case OBJTYPE_STRDATA:
                Out->dwDataLen = In->dwDataLen;
                Out->pbDataBuff = (PUCHAR) NEWSDOBJ(gpheapGlobal, Out->dwDataLen);
                    
                if (Out->pbDataBuff == NULL) {
                    rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                                 ("ToHexString: failed to allocate target buffer"));
                } else {
                    MEMCPY(Out->pbDataBuff, In->pbDataBuff, Out->dwDataLen);
                    rc = WriteObject(pctxt, pdata, pterm->pdataResult);
                }
                break;
            case OBJTYPE_BUFFDATA:
                Out->dwDataLen = 5 * In->dwDataLen;
                Out->pbDataBuff = (PUCHAR) NEWSDOBJ(gpheapGlobal, Out->dwDataLen);

                if (Out->pbDataBuff == NULL) {
                    rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                                 ("ToHexString: failed to allocate target buffer"));
                } else {
                    i = 0;
                    if (In->dwDataLen) {
                        for (SrcIdx = 0; SrcIdx < In->dwDataLen; SrcIdx++) {
                            Out->pbDataBuff[i]   = '0';
                            Out->pbDataBuff[i+1] = 'x';
                            pair = In->pbDataBuff[SrcIdx];
                            Out->pbDataBuff[i+2] = HTOALookupTable[pair >> 4];
                            Out->pbDataBuff[i+3] = HTOALookupTable[pair & 0xF];
                            Out->pbDataBuff[i+4] = ',';
                            i += 5;
                        }
                    }

                    Out->pbDataBuff[Out->dwDataLen - 1] = '\0'; // ending zero
                    rc = WriteObject(pctxt, pdata, pterm->pdataResult);
                }
                break;
            default:
                rc = AMLI_LOGERR(AMLIERR_FATAL,
                            ("ToHexString: invalid arg0 type"));
                break;
            }
    }

    EXIT(2, ("ToHexString=%x (Result=%x)\n", rc, pterm->pdataResult));
    return rc;
}


NTSTATUS LOCAL ConvertToBuffer(POBJDATA In, POBJDATA Out) {
    OBJDATA data;
    int     Len;
    int     i;
    ULONG   int32;
    NTSTATUS rc = STATUS_SUCCESS;

    MEMZERO(&data, sizeof(data));
    data.dwDataType = OBJTYPE_BUFFDATA;
    switch (In->dwDataType) {
    case OBJTYPE_INTDATA:
        int32 = In->dwDataValue;
        Len = 4;

        data.dwDataLen = Len;
        data.pbDataBuff = (PUCHAR) NEWSDOBJ(gpheapGlobal, Len);
        if (data.pbDataBuff == NULL) {
            rc = AMLIERR_OUT_OF_MEM;
        } else {
            for (i = 0; i < Len; i++) {
                data.pbDataBuff[i] = (UCHAR) int32;
                int32 >>= 8;
              }

            FreeDataBuffs(Out, 1);
            MEMCPY(Out, &data, sizeof(data));
        }
        break;
    case OBJTYPE_STRDATA:
    case OBJTYPE_BUFFDATA:
        Len = In->dwDataLen;
        data.dwDataLen = Len;

        data.pbDataBuff = (PUCHAR) NEWSDOBJ(gpheapGlobal, Len);
        if (data.pbDataBuff == NULL) {
            rc = AMLIERR_OUT_OF_MEM;
        } else {
            MEMCPY(data.pbDataBuff, In->pbDataBuff, Len);

            FreeDataBuffs(Out, 1);
            MEMCPY(Out, &data, sizeof(data));
        }
        break;
    default:
        rc = AMLIERR_UNEXPECTED_OBJTYPE;
        break;
    }

    return rc;
}


NTSTATUS LOCAL ToBuffer(PCTXT pctxt, PTERM pterm)
{
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA pdata;
    TRACENAME("TOBUFFER")
    ENTER(2, ("ToBuffer(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    if (((rc = ValidateArgTypes(pterm->pdataArgs, "D"))                       == STATUS_SUCCESS) &&
        ((rc = ValidateTarget(&pterm->pdataArgs[1], OBJTYPE_DATAOBJ, &pdata)) == STATUS_SUCCESS)) {
            if ((rc = ConvertToBuffer(pterm->pdataArgs, pterm->pdataResult))  == STATUS_SUCCESS)
                rc = WriteObject(pctxt, pdata, pterm->pdataResult);
    }

    EXIT(2, ("ToBuffer=%x (Result=%x)\n", rc, pterm->pdataResult));
    return rc;
}


NTSTATUS LOCAL ToDecimalString(PCTXT pctxt, PTERM pterm)
{
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA pdata;
    POBJDATA In  = pterm->pdataArgs;
    POBJDATA Out = pterm->pdataResult;
    ULONG    int32;
    ULONG    StrLen;
    int      SrcBufLen;
    ULONG    SrcIdx;
    int      i;
    int      j;
    UCHAR    number;
    TRACENAME("TODECSTRING")
    ENTER(2, ("ToDecimalString(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    if (((rc = ValidateArgTypes(pterm->pdataArgs, "D"))                       == STATUS_SUCCESS) &&
        ((rc = ValidateTarget(&pterm->pdataArgs[1], OBJTYPE_DATAOBJ, &pdata)) == STATUS_SUCCESS)) {
        Out->dwDataType = OBJTYPE_STRDATA;
        switch (In->dwDataType) {
        case OBJTYPE_INTDATA:
            int32 = In->dwDataValue;
            StrLen = 0;
            do {
                int32 /= 10;
                ++StrLen; 
            } while (int32);

            Out->dwDataLen = StrLen + 1;
            Out->pbDataBuff = (PUCHAR) NEWSDOBJ(gpheapGlobal, Out->dwDataLen);

            if (Out->pbDataBuff == NULL) {
                    rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                                 ("ToDecimalString: failed to allocate target buffer"));
            } else {
                int32 = In->dwDataValue;
                if (StrLen >= 1) {
                    for (i = StrLen - 1; i >= 0; --i) {
                        Out->pbDataBuff[i] = HTOALookupTable[int32 % 10];
                        int32 /= 10;
                    }
                }

                Out->pbDataBuff[Out->dwDataLen - 1] = '\0'; // ending zero
                rc = WriteObject(pctxt, pdata, pterm->pdataResult);
            }
            break;
        case OBJTYPE_STRDATA:
            Out->dwDataLen = In->dwDataLen;
            Out->pbDataBuff = (PUCHAR) NEWSDOBJ(gpheapGlobal, Out->dwDataLen);

            if (Out->pbDataBuff == NULL) {
                    rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                                 ("ToDecimalString: failed to allocate target buffer"));
            } else {
                MEMCPY(Out->pbDataBuff, In->pbDataBuff, Out->dwDataLen);
                rc = WriteObject(pctxt, pdata, pterm->pdataResult);
            }
            break;
        case OBJTYPE_BUFFDATA:
            SrcBufLen = In->dwDataLen;
            StrLen = SrcBufLen - 1;
            if (SrcBufLen) {
                for (i = 0; i < SrcBufLen; i++) {
                    number = In->pbDataBuff[i];
                    if (number >= 10) {
                        if (number >= 100)
                            StrLen += 3;
                        else
                            StrLen += 2;
                    } else {
                        StrLen++;
                    }
                }
            }

            Out->dwDataLen = StrLen + 1;
            Out->pbDataBuff = (PUCHAR) NEWSDOBJ(gpheapGlobal, Out->dwDataLen);

            if (Out->pbDataBuff == NULL) {
                    rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                                 ("ToDecimalString: failed to allocate target buffer"));
            } else {
                j = 0;  // result buffer index
                for ( SrcIdx = 0; SrcIdx < In->dwDataLen; SrcIdx++ ) {
                    number = In->pbDataBuff[SrcIdx];
                    if (number >= 10) {
                        if (number >= 100)
                            Out->pbDataBuff[j++] = HTOALookupTable[(number / 100) % 10];  // 2xx

                        Out->pbDataBuff[j++] = HTOALookupTable[(number / 10) % 10];       // x2x
                        Out->pbDataBuff[j++] = HTOALookupTable[number % 10];              // xx2  
                    } else {
                        Out->pbDataBuff[j++] = HTOALookupTable[number];
                    }
                    Out->pbDataBuff[j++] = ',';
                }
                
                Out->pbDataBuff[Out->dwDataLen - 1] = '\0'; // ending zero
                rc = WriteObject(pctxt, pdata, pterm->pdataResult);
            }
            break;
        default:
            rc = AMLI_LOGERR(AMLIERR_FATAL,
                            ("ToDecimalString: invalid arg0 type"));
            break;
        }
    }

    EXIT(2, ("ToDecimalString=%x (Result=%x)\n", rc, pterm->pdataResult));
    return rc;
}


NTSTATUS LOCAL CreateQWordField(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("CREATEQWORDFIELD")
    NTSTATUS rc = STATUS_SUCCESS;
    PBUFFFIELDOBJ pbf;
    ENTER(2, ("CreateQWordField(pctxt=%x,pbOp=%x,pterm=%x)\n",
              pctxt, pctxt->pbOp, pterm));

    if ((rc = CreateXField(pctxt, pterm, &pterm->pdataArgs[2], &pbf)) ==
        STATUS_SUCCESS)
    {
        pbf->FieldDesc.dwByteOffset = (ULONG)pterm->pdataArgs[1].uipDataValue;
        pbf->FieldDesc.dwStartBitPos = 0;
        pbf->FieldDesc.dwNumBits = 8*sizeof(ULONG);     // 8*sizeof(ULONG64) ACPI 2.0
        pbf->FieldDesc.dwFieldFlags = ACCTYPE_DWORD;    // ACCTYPE_QWORD ACPI 2.0
    }

    EXIT(2, ("CreateQWordField=%x (pnsObj=%x)\n", rc, pterm->pnsObj));
    return rc;
}


UCHAR LOCAL ComputeDataChkSum(UCHAR *Buffer, int Len) {
    UCHAR checksum = 0;

    for ( ; Len; --Len ) {
        checksum += *Buffer;
        Buffer++;
    }

    return -(checksum);
}


NTSTATUS LOCAL ConcatenateResTemplate(PCTXT pctxt, PTERM pterm)
{
    NTSTATUS  rc = STATUS_SUCCESS;
    POBJDATA  pdata;
    POBJDATA  In  = pterm->pdataArgs;
    POBJDATA  Out = pterm->pdataResult;
    ULONG     i,j;
    ULONG     NewLength;
    TRACENAME("CONCATENATERESTEMPLATE")
    ENTER(2, ("ConcatenateResTemplate(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    if (((rc = ValidateArgTypes(pterm->pdataArgs, "BB"))                      == STATUS_SUCCESS) &&
        ((rc = ValidateTarget(&pterm->pdataArgs[2], OBJTYPE_DATAOBJ, &pdata)) == STATUS_SUCCESS)) {
        if (In[0].dwDataLen <= 1 || In[1].dwDataLen <= 1 ) {
            rc = AMLI_LOGERR(AMLIERR_FATAL,
                    ("ConcatenateResTemplate: arg0 or arg1 has length <= 1"));
        } else {
            Out->dwDataType = OBJTYPE_BUFFDATA;
            NewLength = In[0].dwDataLen + In[1].dwDataLen - 2;
            Out->dwDataLen = NewLength;

            Out->pbDataBuff = (PUCHAR) NEWSDOBJ(gpheapGlobal, NewLength);
            if (Out->pbDataBuff == NULL) {
                    rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                            ("ConcatenateResTemplate: failed to allocate target buffer"));
            } else {
                j = 0;

                i = 0;
                if (In[0].dwDataLen != 2) {
                    do {
                        Out->pbDataBuff[j++] = In[0].pbDataBuff[i++];
                    } while (i < In[0].dwDataLen - 2);
                }

                i = 0;
                if (In[1].dwDataLen != 2) {
                    do {
                        Out->pbDataBuff[j++] = In[1].pbDataBuff[i++];
                    } while (i < In[1].dwDataLen - 2);
                }

                Out->pbDataBuff[j++] = 0x79;     //EndTag
                Out->pbDataBuff[j]   = ComputeDataChkSum(Out->pbDataBuff, NewLength - 1);
                rc = WriteObject(pctxt, pdata, pterm->pdataResult);
            }
            
        }
    }

    EXIT(2, ("ConcatenateResTemplate=%x (Result=%x)\n", rc, pterm->pdataResult));
    return rc;
}


size_t LOCAL strnlen(const char *Str, size_t MaxCount)
{
  size_t result;

  for (result = 0; result < MaxCount; ++Str) {
    if (!*Str)
      break;

    result++;
  }
  return result;
}


#define STRSAFE_MAX_CCH  2147483647

// ntstrsafe.c
NTSTATUS RtlStringVPrintfWorkerA(char* pszDest, size_t cchDest, const char* pszFormat, va_list argList)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (cchDest == 0)
    {
        // can not null terminate a zero-byte dest buffer
        status = STATUS_INVALID_PARAMETER;
    }
    else
    {
        int iRet;
        size_t cchMax;

        // leave the last space for the null terminator
        cchMax = cchDest - 1;

        iRet = _vsnprintf(pszDest, cchMax, pszFormat, argList);

        if ((iRet < 0) || (((size_t)iRet) > cchMax))
        {
            // need to null terminate the string
            pszDest += cchMax;
            *pszDest = '\0';

            // we have truncated pszDest
            status = STATUS_BUFFER_OVERFLOW;
        }
        else if (((size_t)iRet) == cchMax)
        {
            // need to null terminate the string
            pszDest += cchMax;
            *pszDest = '\0';
        }
    }

    return status;
}


// ntstrsafe.c
NTSTATUS RtlStringCchPrintfA(char* pszDest, size_t cchDest, const char* pszFormat, ...)
{
    NTSTATUS status;

    if (cchDest > STRSAFE_MAX_CCH)
    {
        status = STATUS_INVALID_PARAMETER;
    }
    else
    {
        va_list argList;

        va_start(argList, pszFormat);

        status = RtlStringVPrintfWorkerA(pszDest, cchDest, pszFormat, argList);

        va_end(argList);
    }

    return status;
}


NTSTATUS LOCAL ConvertToString(POBJDATA In, ULONG MaxLen, POBJDATA Out)
{
    NTSTATUS    rc = STATUS_SUCCESS;
    ULONG       StrLen = MaxLen;
    char        TmpBuf[9]; // 17 ACPI 2.0
    OBJDATA     data;
    ULONG       BufLen;
    ULONG       InStrLen;

    MEMZERO(&TmpBuf, sizeof(TmpBuf));
    MEMZERO(&data,   sizeof(data));
    data.dwDataType = OBJTYPE_STRDATA;

    switch (In->dwDataType) {
    case OBJTYPE_INTDATA:
        BufLen = 9;
        RtlStringCchPrintfA(TmpBuf, 9, "%x", In->dwDataValue);
        if (!MaxLen || MaxLen >= BufLen)
            StrLen = strnlen(TmpBuf, BufLen);
        data.dwDataLen = StrLen + 1;

        data.pbDataBuff = (PUCHAR) NEWSDOBJ(gpheapGlobal, data.dwDataLen);
        if (data.pbDataBuff == NULL) {
            rc = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            MEMCPY(data.pbDataBuff, TmpBuf, data.dwDataLen);
            data.pbDataBuff[data.dwDataLen - 1] = '\0'; // ending zero
            FreeDataBuffs(Out, 1);
            MEMCPY(Out, &data, sizeof(data));
        }
        break;
    case OBJTYPE_STRDATA:
        if (MaxLen > In->dwDataLen - 1)
            rc = STATUS_ACPI_FATAL;
        else {
            if (!MaxLen)
                StrLen = In->dwDataLen - 1;
            data.dwDataLen = StrLen + 1;

            data.pbDataBuff = (PUCHAR) NEWSDOBJ(gpheapGlobal, data.dwDataLen);
            if (data.pbDataBuff == NULL) {
                rc = STATUS_INSUFFICIENT_RESOURCES;
            } else {
                MEMCPY(data.pbDataBuff, In->pbDataBuff, data.dwDataLen);
                data.pbDataBuff[data.dwDataLen - 1] = '\0'; // ending zero
                FreeDataBuffs(Out, 1);
                MEMCPY(Out, &data, sizeof(data));
            }
        }
        break;
    case OBJTYPE_BUFFDATA:
        InStrLen = In->dwDataLen;
        if (InStrLen >= 201)
            InStrLen = 201;
        if (!MaxLen) {
            StrLen = strnlen((PCHAR)In->pbDataBuff, InStrLen);
            if (StrLen == InStrLen)
                return STATUS_INVALID_BUFFER_SIZE;
        } else {
            if (MaxLen > InStrLen || MaxLen > 200)
               return STATUS_ACPI_FATAL;
        }

        data.dwDataLen = StrLen + 1;
        data.pbDataBuff = (PUCHAR) NEWSDOBJ(gpheapGlobal, data.dwDataLen);
        if (data.pbDataBuff == NULL) {
            rc = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            MEMCPY(data.pbDataBuff, In->pbDataBuff, data.dwDataLen - 1);
            data.pbDataBuff[data.dwDataLen - 1] = '\0'; // ending zero
            FreeDataBuffs(Out, 1);
            MEMCPY(Out, &data, sizeof(data));
        }
        break;
    default:
        rc = STATUS_ACPI_INVALID_OBJTYPE;
    }

    return rc;
}


NTSTATUS LOCAL ToString(PCTXT pctxt, PTERM pterm)
{
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA pdata;
    ULONG    MaxLen;
    TRACENAME("TOSTRING")
    ENTER(2, ("ToString(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    if ( pterm->icArgs == 2                                                                    &&
         ((rc = ValidateArgTypes(pterm->pdataArgs, "B"))                    == STATUS_SUCCESS) &&
         ((rc = ValidateTarget(&pterm->pdataArgs[1], OBJTYPE_DATA, &pdata)) == STATUS_SUCCESS) ) {
            rc = ConvertToString(pterm->pdataArgs, 0, pterm->pdataResult);

            switch (rc) {
            case STATUS_INSUFFICIENT_RESOURCES:
              rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                  ("ToString: failed to allocate target buffer"));
              break;
            case STATUS_INVALID_BUFFER_SIZE:
              rc = AMLI_LOGERR(AMLIERR_FATAL,
                  ("ToString: buffer length exceeds maximum value"));
              break;
            case STATUS_ACPI_FATAL:
              rc = AMLI_LOGERR(AMLIERR_FATAL,
                  ("ToString: length specified exceeds input buffer length or maximum value"));
              break;
            }
    } else 
    if ( pterm->icArgs == 3                                                                    &&
         ((rc = ValidateArgTypes(pterm->pdataArgs, "BI"))                   == STATUS_SUCCESS) &&
         ((rc = ValidateTarget(&pterm->pdataArgs[2], OBJTYPE_DATA, &pdata)) == STATUS_SUCCESS) ) {
            MaxLen = pterm->pdataArgs[1].dwDataValue;
            if (MaxLen != 0 &&
                MaxLen != 0xFFFFFFFF) {
                  rc = ConvertToString(pterm->pdataArgs, MaxLen, pterm->pdataResult);
            } else {
                  rc = ConvertToString(pterm->pdataArgs, 0, pterm->pdataResult);
            }

            switch (rc) {
            case STATUS_INSUFFICIENT_RESOURCES:
              rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                  ("ToString: failed to allocate target buffer"));
              break;
            case STATUS_INVALID_BUFFER_SIZE:
              rc = AMLI_LOGERR(AMLIERR_FATAL,
                  ("ToString: buffer length exceeds maximum value"));
              break;
            case STATUS_ACPI_FATAL:
              rc = AMLI_LOGERR(AMLIERR_FATAL,
                  ("ToString: length specified exceeds input buffer length or maximum value"));
              break;
            }
    } else {
        rc = AMLI_LOGERR(AMLIERR_FATAL,
                            ("ToString: invalid # of arguments: %x", pterm->icArgs));
    }

    EXIT(2, ("ToString=%x (Result=%x)\n", rc, pterm->pdataResult));
    return rc;
}


NTSTATUS LOCAL CopyObject(PCTXT pctxt, PTERM pterm)
{
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA  In  = pterm->pdataArgs;
    POBJDATA  Out = pterm->pdataResult;
    POBJDATA  pdata;
    BOOLEAN   bWrite;
    TRACENAME("COPYOBJECT")
    ENTER(2, ("CopyObject(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    bWrite = FALSE;
    rc = ValidateTarget(&pterm->pdataArgs[1], 0, &pdata);
    if (rc) {
        rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                ("CopyObject: failed because target object is not a supername"));
    } else {
        if (MatchObjType(pdata->dwDataType, OBJTYPE_DATAFIELD)) {
            if (In->dwDataType != OBJTYPE_INTDATA &&
                In->dwDataType != OBJTYPE_BUFFDATA)
            {
                rc = AMLI_LOGERR(AMLIERR_FATAL,
                    ("CopyObject: Only Integer and Buffer data can be copied to a Field unit or Buffer Field"));
                goto Exit;
            }
            bWrite = TRUE;
        }

        MoveObjData(Out, In);
        if (bWrite)
            rc = WriteObject(pctxt, pdata, Out);
        else
            rc = DupObjData(gpheapGlobal, pdata, Out);

        if (rc) {
            AMLI_LOGERR(rc,
                    ("CopyObject: failed to duplicate objdata"));
        }
    }

Exit:
    EXIT(2, ("CopyObject=%x (type=%s,value=%I64x,buff=%x,len=%x)\n",
            rc,
            GetObjectTypeName(In->dwDataType),
            In->dwDataValue,
            In->pbDataBuff,
            In->dwDataLen));
    return rc;
}


NTSTATUS LOCAL MidString(PCTXT pctxt, PTERM pterm)
{
    NTSTATUS rc = STATUS_SUCCESS;
    POBJDATA  In  = pterm->pdataArgs;
    POBJDATA  Out = pterm->pdataResult;
    POBJDATA  pdata;
    ULONG     DataLen, NewLength;
    ULONG     MidIndex, MidSize;  
    ULONG     i,j;
    TRACENAME("MID")
    ENTER(2, ("MidString(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    if (((rc = ValidateArgTypes(pterm->pdataArgs, "TII"))                     == STATUS_SUCCESS) &&
        ((rc = ValidateTarget(&pterm->pdataArgs[3], OBJTYPE_DATAOBJ, &pdata)) == STATUS_SUCCESS)) {
            if (In->dwDataType > OBJTYPE_BUFFDATA) {
                rc = AMLI_LOGERR(AMLIERR_FATAL,
                        ("Mid: invalid arg0 type"));
            } else {
                Out->dwDataType = In->dwDataType;
                DataLen = In->dwDataLen;
                MidIndex = In[1].dwDataValue;
                MidSize  = In[2].dwDataValue;
                if (MidIndex < DataLen) {
                    NewLength = MidSize;

                    if (Out->dwDataType == OBJTYPE_STRDATA) {
                        DataLen--;   // exclude ending zero
                        if ((MidIndex + MidSize) > DataLen)
                            NewLength = DataLen - MidIndex;

                        Out->pbDataBuff = (PUCHAR) NEWSDOBJ(gpheapGlobal, NewLength + 1);
                        if (Out->pbDataBuff ==  NULL) {
                            rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                                 ("Mid: failed to allocate target string"));
                        } else {
                            Out->dwDataLen = NewLength + 1;
                            Out->pbDataBuff[Out->dwDataLen - 1] = '\0'; // ending zero
                        }
                    } else {
                        if ( Out->dwDataType != OBJTYPE_BUFFDATA ) {
                            rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                                 ("Mid: pterm->pdataResult->dwDataType != OBJTYPE_BUFFDATA"));
                        } else {
                            if ((MidIndex + MidSize) > DataLen)
                                NewLength = DataLen - MidIndex;

                            Out->pbDataBuff = (PUCHAR) NEWSDOBJ(gpheapGlobal, NewLength);
                            if (Out->pbDataBuff ==  NULL) {
                                rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                                     ("Mid: failed to allocate target string"));
                            } else {
                                Out->dwDataLen = NewLength;
                            }
                        }
                    }

                    if (!rc) {
                        i = MidIndex;
                        j = 0;
                        if (NewLength) {
                            do {
                                Out->pbDataBuff[j++] = In->pbDataBuff[i++];
                            } while (j < NewLength);
                        }
    
                        rc = WriteObject(pctxt, pdata, pterm->pdataResult);
                    }
                } else { // MidIndex >= DataLen, set len = 0
                    if (In->dwDataType == OBJTYPE_STRDATA) {
                        Out->pbDataBuff = (PUCHAR) NEWSDOBJ(gpheapGlobal, 1);
                        if (Out->pbDataBuff ==  NULL) {
                            rc = AMLI_LOGERR(AMLIERR_OUT_OF_MEM,
                                 ("Mid: failed to allocate target string"));
                        } else {
                            Out->pbDataBuff[0] = '\0'; // ending zero
                            Out->dwDataLen = 1;

                            rc = WriteObject(pctxt, pdata, pterm->pdataResult);
                        }
                    }
                }
            }
    }

    EXIT(2, ("MidString=%x (Result=%x)\n", rc, pterm->pdataResult));
    return rc;
}


NTSTATUS LOCAL Continue(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("CONTINUE")
    ENTER(2, ("Continue(pctxt=%x,pbOp=%x,pterm=%x)\n", pctxt, pctxt->pbOp, pterm));

    ;

    EXIT(2, ("Continue=%x\n", AMLISTA_CONTINUEOP));
    return AMLISTA_CONTINUEOP;
}


NTSTATUS LOCAL Timer(PCTXT pctxt, PTERM pterm)
{
    TRACENAME("TIMER")
    ENTER(2, ("Timer(pctxt=%x,pbOp=%x,pterm=%x, Querying for %s)\n",
                  pctxt,
                  pctxt->pbOp,
                  pterm,
                  pterm->pdataArgs->pbDataBuff));

    pterm->pdataResult->dwDataType = 1;
    pterm->pdataResult->dwDataValue = (ULONG)KeQueryInterruptTime();

    EXIT(2, ("Timer=%x (pnsObj=%x)\n", 0, pterm->pnsObj));
    return AMLIERR_NONE;
}


    /*
    __asm {
        L1: jmp L1
    }
    */


// ACPI 2.0
///////////////////////////////////////////////