//;******************************************************************************
//;* Copyright (c) 1998-2014, Insyde Software Corp. All Rights Reserved.
//;*
//;* You may not reproduce, distribute, publish, display, perform, modify, adapt,
//;* transmit, broadcast, present, recite, release, license or otherwise exploit
//;* any part of this publication in any form, by any means, without the prior
//;* written permission of Insyde Software Corp.
//;*
//;******************************************************************************
#include "stdafx.h"
#include "dia2.h"
#include "cvconst.h"
#include "stdio.h"
#include "io.h"
#include "malloc.h"
#include "string.h"
#include "dispdb.h"
#include <direct.h>

static	MODULE_DESC		**m_pModuleFilesList = NULL;
static	MODULE_DESC		*m_pCurrModuleFile = NULL;
static	MODULE_DESC		m_stLastQueryModule;
static	char			**m_pSourceNamesList = NULL;
static	VAR_DESC		**m_pGlobalSymbolsList = NULL;
static	ADDRESS_DESC		*m_pAddrList = NULL;
static	int			m_nNumModules = 0;
static	int			m_nNumSourceFiles = 0;
static	int			m_nNumGlobalSymbols = 0;
static	int			m_nNumAddrs = 0;

BOOL IsWow64 (void)
{
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);	
	LPFN_ISWOW64PROCESS	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress (GetModuleHandle (_T("kernel32")), "IsWow64Process");

	if (NULL == fnIsWow64Process)
		return FALSE;

	BOOL bIsWow64 = FALSE;
	if (!fnIsWow64Process (GetCurrentProcess(), &bIsWow64)) {			
		//WOW64 is not present
		return FALSE;
	}

	return (bIsWow64 == TRUE);
}

//================================================================================================
//====================================== Public Function =========================================
//================================================================================================

static int CompareString(const void* p1, const void* p2)
{
	return strcmp((*(VAR_DESC**)p1)->VarName, (*(VAR_DESC**)p2)->VarName);
}

//===============================================================================================
//==================================== Private Function =========================================
//===============================================================================================

static void AdjustModuleListBuffer(int DesireItem)
{
	int nTotalModuleList = 0;
	if (m_pModuleFilesList) nTotalModuleList = (int)_msize(m_pModuleFilesList) / sizeof(MODULE_DESC*);
	if (m_nNumModules + DesireItem > nTotalModuleList)
	{
		nTotalModuleList += 0x100;
		m_pModuleFilesList = (MODULE_DESC**)realloc((void*)m_pModuleFilesList, nTotalModuleList * sizeof(MODULE_DESC*));
	}
}

//===============================================================================================
//==================================== Private Function =========================================
//===============================================================================================

static void AdjustAddrLists(int nDesireItems)
{
	int nTotalAddrLists = 0;
	if (m_pAddrList) nTotalAddrLists = (int)_msize(m_pAddrList) / sizeof(ADDRESS_DESC);
	if (m_nNumAddrs + nDesireItems > nTotalAddrLists)
	{
		nTotalAddrLists += 0x100;
		m_pAddrList = (ADDRESS_DESC*)realloc((void*)m_pAddrList, nTotalAddrLists * sizeof(ADDRESS_DESC));
	}
}

//===============================================================================================
//==================================== Private Function =========================================
//===============================================================================================

static int CreateDataSource(MODULE_DESC *pModule)
{
	HRESULT	hr;
	FILE *file;
	DWORD size;
	void *buffer;
	IDiaSession *pCurrSession;
	IDiaDataSource *pCurrDataSource;
	IStream	*pPdbBuffer;
	HGLOBAL	hPdbBuffer;
	int i, nCurrPos;

	file = fopen(pModule->ModuleFullName, "rb");
	if (!file) return FALSE;
	size = _filelength (_fileno(file));
	hPdbBuffer = GlobalAlloc(GMEM_MOVEABLE, size);
	buffer = GlobalLock(hPdbBuffer);
	fread(buffer, 1, size, file);
	GlobalUnlock(hPdbBuffer);
	fclose(file);
	hr = CreateStreamOnHGlobal(hPdbBuffer, FALSE, &pPdbBuffer);
	if (hr != S_OK) return FALSE;
	hr = CoCreateInstance(__uuidof(DiaSource), NULL, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void **)&pCurrDataSource);
	if (hr != S_OK) return FALSE;
	if (pCurrDataSource->loadDataFromIStream(pPdbBuffer) != S_OK)
	{
		pCurrDataSource->Release();
		pCurrDataSource = NULL;
		m_pCurrModuleFile = NULL;
		return FALSE;
	}
	if (pCurrDataSource->openSession(&pCurrSession) != S_OK) return FALSE;
	AdjustModuleListBuffer(1);
	for (i = 0, nCurrPos = m_nNumModules; i < m_nNumModules; i ++)
	{
		if (pModule->BaseAddr >= m_pModuleFilesList[i]->BaseAddr)
		{
			nCurrPos = i;
			memmove(m_pModuleFilesList + i + 1, m_pModuleFilesList + i, sizeof(MODULE_DESC*) * (m_nNumModules - i));
			break;
		}
	}
	m_pModuleFilesList[nCurrPos] = (MODULE_DESC*)malloc(sizeof(MODULE_DESC));
	memcpy(m_pModuleFilesList[nCurrPos], pModule, sizeof(MODULE_DESC));
	m_pCurrModuleFile = m_pModuleFilesList[nCurrPos];
	m_pCurrModuleFile->PdbSession = pCurrSession;
	m_pCurrModuleFile->PdbDataSource = pCurrDataSource;
	m_pCurrModuleFile->PdbBuffer = pPdbBuffer;
	m_pCurrModuleFile->PdbBufferHandle = hPdbBuffer;
	return TRUE;
}

//===============================================================================================
//==================================== Private Function =========================================
//===============================================================================================

static void DeleteModule(int nNum)
{
	MODULE_DESC *pmlist;
	int i;
	
	pmlist = m_pModuleFilesList[nNum];
	for (i = 0; i < pmlist->NumOfSourceNames; i ++) if (pmlist->SourceNameList[i]) free(pmlist->SourceNameList[i]);
	if (pmlist->SourceNameList) free(pmlist->SourceNameList);
	if (pmlist->GlobalVarList) free(pmlist->GlobalVarList);
	if (pmlist->PdbSession) ((IDiaSession*)pmlist->PdbSession)->Release();
	if (pmlist->PdbDataSource) ((IDiaDataSource*)pmlist->PdbDataSource)->Release();
	if (pmlist->PdbBuffer) ((IStream*)pmlist->PdbBuffer)->Release();
	if (pmlist->PdbBufferHandle) GlobalFree(pmlist->PdbBufferHandle);
	if (pmlist->FuncList) free (pmlist->FuncList);
	free(pmlist);
	if (m_pCurrModuleFile == pmlist) m_pCurrModuleFile = NULL;
	memcpy(m_pModuleFilesList + nNum, m_pModuleFilesList + nNum + 1, sizeof(MODULE_DESC*) * (m_nNumModules - nNum - 1));
	m_nNumModules --;
	if (!m_nNumModules)
	{
		free(m_pModuleFilesList);
		m_pModuleFilesList = NULL;
	}
	if (m_pSourceNamesList)
	{
		free(m_pSourceNamesList);
		m_pSourceNamesList = NULL;
		m_nNumSourceFiles = 0;
	}
	if (m_pGlobalSymbolsList)
	{
		free(m_pGlobalSymbolsList);
		m_pGlobalSymbolsList = NULL;
		m_nNumGlobalSymbols = 0;
	}
}

//===============================================================================================
//==================================== Private Function =========================================
//===============================================================================================

unsigned __int64 ConvertVariant(VARIANT v)
{
	switch( v.vt )
	{
		
		case VT_I8:		// LONGLONG
			return v.llVal;
		case VT_I4:		// LONG
			return v.lVal;
		case VT_UI1:		// BYTE
			return v.bVal;
		case VT_I2:		// SHORT
			return v.iVal;
		case VT_I1:		// CHAR
			return v.cVal;
		case VT_UI2:		// USHORT
			return v.uiVal;
		case VT_UI4:		// ULONG
			return v.ulVal;
		case VT_UI8:		// ULONGLONG
			return v.ullVal;
		case VT_INT:		// INT
			return v.intVal;
		case VT_UINT:		// UINT
			return v.uintVal;
	}
	return 0;
}

//===============================================================================================
//==================================== Private Function =========================================
//===============================================================================================

static void GetDataType(IDiaSymbol *pType, VAR_DESC *pCurrVarList)
{
	DWORD tag = 0, bt;
	ULONGLONG size;
	IDiaSymbol *pBaseType;
	BSTR name;

	pType->get_symTag(&tag);
	pCurrVarList->SymbolTag = (BYTE)tag;
	pType->get_length(&size);
	if (!pCurrVarList->Len) pCurrVarList->Len = (DWORD)size;
	switch (tag)
	{
		case SymTagUDT:		// Stop recursive
		case SymTagEnum:
			if (pType->get_name(&name) == S_OK && name != NULL)
			{
				wcstombs(pCurrVarList->TypeName, name, 80);
				pType->get_symIndexId(&pCurrVarList->SymbolID);
				SysFreeString(name);
				pCurrVarList->BaseTypeLen = (DWORD)size;	
			}
			break;
		case SymTagBaseType:	// Stop recursive
			pType->get_baseType(&bt);
			pCurrVarList->BaseType = (BYTE)bt;
			if (size) pCurrVarList->BaseTypeLen = (DWORD)size;	// The size of void is 0 
			break;
		case SymTagPointerType:	// Recursive to find out base type
			pType->get_type(&pBaseType);
			pCurrVarList->PointerTimes ++;
			pCurrVarList->BaseTypeLen = (DWORD)size;		// In order to prevent BaseTypeLen no specify by SymTagBaseType
			GetDataType(pBaseType, pCurrVarList);
			pBaseType->Release();
			break;
		case SymTagArrayType:	// Recursive to find out base type
			pType->get_type(&pBaseType);
			GetDataType(pBaseType, pCurrVarList);
			pCurrVarList->NumElements = pCurrVarList->Len / pCurrVarList->BaseTypeLen;
			pBaseType->Release();
			break;

	}
}

//===============================================================================================
//==================================== Private Function =========================================
//===============================================================================================

static void FindLocalVars(IDiaSymbol *pBlock, int *pNumVars, VAR_DESC **pVarLists)
{
	long i, num;
	DWORD tag, kind, loctype;
	BSTR name;
	IDiaEnumSymbols *pSymbols;
	IDiaSymbol *pSymbol, *pParent, *pType;
	VAR_DESC *pCurrVarList;

	*pVarLists = NULL;
	*pNumVars = 0;
	do
	{
		if (pBlock->findChildren(SymTagNull, NULL, nsNone, &pSymbols) != S_OK || pSymbols == NULL) break;
		if (pSymbols->get_Count(&num) != S_OK || num == 0) break;
		*pVarLists = (VAR_DESC*)realloc(*pVarLists, ((*pNumVars) + num) * sizeof(VAR_DESC));
		pCurrVarList = (*pVarLists) + (*pNumVars);
		memset(pCurrVarList, 0, num * sizeof(VAR_DESC));
		for (i = 0; i < num; i ++)
		{
			pSymbols->Item(i, &pSymbol);
			pSymbol->get_symTag(&tag);
			switch (tag)
			{
				case SymTagData:
					pSymbol->get_name(&name);
					if (name != NULL && name[0] != 0)
					{
						wcstombs(pCurrVarList->VarName, name, 80);
						SysFreeString(name);
						pSymbol->get_dataKind(&kind);
						if (kind == DataIsParam || kind == DataIsLocal || kind == DataIsStaticLocal)
						{
							pCurrVarList->DataKind = (BYTE)kind;
							pSymbol->get_type(&pType);
							pSymbol->get_locationType(&loctype);
							if (kind == DataIsStaticLocal)
							{
								pSymbol->get_relativeVirtualAddress((DWORD*)&pCurrVarList->DataOffset);
							}
							else
							{
								switch (loctype)
								{
									case LocIsRegRel:
										pSymbol->get_registerId((DWORD*)&pCurrVarList->BaseRegNum);
										pSymbol->get_offset(&pCurrVarList->DataOffset);
										break;
								}
							}
							GetDataType(pType, pCurrVarList);
							pType->Release();
						}
						pCurrVarList ++;
						(*pNumVars) ++;
					}
					break;
				case SymTagFuncDebugStart:
					pSymbol->get_relativeVirtualAddress(&pCurrVarList->ValidScopeStart);
					break;
				case SymTagFuncDebugEnd:
					pSymbol->get_relativeVirtualAddress(&pCurrVarList->ValidScopeEnd);
					break;
			}
			pSymbol->Release();
		}
		pSymbols->Release();
		pBlock->get_symTag(&tag);
		if (tag == SymTagFunction) break;
		if (pBlock->get_lexicalParent(&pParent) != S_OK || pParent == NULL) break;
		pBlock->Release();
		pBlock = pParent;
	}
	while (pBlock);
	pBlock->Release();
}

//===============================================================================================
//==================================== Private Function =========================================
//===============================================================================================

static int CheckPdbExist(MODULE_DESC *ModuleList, DELETED_CALLBACK DeletedCallback)
{
	HANDLE hFile = 0;
	int i, result = 1;
	MODULE_DESC *pmlist, pmlistbak;
	bool bModuleNotFound, bModuleDifferent, bModuleTimeDifferent;

	hFile = CreateFile(ModuleList->ModuleFullName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		GetFileTime(hFile, NULL, NULL, &ModuleList->FileTime);
		CloseHandle(hFile);
		bModuleNotFound = false;
	}
	else
	{
		result = -1;
		bModuleNotFound = true;
	}
	for (i = 0; i < m_nNumModules && m_pModuleFilesList[i]->BaseAddr + m_pModuleFilesList[i]->Size >= ModuleList->BaseAddr; i ++)
	{
		pmlist = m_pModuleFilesList[i];
		bModuleDifferent = (_stricmp(pmlist->ModuleFullName, ModuleList->ModuleFullName) != 0);
		bModuleTimeDifferent = (bModuleDifferent || memcmp(&ModuleList->FileTime, &pmlist->FileTime, sizeof(FILETIME)));
		if (!bModuleNotFound && !bModuleDifferent && !bModuleTimeDifferent && (ModuleList->BaseAddr == pmlist->BaseAddr || !ModuleList->BaseAddr)) return 0;
		if (pmlist->BaseAddr >= ModuleList->BaseAddr + ModuleList->Size || pmlist->BaseAddr + pmlist->Size <= ModuleList->BaseAddr) continue;
		pmlistbak = *pmlist;
		DeleteModule(i);
		if (DeletedCallback) DeletedCallback(&pmlistbak);
		i --;
		result = (bModuleNotFound) ? -1 : 1;
	}
	return result;
}

//===============================================================================================
//==================================== Private Function =========================================
//===============================================================================================

static int FindSourceInfo(char *pSrcName, DWORD *Line, ULONGLONG *RVA)
{
	DWORD celt, linenum, nearline, lineoffset, found = 0;
	IDiaEnumSourceFiles *pSourceFiles;
	IDiaSourceFile *pSourceFile;
	IDiaEnumSymbols *pSymbols;
	IDiaSymbol *pFunction;
	IDiaEnumLineNumbers *pLines;
	IDiaLineNumber *pLine;
	BSTR fileName;
	wchar_t wSourceName[_MAX_PATH];
	
	mbstowcs(wSourceName, pSrcName, sizeof(wSourceName)/sizeof(wSourceName[0]));
	if (((IDiaSession*)m_pCurrModuleFile->PdbSession)->findFile(NULL, wSourceName, nsNone, &pSourceFiles) != S_OK) return 0;
	while (pSourceFiles->Next(1, &pSourceFile, &celt) == S_OK && celt == 1 && !found)
	{
		if (pSourceFile->get_fileName(&fileName) == S_OK)
		{
			if (memcmp(fileName, wSourceName, SysStringByteLen(fileName)) == 0) found = 1;
			SysFreeString(fileName);
		}
	}
	pSourceFiles->Release();
	if (!found) return 0; else found = 0;
	if (pSourceFile->get_compilands(&pSymbols) != S_OK) return 0;
SearchAgain:
	nearline = 0xffffffff;
	while (pSymbols->Next(1, &pFunction, &celt) == S_OK && celt == 1 && !found)
	{
		if (((IDiaSession*)m_pCurrModuleFile->PdbSession)->findLines(pFunction, pSourceFile, &pLines) != S_OK) continue;
		while (pLines->Next(1, &pLine, &celt) == S_OK && celt == 1 && !found)
		{
			pLine->get_lineNumber(&linenum);
			if (linenum == *Line)
			{
				*Line = linenum;
				pLine->get_relativeVirtualAddress(&lineoffset);
				*RVA = lineoffset;
				found = 1;
			}
			else if (linenum > *Line && nearline > linenum) nearline = linenum;
			pLine->Release();
		}
		pLines->Release();
		pFunction->Release();
	}
	if (!found && nearline != 0xffffffff)
	{
		*Line = nearline;
		pSymbols->Reset();
		goto SearchAgain;
	}
	pSymbols->Release();
	pSourceFile->Release();
	return found;
}

bool GetAllFunctionSymbol (IDiaSymbol *pGlobal)
{
	IDiaEnumSymbols *pEnumSymbols;

	if (FAILED(pGlobal->findChildren(SymTagFunction, NULL, nsNone, &pEnumSymbols))) { //SymTagPublicSymbol
		return false;
	}

	pEnumSymbols->get_Count (&m_pCurrModuleFile->NumOfFuncs);
	m_pCurrModuleFile->FuncList = (FUNC_DESC*)calloc (m_pCurrModuleFile->NumOfFuncs, sizeof(FUNC_DESC));

	IDiaSymbol *pSymbol;
	ULONG celt = 0;
	int iIdx = 0;

	while (SUCCEEDED (pEnumSymbols->Next(1, &pSymbol, &celt)) && (celt == 1)) {
		//DWORD dwSymTag;
		DWORD dwRVA;
		ULONGLONG ulLen;
		BSTR bstrUndname;

		//if (pSymbol->get_symTag (&dwSymTag) != S_OK)
		//	continue;		

		if (pSymbol->get_name (&bstrUndname) != S_OK) {			
			pSymbol->Release();
			continue;
		}

		FUNC_DESC *pFuncDesc = &m_pCurrModuleFile->FuncList[iIdx];		

		if (pSymbol->get_relativeVirtualAddress (&dwRVA) == S_OK) {
			pFuncDesc->StartAddr = (DWORD)(dwRVA + m_pCurrModuleFile->BaseAddr + m_pCurrModuleFile->BaseAddrAdjust);
		} else {
			pFuncDesc->StartAddr = 0;
		}

		if (pSymbol->get_length (&ulLen) == S_OK) {
			pFuncDesc->Length = ulLen;
			
			IDiaEnumLineNumbers* pEnumLines;
			IDiaLineNumber *pLine;
			DWORD line_num, count;
			if (((IDiaSession*)m_pCurrModuleFile->PdbSession)->findLinesByRVA(dwRVA, (DWORD)ulLen, &pEnumLines) == S_OK) {
				while (SUCCEEDED(pEnumLines->Next(1, &pLine, &count)) && count == 1) {
					pLine->get_lineNumber(&line_num);
					if ((pFuncDesc->slno == 0) || (line_num < pFuncDesc->slno))
						pFuncDesc->slno = line_num;
					if (line_num > pFuncDesc->elno)
						pFuncDesc->elno = line_num;
					pLine->Release();
				}
				pEnumLines->Release();
			}
		}
				
		wcstombs (pFuncDesc->Name, bstrUndname, 80);
		SysFreeString (bstrUndname);
		iIdx++;

		pSymbol->Release();
	}

	m_pCurrModuleFile->NumOfFuncs = iIdx;
	pEnumSymbols->Release();

	return true;
}
//===============================================================================================
//==================================== Public Function ==========================================
//===============================================================================================

int PdbRegisterModule(MODULE_DESC *ModuleList, DELETED_CALLBACK DeletedCallback)
{
	int i, j, k, result;
	DWORD dwSymTag;
	IDiaEnumSourceFiles *pSourceFiles;
	IDiaSourceFile *pSourceFile;
	IDiaEnumSymbols *pSymbols;
	IDiaSymbol *pGlobalSymbol, *pSymbol;
	VAR_DESC *pVar;
	BSTR name;
	
	memcpy(&m_stLastQueryModule, ModuleList, sizeof(MODULE_DESC));
	result = CheckPdbExist(ModuleList, DeletedCallback);
	if (result != 1) return -result;
	if (!CreateDataSource(ModuleList)) return 2;
	if (((IDiaSession*)m_pCurrModuleFile->PdbSession)->findFile(NULL, NULL, nsNone, &pSourceFiles) == S_OK)
	{
		pSourceFiles->get_Count(&m_pCurrModuleFile->NumOfSourceNames);
		m_pCurrModuleFile->SourceNameList = (char**)calloc(m_pCurrModuleFile->NumOfSourceNames, sizeof(char*));
		for (i = 0, j = 0; i < m_pCurrModuleFile->NumOfSourceNames; i ++)
		{
			if (pSourceFiles->Item(i, &pSourceFile) == S_OK)
			{
				if (pSourceFile->get_fileName(&name) == S_OK && (k = SysStringByteLen(name)) != 0)
				{
					m_pCurrModuleFile->SourceNameList[j] = (char*)malloc(k + 1);
					wcstombs(m_pCurrModuleFile->SourceNameList[j], name, k + 1);
					SysFreeString(name);
					j ++;
					if (m_pSourceNamesList)
					{
						free(m_pSourceNamesList);
						m_pSourceNamesList = NULL;
						m_nNumSourceFiles = 0;
					}
				}
				pSourceFile->Release();
			}
		}
		m_pCurrModuleFile->NumOfSourceNames = j;
		pSourceFiles->Release();
	}
	
	if (((IDiaSession*)m_pCurrModuleFile->PdbSession)->get_globalScope(&pGlobalSymbol) == S_OK)
	{
		if (pGlobalSymbol->findChildren(SymTagFunction, NULL, nsNone, &pSymbols) == S_OK)
		{
			pSymbols->get_Count(&m_pCurrModuleFile->NumOfGlobalVars);
			m_pCurrModuleFile->GlobalVarList = (VAR_DESC*)calloc(m_pCurrModuleFile->NumOfGlobalVars, sizeof(VAR_DESC));
			for (i = 0, j = 0; i < m_pCurrModuleFile->NumOfGlobalVars; i ++)
			{
				if (pSymbols->Item(i, &pSymbol) == S_OK)
				{
					pSymbol->get_symTag(&dwSymTag);
					if (dwSymTag == SymTagFunction || dwSymTag == SymTagData)
					{
						pSymbol->get_name(&name);
						if (name != NULL)
						{
							pVar = &m_pCurrModuleFile->GlobalVarList[j];
							wcstombs(pVar->VarName, name, 80);
							SysFreeString(name);
							pVar->SymbolTag = (BYTE)dwSymTag;
							pVar->BaseAddr = 0;
							pSymbol->get_relativeVirtualAddress((DWORD*)&pVar->BaseAddr);
							pVar->BaseAddr += m_pCurrModuleFile->BaseAddr;
							pVar->BaseModuleAddr = m_pCurrModuleFile->BaseAddr;
							j ++;
							if (m_pGlobalSymbolsList)
							{
								free(m_pGlobalSymbolsList);
								m_pGlobalSymbolsList = NULL;
								m_nNumGlobalSymbols = 0;
							}
						}
					}
					pSymbol->Release();
				}
			}
			m_pCurrModuleFile->NumOfGlobalVars = j;
			pSymbols->Release();
		}

		GetAllFunctionSymbol (pGlobalSymbol);

		pGlobalSymbol->Release();
	}
	
	m_pCurrModuleFile->SerialNumber = m_nNumModules;
	m_nNumModules ++;
	return 0;
}

//===============================================================================================
//==================================== Public Function ==========================================
//===============================================================================================

int PdbUnregisterModules(int nType, ULONGLONG LowBoundry, ULONGLONG HighBoundry)
{		
	if (m_pModuleFilesList == NULL)
		return TRUE;
	
	for (int i = m_nNumModules - 1; i >= 0; i --) {
		MODULE_DESC *pmlist = m_pModuleFilesList[i];
		bool bDelete = false;

		if (nType == RANGE_INCLUDE)	{
			if (pmlist->BaseAddr >= LowBoundry && pmlist->BaseAddr < HighBoundry) 
				bDelete = true;
		} else {
			if ((pmlist->BaseAddr < LowBoundry || pmlist->BaseAddr >= HighBoundry) && m_pModuleFilesList[i]->BaseAddr != m_stLastQueryModule.BaseAddr) 
				bDelete = true;
		}

		if (bDelete) {
			DeleteModule (i);
		}
	}

	if (m_nNumModules == 0) {
		free (m_pModuleFilesList);
		m_pModuleFilesList = NULL;
		m_nNumModules = 0;
	}	
	
	return TRUE;
}

//===============================================================================================
//==================================== Public Function ==========================================
//===============================================================================================

int PdbQueryModuleByAddr(ULONGLONG Addr, char **SourceName, unsigned long *Line, char **FuncName)
{
	int i, j, found, LineIndex;
	long NumSameLines;
	DWORD rva, line;
	MODULE_DESC *pmlist;
	IDiaEnumLineNumbers *pLines;
	IDiaLineNumber *pLine;
	IDiaSourceFile *pSourceFile;
	BSTR fileName, funcName;
	char cfileName[512];
	IDiaSymbol* pFunc;
	LONG disp = 0;
	int foundFunc = 0;

	if (!m_pModuleFilesList) return FALSE;
	for (i = 0, found = 0; i < m_nNumModules && !found; i ++)
	{
		pmlist = m_pModuleFilesList[i];
		if (Addr >= pmlist->BaseAddr && Addr < pmlist->BaseAddr + pmlist->Size)
		{
			m_pCurrModuleFile = pmlist;
			rva = (DWORD)(Addr - pmlist->BaseAddr - pmlist->BaseAddrAdjust);
			if (((IDiaSession*)m_pCurrModuleFile->PdbSession)->findLinesByRVA(rva, 0, &pLines) != S_OK) return FALSE;
			pLines->get_Count(&NumSameLines);
			if (NumSameLines == 0) return FALSE;
			if (NumSameLines > 1)
			{
				for (j = 0, LineIndex = -1; j < NumSameLines; j ++)
				{
					pLines->Item(j, &pLine);
					pLine->get_lineNumber(&line);
					pLine->Release();
					if (*Line == line)
					{
						LineIndex = j;
						break;
					}
				}
				if (LineIndex == -1) LineIndex = 0;
			} else LineIndex = 0;
			pLines->Item(LineIndex, &pLine);
			pLine->get_lineNumber(Line);
			pLine->get_sourceFile(&pSourceFile);
			pSourceFile->get_fileName(&fileName);
			wcstombs(cfileName, fileName, 512);
			SysFreeString(fileName);
			for (j = 0; j < m_pCurrModuleFile->NumOfSourceNames; j ++)
			{
				if (_stricmp(cfileName, m_pCurrModuleFile->SourceNameList[j]) == 0)
				{
					*SourceName = m_pCurrModuleFile->SourceNameList[j];
					found = 1;
					break;
				}
			}
			
			if (FuncName && ((IDiaSession*)m_pCurrModuleFile->PdbSession)->findSymbolByRVA(rva, SymTagFunction, &pFunc) == S_OK)
			{
				pFunc->get_name(&funcName);
				wcstombs(cfileName, funcName, 80);
				for (j = 0; j < m_pCurrModuleFile->NumOfFuncs; j ++)
				{
					if (_stricmp(cfileName, m_pCurrModuleFile->FuncList[j].Name) == 0)
					{
						*FuncName = m_pCurrModuleFile->FuncList[j].Name;
						foundFunc = 1;
						//*offset = 0; //disp;
						break;
					}
				}
				SysFreeString(funcName);
				pFunc->Release();
			}
			else
			{
				disp = 0;
			}

			pSourceFile->Release();
			pLine->Release();
			pLines->Release();
		}
	}
	return found;
}

//===============================================================================================
//==================================== Public Function ==========================================
//===============================================================================================

int PdbQueryAddrByModule(char *SourceName, DWORD *Line, char *ModuleName, ADDRESS_DESC **AddrList)
{
	int i, j, k, len;
	MODULE_DESC **pmlist, *pmdesc, *pmdescskip;
	ULONGLONG RVA, ModuleBaseAddr;
	long ModuleAddrAdjust;
	DWORD ModuleSize;
	char *pSrcName;
	
	if (!m_pModuleFilesList || !SourceName) return 0;
	m_nNumAddrs = 0;
	for (i = 0; i < 2; i ++)
	{
		if (!i)
		{
			if (m_pCurrModuleFile)
			{
				len = 1;
				pmlist = &m_pCurrModuleFile;
			}
			else continue;
		}
		else
		{
			len = m_nNumModules;
			pmlist = m_pModuleFilesList;
			pmdescskip = m_pCurrModuleFile;
		}
		for (j = 0; j < len; j ++)
		{
			pmdesc = pmlist[j];
			if (i && pmdesc == pmdescskip) continue;
			for (k = 0; k < pmdesc->NumOfSourceNames; k ++)
			{
				pSrcName = pmdesc->SourceNameList[k];
				if (_stricmp(SourceName, pSrcName) == 0)
				{
					if (!ModuleName || _stricmp(ModuleName, pmdesc->ModuleFullName) == 0)
					{
						if (!m_pCurrModuleFile || _stricmp(pmdesc->ModuleFullName, m_pCurrModuleFile->ModuleFullName) != 0)
						{
							m_pCurrModuleFile = pmdesc;
							ModuleBaseAddr = m_pCurrModuleFile->BaseAddr;
							ModuleAddrAdjust = m_pCurrModuleFile->BaseAddrAdjust;
							ModuleSize = m_pCurrModuleFile->Size;
						}
						else
						{
							ModuleBaseAddr = pmdesc->BaseAddr;
							ModuleAddrAdjust = pmdesc->BaseAddrAdjust;
							ModuleSize = pmdesc->Size;
						}
						if (FindSourceInfo(pSrcName, Line, &RVA))
						{
							AdjustAddrLists(1);
							m_pAddrList[m_nNumAddrs].Addr = ModuleBaseAddr + ModuleAddrAdjust + RVA;
							strcpy(m_pAddrList[m_nNumAddrs].ModuleName, pmdesc->ModuleFullName);
							m_pAddrList[m_nNumAddrs].SerialNumber = pmdesc->SerialNumber;
							m_nNumAddrs ++;
						}
					}
					break;
				}	
			}
		}
	}
	if (m_nNumAddrs) *AddrList = m_pAddrList;
	return m_nNumAddrs;
}

//===============================================================================================
//==================================== Public Function ==========================================
//===============================================================================================

int PdbQueryVariables(int nType, ULONGLONG Addr, int *NumVars, VAR_DESC **VarList, int *FirstLine, ULONGLONG *ModuleBaseAddr)
{
	int nResult = false;
	long i, j, num;
	DWORD rva, frva, kind;
	VAR_DESC *pVar;
	MODULE_DESC *pmlist;
	IDiaSymbol *pGlobal, *pFunction, *pSymbol, *pType; //, *pBlock
	IDiaEnumSymbols *pSymbols;
	BSTR name;
	
	if (!m_pModuleFilesList) return FALSE;
	for (i = 0; i < m_nNumModules; i ++)
	{
		pmlist = m_pModuleFilesList[i];
		if (Addr >= pmlist->BaseAddr && Addr < pmlist->BaseAddr + pmlist->Size)
		{
			m_pCurrModuleFile = pmlist;
			if (ModuleBaseAddr) *ModuleBaseAddr = pmlist->BaseAddr + pmlist->BaseAddrAdjust;
			if (!nType)
			{
				rva = (DWORD)(Addr - pmlist->BaseAddr - pmlist->BaseAddrAdjust);
				//if (((IDiaSession*)m_pCurrModuleFile->PdbSession)->findSymbolByRVA(rva, SymTagBlock, &pBlock) != S_OK || pBlock == NULL) return FALSE;
				//FindLocalVars(pBlock, NumVars, VarList);
				if (((IDiaSession*)m_pCurrModuleFile->PdbSession)->findSymbolByRVA(rva, SymTagFunction, &pFunction) != S_OK || pFunction == NULL) return FALSE;
				FindLocalVars(pFunction, NumVars, VarList);
				pFunction->get_relativeVirtualAddress(&frva);
				*FirstLine = (rva == frva);
				pFunction->Release();
				nResult = (*NumVars > 0);
			}
			else
			{
				if (((IDiaSession*)m_pCurrModuleFile->PdbSession)->get_globalScope(&pGlobal) == S_OK && pGlobal)
				{
					if (pGlobal->findChildren(SymTagData, NULL, nsNone, &pSymbols) == S_OK)
					{
						if (pSymbols->get_Count(&num) == S_OK && num != 0)
						{
							*VarList = pVar = (VAR_DESC*)calloc(num, sizeof(VAR_DESC));
							for (j = 0, *NumVars = 0; j < num; j ++)
							{
								pSymbols->Item(j, &pSymbol);
								pSymbol->get_name(&name);
								if (name != NULL)
								{
									wcstombs(pVar->VarName, name, 80);
									SysFreeString(name);
									pSymbol->get_dataKind(&kind);
									if (kind == DataIsGlobal)
									{
										pVar->DataKind = (BYTE)kind;
										pSymbol->get_relativeVirtualAddress((DWORD*)&pVar->DataOffset);
										if (pVar->DataOffset)
										{
											pSymbol->get_type(&pType);
											GetDataType(pType, pVar);
											pType->Release();
											pVar ++;
											(*NumVars) ++;
											nResult = true;
										}
									}
								}
								pSymbol->Release();
							}
						}
						pSymbols->Release();
					}
					pGlobal->Release();
				}
			}
			break;
		}
	}
	return nResult;
}

//===============================================================================================
//==================================== Public Function ==========================================
//===============================================================================================

int PdbQueryVarStruct(ULONGLONG Addr, DWORD SymbolID, int *nSize, int *NumVars, VAR_DESC **VarList)
{
	ULONGLONG length;
	long i, j, num, offset;
	DWORD kind, loctype, bitpos;
	VAR_DESC *pVar;
	MODULE_DESC *pmlist;
	IDiaSymbol *pStructure, *pSymbol, *pType;
	IDiaEnumSymbols *pSymbols; 
	BSTR name;
	int nResult = false;
	VARIANT Variant;
	
	if (!m_pModuleFilesList) return FALSE;
	for (i = 0; i < m_nNumModules; i ++)
	{
		pmlist = m_pModuleFilesList[i];
		if (Addr >= pmlist->BaseAddr && Addr < pmlist->BaseAddr + pmlist->Size)
		{
			m_pCurrModuleFile = pmlist;
			if (((IDiaSession*)m_pCurrModuleFile->PdbSession)->symbolById(SymbolID, &pStructure) == S_OK)
			{
				pStructure->get_length(&length);
				*nSize = (int)length;
				if (pStructure->findChildren(SymTagNull, NULL, nsfCaseInsensitive, &pSymbols) == S_OK)
				{
					if (pSymbols->get_Count(&num) == S_OK && num != 0)
					{
						*VarList = pVar = (VAR_DESC*)calloc(num, sizeof(VAR_DESC));
						for (j = 0, *NumVars = 0; j < num; j ++)
						{
							pSymbols->Item(j, &pSymbol);
							pSymbol->get_name(&name);
							if (name != NULL)
							{
								wcstombs(pVar->VarName, name, 80);
								SysFreeString(name);
								pSymbol->get_dataKind(&kind);
								pVar->DataKind = (BYTE)kind;
								pSymbol->get_locationType(&loctype);
								switch(loctype)
								{
									case LocIsConstant:
										pSymbol->get_value(&Variant);
										pVar->ConstValue = ConvertVariant(Variant);
										break;
									case LocIsThisRel:
									case LocIsBitField:
										pSymbol->get_offset(&offset);
										pVar->DataOffset = offset;
										pSymbol->get_type(&pType);
										GetDataType(pType, pVar);
										pType->Release();
										if (loctype == LocIsBitField)
										{
											pSymbol->get_bitPosition(&bitpos);
											pVar->BitFieldPos = (short)bitpos;
											pSymbol->get_length(&length);
											pVar->BitFieldLen = (short)length;
										}
										break;
								}
								pVar ++;
								(*NumVars) ++;
								nResult = true;
							}
							pSymbol->Release();
						}
					}
					pSymbols->Release();
				}
				pStructure->Release();
			}
		}
	}
	return nResult;
}

//===============================================================================================
//==================================== Public Function ==========================================
//===============================================================================================

int PdbGetSourceNames(MODULE_DESC *OwnerModule, char ***pSourceNames)
{
	int i, j, k, nNumSourceFiles = 0;
	MODULE_DESC *pmlist;

	if (!m_nNumModules) return 0;
	if (!OwnerModule)
	{
		if (!m_pSourceNamesList)
		{
			for (i = 0, m_nNumSourceFiles = 0; i < m_nNumModules; i ++)
			{
				pmlist = m_pModuleFilesList[i];
				m_nNumSourceFiles += pmlist->NumOfSourceNames;
			}
			m_pSourceNamesList = (char**)malloc(sizeof(char*) * m_nNumSourceFiles);
			for (i = 0, j = 0; i < m_nNumModules; i ++)
			{
				pmlist = m_pModuleFilesList[i];
				for (k = 0; k < pmlist->NumOfSourceNames; k ++)
				{
					m_pSourceNamesList[j] = pmlist->SourceNameList[k];
					j ++;
				}
			}
		}
		*pSourceNames = m_pSourceNamesList;
		nNumSourceFiles = m_nNumSourceFiles;
	}
	else
	{
		for (i = 0; i < m_nNumModules; i ++)
		{
			pmlist = m_pModuleFilesList[i];
			if (OwnerModule == pmlist)
			{
				*pSourceNames = pmlist->SourceNameList;
				nNumSourceFiles = pmlist->NumOfSourceNames;
				break;
			}
		}
	}
	return nNumSourceFiles;
}

//===============================================================================================
//==================================== Public Function ==========================================
//===============================================================================================

int PdbGetAllSymbols(VAR_DESC ***pSymbolList)
{
	int i, j, k;
	MODULE_DESC *pmlist;

	if (!m_nNumModules) return 0;
	if (!m_pGlobalSymbolsList)
	{
		for (i = 0, m_nNumGlobalSymbols = 0; i < m_nNumModules; i ++)
		{
			pmlist = m_pModuleFilesList[i];
			m_nNumGlobalSymbols += pmlist->NumOfGlobalVars;
		}
		m_pGlobalSymbolsList = (VAR_DESC**)malloc(sizeof(VAR_DESC*) * m_nNumGlobalSymbols);
		for (i = 0, j = 0; i < m_nNumModules; i ++)
		{
			pmlist = m_pModuleFilesList[i];
			for (k = 0; k < pmlist->NumOfGlobalVars; k ++)
			{
				m_pGlobalSymbolsList[j] = &pmlist->GlobalVarList[k];
				j ++;
			}
		}
		qsort(m_pGlobalSymbolsList, m_nNumGlobalSymbols, sizeof(VAR_DESC*), CompareString);
	}
	*pSymbolList = m_pGlobalSymbolsList;
	return m_nNumGlobalSymbols;
}

//===============================================================================================
//==================================== Public Function ==========================================
//===============================================================================================

int PdbGetAllModules(MODULE_DESC ***ModuleList)
{
	*ModuleList = m_pModuleFilesList;
	return m_nNumModules;
}

//===============================================================================================
//==================================== Public Function ==========================================
//===============================================================================================

MODULE_DESC *PdbGetLastQueryModule()
{
	return &m_stLastQueryModule;
}

//===============================================================================================
//==================================== Public Function ==========================================					
//===============================================================================================

BOOL PdbInit (char *CurrDir)
{
	if (FAILED (CoInitialize (NULL))) 
		return FALSE;
	
	BOOL result = TRUE;
	IDiaDataSource *pComObj;
	HRESULT hr = CoCreateInstance(__uuidof(DiaSource), NULL, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (LPVOID*)&pComObj);
	if (FAILED(hr))
	{
		const char *pszMsDiaDllFileName = "msdia90.dll";	
		char szMsDiaDllFilePath[_MAX_PATH] = {0};
			
		strcpy (szMsDiaDllFilePath, CurrDir);
		if (szMsDiaDllFilePath[strlen (szMsDiaDllFilePath) - 1] != '\\') 
			strcat (szMsDiaDllFilePath, "\\");
		strcat (szMsDiaDllFilePath, pszMsDiaDllFileName);
		
		//if (IsWow64 ()) {
			// A workaround solution to register COM DLL;
			// Copy msdia90.dll to \Windows\SysWoW64 and call \Windows\SysWoW64\regsvr32.exe
			// to register it as 32-bit COM DLL (instead of 64-bit COM)
			char pszSysPathName[_MAX_PATH]; // = "C:\\Windows\\SysWoW64";
			//char szNewMsDiaDllFilePath[_MAX_PATH] = {0};		
			if (IsWow64 ())
				GetSystemWow64Directory (pszSysPathName, MAX_PATH);
			else
				GetSystemDirectory (pszSysPathName, MAX_PATH);
			//sprintf (szNewMsDiaDllFilePath, "%s\\%s", pszSysPathName, pszMsDiaDllFileName);
			//if (CopyFile (szMsDiaDllFilePath, szNewMsDiaDllFilePath, TRUE))
			{
				//char szCurWorkingDir[_MAX_PATH] = {0};
				char RegDllCmdLine[0x200] = {0};
				
				//_getcwd (szCurWorkingDir, _MAX_PATH);
				//_chdir (pszSysPathName);
				
				sprintf (RegDllCmdLine, "regsvr32.exe /s \"%s\"", szMsDiaDllFilePath);
				system (RegDllCmdLine);
				/*
				memset (RegDllCmdLine, 0, sizeof (RegDllCmdLine));
				sprintf (RegDllCmdLine, "regsvr32.exe /u /s %s", pszMsDiaDllFileName);
				system (RegDllCmdLine);
				*/
				//_chdir (szCurWorkingDir);
			}
		//} 
		/*
		else
		{
			HMODULE hMsDiaDllModule = LoadLibrary(szMsDiaDllFilePath);
			if (hMsDiaDllModule) {
				typedef long (*funptrDllRegisterServer) (void);
				funptrDllRegisterServer ptrDllRegisterServer = NULL;
				ptrDllRegisterServer = (funptrDllRegisterServer) GetProcAddress(hMsDiaDllModule , "DllRegisterServer");
				if (ptrDllRegisterServer) {
					long status = ptrDllRegisterServer();
					if (status == 0x80004005) 
						result = FALSE;
				}
			
				FreeLibrary(hMsDiaDllModule);
			}	
		}
		*/
	}
	else
		pComObj->Release();

	m_pCurrModuleFile = NULL;
	m_nNumModules = 0;
	AdjustModuleListBuffer (0x100);
	return result;
}

//===============================================================================================
//==================================== Public Function ==========================================					
//===============================================================================================
void PdbReset()
{
	PdbUnregisterModules(RANGE_INCLUDE, 0, 0xffffffffffffffff);
	if (m_pAddrList)
	{
		free(m_pAddrList);
		m_pAddrList = NULL;
		m_nNumAddrs = 0;
	}
}
	
void PdbShutdown()
{
	PdbUnregisterModules(RANGE_INCLUDE, 0, 0xffffffffffffffff);
	if (m_pAddrList)
	{
		free(m_pAddrList);
		m_pAddrList = NULL;
		m_nNumAddrs = 0;
	}
	CoUninitialize();
}
