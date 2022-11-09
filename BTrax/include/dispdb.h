//;******************************************************************************
//;* Copyright (c) 1998-2014, Insyde Software Corp. All Rights Reserved.
//;*
//;* You may not reproduce, distribute, publish, display, perform, modify, adapt,
//;* transmit, broadcast, present, recite, release, license or otherwise exploit
//;* any part of this publication in any form, by any means, without the prior
//;* written permission of Insyde Software Corp.
//;*
//;******************************************************************************
#ifndef _DISPDB_H_
#define _DISPDB_H_

#define MAX_MODULE_NAME 256

typedef struct _FUNC_DESC {
	UINT64	StartAddr;
	UINT64	Length;
	DWORD	slno;
	DWORD	elno;
	TCHAR	Name[80];
} FUNC_DESC;

typedef struct
{
	unsigned char		DataKind;
	unsigned char		PointerTimes;
	unsigned char		SymbolTag;
	unsigned char		BaseType;
	int			BaseTypeLen;
	union
	{
		int			Len;
		unsigned __int64	BaseModuleAddr;
	};
	union
	{
		unsigned __int64	BaseAddr;
		unsigned __int64	ConstValue;
		struct
		{
			long		BaseRegNum;
			long		DataOffset;
		};
	};
	unsigned long		ValidScopeStart;
	unsigned long		ValidScopeEnd;		
	int				NumElements;
	short			BitFieldPos;
	short			BitFieldLen;
	char			VarName[80];
	char			TypeName[80];
	unsigned long		SymbolID;
} VAR_DESC;

typedef struct
{
	unsigned __int64	BaseAddr;
	unsigned __int64	EntryPoint;
	long			BaseAddrAdjust;
	unsigned long		Size;
	unsigned long		SerialNumber;
	unsigned long		CpuMode;
	char			ModuleFullName[MAX_MODULE_NAME];
	char			**SourceNameList;
	long			NumOfSourceNames;
	VAR_DESC		*GlobalVarList;
	FUNC_DESC		*FuncList;
	long			NumOfGlobalVars;
	long			NumOfFuncs;
	FILETIME		FileTime;
	void			*PdbDataSource;
	void			*PdbSession;
	void			*PdbBuffer;
	HGLOBAL			PdbBufferHandle;
} MODULE_DESC;

typedef struct
{
	unsigned __int64	Addr;
	unsigned long		SerialNumber;
	char			ModuleName[MAX_MODULE_NAME];
} ADDRESS_DESC;

typedef struct
{
  UINT64 ImageBase;
  UINT64 ImageEntry;
  INT32  ImageBaseAdjust;
  UINT32 ImageSize;
  UINT32 CpuMode;
  UINT32 SerialNumber;
  char   ModuleName[MAX_MODULE_NAME];
} IMAGE_INFO;
/*
typedef struct
{
	unsigned long	LastLine;
	unsigned long	NumOfLines;
	unsigned long	Lines[10];
} LINE_DESC;
*/
typedef struct _bts_log_header {
  UINT32 signature; //'HSTB'
  UINT32 version;	// 0x10000 (IA32), 0x10001 (X64)
  UINT32 bts_offset;
  UINT32 bts_size;
  UINT32 imginfo_offset;
  UINT32 imginfo_size;
} bts_log_header, *pbts_log_header;

typedef void (*DELETED_CALLBACK)(MODULE_DESC *DeletedModule);

#define	RANGE_INCLUDE	0
#define	RANGE_EXCLUDE	1
/*
typedef void (*PdbResetFtn) ();
typedef int  (*PdbRegisterModuleFtn) (MODULE_DESC*, DELETED_CALLBACK);
typedef int	 (*PdbQueryModuleByAddrFtn) (unsigned __int64, char**, unsigned long*, char**);
typedef int  (*PdbGetAllModulesFtn) (MODULE_DESC***);
typedef struct _PDB_FUNCS {
	PdbResetFtn				Reset;
	PdbRegisterModuleFtn	RegisterModule;
	PdbQueryModuleByAddrFtn	QueryModuleByAddr;
	PdbGetAllModulesFtn		GetAllModules;
} PDB_FUNCS, *PPDB_FUNCS;
*/
#ifdef __cplusplus
extern "C" {
#endif

BOOL PdbInit(char *CurrDir);
void PdbReset();
void PdbShutdown();
int PdbRegisterModule(MODULE_DESC *ModuleList, DELETED_CALLBACK DeletedCallback);
//int PdbUnregisterModules(int nType = RANGE_INCLUDE, ULONGLONG LowBoundry = 0, ULONGLONG HighBoundry = 0xffffffffffffffff);
int	PdbUnregisterModules(int nType, ULONGLONG LowBoundry, ULONGLONG HighBoundry);
int	PdbQueryModuleByAddr(unsigned __int64 Addr, char **SourceName, unsigned long *Line, char **FuncName);
int	PdbQueryAddrByModule(char *SourceName, unsigned long *Line, char *ModuleName, ADDRESS_DESC **AddrList);
int	PdbQueryVariables(int nType, unsigned __int64 Addr, int *NumVars, VAR_DESC **VarList, int *FirstLine, unsigned __int64 *ModuleBaseAddr);
int	PdbQueryVarStruct(unsigned __int64 Addr, unsigned long SymbolID, int *nSize, int *nNumVars, VAR_DESC **pVarDesc);
int	PdbGetSourceNames(MODULE_DESC *OwnerModule, char ***pSourceNames);
int	PdbGetAllSymbols(VAR_DESC ***pVarDescList);
int	PdbGetAllModules(MODULE_DESC ***ModuleList);
MODULE_DESC *PdbGetLastQueryModule();

#ifdef __cplusplus
}
#endif

#endif
