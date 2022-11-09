#pragma once

#ifdef BTRAX_EXPORTS
   #define DLLAPI  __declspec(dllexport)   // export DLL information
#else
   #define DLLAPI  __declspec(dllimport)   // import DLL information
#endif

#ifndef ReportProgressFtn
typedef void (*ReportProgressFtn) (int);
#endif

#ifdef __cplusplus
extern "C" {
#endif
int DLLAPI execpathmain(char *logfile, char *outpath, char *srcpath, char livemode, ReportProgressFtn iReport, PPDB_FUNCS Pdb);
#ifdef __cplusplus
}
#endif
