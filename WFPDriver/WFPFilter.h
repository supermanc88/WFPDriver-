#if WINVER > 0x0600 

#ifndef WFPFILTER_H
#define WFPFILTER_H



#ifdef __cplusplus
extern "C"{
#endif


//insert/remove (nPolicy = NONE) net policy
//
//
// BOOL InsertNetPolicyEx(IN CNetPolicyEx *pNetPolicyEx);
//
// BOOL RemoveNetPolicyEx(IN CNetPolicyEx *pNetPolicyEx);
//
// VOID ClearNetPolicyEx();
//
//
// DRIVER_INITIALIZE DriverEntryWFP;
// NTSTATUS
// DriverEntryWFP(
//    IN  PDRIVER_OBJECT  driverObject,
//    IN  PUNICODE_STRING registryPath
//    );
//
// DRIVER_UNLOAD DriverUnload;
// VOID
// DriverUnload(
//    IN  PDRIVER_OBJECT driverObject
//    );



#ifdef __cplusplus
}
#endif



#endif // WFPFILTER_H

#endif //#if WINVER >= 0x0600 
