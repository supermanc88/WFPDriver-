#if WINVER > 0x0600 
// #include "head.h"
//
#undef MAX_PATH
extern "C"
{
	//for use ndis.h
#define NDIS60  1
#define NDIS_SUPPORT_NDIS6 1
#include <ndis.h>
	//#pragma warning(push)
	//#pragma warning(disable:4201)       // unnamed struct/union
#include <fwpsk.h>
	//#pragma warning(pop)
#include <ip2string.h>
#include <fwpmk.h>
#define INITGUID
#include <guiddef.h>
#include <ntddk.h>
#include <stdio.h>

#ifndef FlagOn
#define FlagOn(_F,_SF)        ((_F) & (_SF))
#endif
#ifndef ClearFlag
#define ClearFlag(_F,_SF)		((_F) &= ~(_SF))
#endif

//#include "WFPFilter.h"
// 
// Callout and sublayer GUIDs
//

// bb6e405b-19f4-4ff3-b501-1a3dc01aae81
DEFINE_GUID(
			FILELOCK_NET_OUTBOUND_TRANSPORT_CALLOUT_V4,
			0xbb6e405b,
			0x19f4,
			0x4ff3,
			0xb5, 0x01, 0x1a, 0x3d, 0xc0, 0x1a, 0xae, 0x81
			);
// cabf7559-7c60-46c8-9d3b-2155ad5cf86f
DEFINE_GUID(
			FILELOCK_NET_OUTBOUND_TRANSPORT_CALLOUT_V6,
			0xcabf7559,
			0x7c60,
			0x46c8,
			0x9d, 0x3b, 0x21, 0x55, 0xad, 0x5c, 0xf8, 0x6f
			);

// 66b743d4-1249-4614-a632-6f9c4d08d25c
DEFINE_GUID(
			FILELOCK_NET_ALE_FLOW_ESTABLISHED_V4,
			0x66b743d4,
			0x1249,
			0x4614,
			0xa6, 0x32, 0x6f, 0x9c, 0x4d, 0x08, 0xd2, 0x5c
			);

// 6c80683a-5b84-43c3-8ae9-eddb5c0d23c6
DEFINE_GUID(
			FILELOCK_NET_ALE_FLOW_ESTABLISHED_V6,
			0x6c80683a,
			0x5b84,
			0x43c3,
			0x8a, 0xe9, 0xed, 0xdb, 0x5c, 0x0d, 0x23, 0xc6
			);

// 2e207682-d95f-4525-b966-969f26587f33
DEFINE_GUID(
			FILELOCK_NET_SUBLAYER,
			0x2e207682,
			0xd95f,
			0x4525,
			0xb9, 0x66, 0x96, 0x9f, 0x26, 0x58, 0x7f, 0x33
			);

// 
// Callout driver global variables
//

PDEVICE_OBJECT g_DeviceObjectWFP = NULL;

HANDLE g_EngineHandle = NULL;

UINT32 g_AleEstablishedCalloutIdV4 = 0;
UINT32 g_AleEstablishedCalloutIdV6 =0;

UINT32 g_OutboundTlCalloutIdV4 = 0;
UINT32 g_OutboundTlCalloutIdV6 = 0;

//////


#if 0
//used for WFPFilter
CNetPolicyEx g_NetPolicyListEx[MAX_NETPOLICY_NUMS] = {0};
ULONG g_NetPolicyNoSendNumsEx = 0;
ULONG g_NetPolicyNoConnectNumsEx = 0;


//insert/remove (nPolicy = NONE) net policy
BOOL InsertNetPolicyEx(IN CNetPolicyEx *pNetPolicyEx)
{
	//find the process ID in the buffer
	int i;
	int inx = MAX_NETPOLICY_NUMS;

	for(i=0;i<MAX_NETPOLICY_NUMS;i++)
	{
		if(0 == memcmp(&g_NetPolicyListEx[i],pNetPolicyEx,sizeof(CNetPolicyEx)))
		{
			g_NetPolicyListEx[i].nPolicy = pNetPolicyEx->nPolicy;
			KdPrint(("InsertNetPolicyEx: Repeat,noConn=%d,noSend=%d,Lport=%d,RIP=0x%x,RPort=%d\n",
				g_NetPolicyNoConnectNumsEx,g_NetPolicyNoSendNumsEx,pNetPolicyEx->LocalPort,pNetPolicyEx->RemoteIP,pNetPolicyEx->RemotePort));

			return TRUE;
		}

		if(!g_NetPolicyListEx[i].nPolicy && (MAX_NETPOLICY_NUMS == inx))
		{
			inx = i;
		}
	}

	if(inx < MAX_NETPOLICY_NUMS)
	{
		g_NetPolicyListEx[inx] = *pNetPolicyEx;

		if(FlagOn(pNetPolicyEx->nPolicy,NETPOLICY_NOCONNECT))
		{
			g_NetPolicyNoConnectNumsEx++;
		}
		if(FlagOn(pNetPolicyEx->nPolicy,NETPOLICY_NOSEND))
		{
			g_NetPolicyNoSendNumsEx++;
		}

		KdPrint(("InsertNetPolicyEx: noConn=%d,noSend=%d,inx=%d,LIP=%x,Lport=%d,RPort=%d,RIP=0x%x,nPolicy=%x,Protocol=%x\n",
			g_NetPolicyNoConnectNumsEx,g_NetPolicyNoSendNumsEx,inx,
			pNetPolicyEx->LocalIP,pNetPolicyEx->LocalPort,pNetPolicyEx->RemoteIP,pNetPolicyEx->RemotePort,pNetPolicyEx->nPolicy,pNetPolicyEx->Protocol));

		return TRUE;
	}

	return FALSE;
}


BOOL RemoveNetPolicyEx(IN CNetPolicyEx *pNetPolicyEx)
{
	//find the process ID in the buffer
	int i;
	KdPrint(("RemoveNetPolicyEx: total=%d,Lport=%d,RPort=%d,RIP=0x%x\n",
		g_NetPolicyNoSendNumsEx+g_NetPolicyNoConnectNumsEx,pNetPolicyEx->LocalPort,pNetPolicyEx->RemoteIP,pNetPolicyEx->RemotePort));

	for(i=0;i< MAX_NETPOLICY_NUMS;i++)
	{
		if(0 == memcmp(&g_NetPolicyListEx[i],pNetPolicyEx,sizeof(CNetPolicyEx)))
		{
			if(g_NetPolicyNoConnectNumsEx && FlagOn(pNetPolicyEx->nPolicy,NETPOLICY_NOCONNECT))
			{
				g_NetPolicyNoConnectNumsEx--;
			}
			if(g_NetPolicyNoSendNumsEx && FlagOn(pNetPolicyEx->nPolicy,NETPOLICY_NOSEND))
			{
				g_NetPolicyNoSendNumsEx--;
			}
			memset(&g_NetPolicyListEx[i],0,sizeof(CNetPolicyEx));
			return TRUE;
		}
	}
	return FALSE;
}


VOID ClearNetPolicyEx()
{
	KdPrint(("ClearNetPolicyEx: noConnect=%d,nosend=%d\n",g_NetPolicyNoConnectNumsEx,g_NetPolicyNoSendNumsEx));	 
	g_NetPolicyNoConnectNumsEx = 0;
	g_NetPolicyNoSendNumsEx = 0;
	RtlZeroMemory(g_NetPolicyListEx,sizeof(CNetPolicyEx)*MAX_NETPOLICY_NUMS);
}


/*
get dynamic network policy
only support LocalIP and LocalPort

*/

VOID CheckNetSendPolicyEx(IN CNetPolicyEx *pNetPolicyEx)
{
	int i;
	pNetPolicyEx->nPolicy = NETPOLICY_NONE;

	for(i=0;i<MAX_NETPOLICY_NUMS;i++)
	{
		if(FlagOn(g_NetPolicyListEx[i].nPolicy,NETPOLICY_NOSEND) && 
			FlagOn(g_NetPolicyListEx[i].Protocol,pNetPolicyEx->Protocol) &&
			(!g_NetPolicyListEx[i].LocalIP || (g_NetPolicyListEx[i].LocalIP == pNetPolicyEx->LocalIP)) &&
			(!g_NetPolicyListEx[i].LocalPort || (g_NetPolicyListEx[i].LocalPort == pNetPolicyEx->LocalPort))
			)
		{
			KdPrint(("CheckNetSendPolicyEx:: Find NetPolicy,port=%d\n",pNetPolicyEx->LocalPort));
			pNetPolicyEx->nPolicy = g_NetPolicyListEx[i].nPolicy;
			return;
		}
	}
}


/*
get dynamic network policy
support  LocalPort, RemoteIP,RemotePort 
*/

VOID CheckNetConnectPolicyEx(IN CNetPolicyEx *pNetPolicyEx)
{

	int i;
	pNetPolicyEx->nPolicy = NETPOLICY_NONE;

	for(i=0;i<MAX_NETPOLICY_NUMS;i++)
	{
		if(FlagOn(g_NetPolicyListEx[i].nPolicy,NETPOLICY_NOCONNECT) && 
			(!g_NetPolicyListEx[i].LocalPort  || (g_NetPolicyListEx[i].LocalPort == pNetPolicyEx->LocalPort)) &&
			(!g_NetPolicyListEx[i].RemoteIP   || (g_NetPolicyListEx[i].RemoteIP == pNetPolicyEx->RemoteIP))	&&
			(!g_NetPolicyListEx[i].RemotePort || (g_NetPolicyListEx[i].RemotePort == pNetPolicyEx->RemotePort))
			)
		{
			KdPrint(("CheckNetConnectPolicyEx:: Find,LocalPort=%d,RemoteIp=0x%x\n",pNetPolicyEx->LocalPort,pNetPolicyEx->RemoteIP));
			pNetPolicyEx->nPolicy = g_NetPolicyListEx[i].nPolicy;
			return;
		}
	}
}



void ntohV6(USHORT *netIPV6)
{
	for(int i = 0;i < 8;i++)
	{
		*netIPV6 = RtlUshortByteSwap(*netIPV6);
		*netIPV6++;
	}
}

#endif
//
//must support IRQL = DISPATCH_LEVEL.
//return
//TRUE: Dennied 
//FALSE: pass through

  BOOL DenyWFPConnect(IN const FWPS_INCOMING_VALUES0* inFixedValues,const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,IN ULONG Pid)
{
	// PCFilePolicy pFilePolicy;
	UNICODE_STRING uDest;
	BOOLEAN bIPV6 = FALSE;
	// pFilePolicy = (PCFilePolicy) ExAllocateFromPagedLookasideList(&g_FilePolicyPool);
	//
	// if(pFilePolicy == NULL)
	// {
	// 	return FALSE;
	// }
	//
	// RtlZeroMemory(pFilePolicy,FILE_POLICY_SIZE);
	// CNetPolicyEx *pPolicyEx = (CNetPolicyEx *)(pFilePolicy->FileName+256);

	switch(inFixedValues->layerId)	
	{
		case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4:
			// pPolicyEx->RemoteIP = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32; 
			// pPolicyEx->RemotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16;
			// pPolicyEx->LocalIP = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32; 
			// pPolicyEx->LocalPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16;
		{
			UINT32 remoteIP = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32;
			UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16;
			UINT32 localIP = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32;
			UINT16 localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16;
		}
		break;
		case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6:
			// RtlCopyMemory(pPolicyEx->RemoteIPV6,inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS].value.byteArray16, sizeof(FWP_BYTE_ARRAY16));
			// ntohV6(pPolicyEx->RemoteIPV6);
			// pPolicyEx->RemotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT].value.uint16;
			// RtlCopyMemory(pPolicyEx->LocalIPV6,inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS].value.byteArray16, sizeof(FWP_BYTE_ARRAY16));
			// ntohV6(pPolicyEx->LocalIPV6);
			// pPolicyEx->LocalPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT].value.uint16;
			// bIPV6 = TRUE;
			break;
		default:
			KdPrint(( "DenyWFPConnect: NO LAYER layerId=%x\n",inFixedValues->layerId));
			// ExFreeToPagedLookasideList(&g_FilePolicyPool, pFilePolicy);
			return FALSE;
			break;
	}

	
// 	if(g_NetPolicyNoConnectNums)
// 	{
// 		CheckNetConnectPolicy(pPolicyEx);
// 		if(FlagOn(pPolicyEx->nPolicy,NETPOLICY_NOCONNECT))
// 		{
// 			if(bIPV6)
// 			{
// 				KdPrint(("DenyWFPConnect[DENY]: Connect Denied,Pid=%d,LocalPort=%d,RemoteIp=%x-%x-%x-%x-%x-%x-%x-%x,port=%d\n",
// 					Pid,
// 					pPolicyEx->LocalPort,
// 					pPolicyEx->RemoteIPV6[0],
// 					pPolicyEx->RemoteIPV6[1],
// 					pPolicyEx->RemoteIPV6[2],
// 					pPolicyEx->RemoteIPV6[3],
// 					pPolicyEx->RemoteIPV6[4],
// 					pPolicyEx->RemoteIPV6[5],
// 					pPolicyEx->RemoteIPV6[6],
// 					pPolicyEx->RemoteIPV6[7],
// 					pPolicyEx->RemotePort)); 	
// 			}
// 			else
// 			{
// 				KdPrint(( "DenyWFPConnect[DENY]: Connect Denied,Pid=%d,LocalPort=%d,RemoteIp=%d.%d.%d.%d,port=%d\n",
// 					Pid,
// 					pPolicyEx->LocalPort,
// 					pPolicyEx->RemoteIP >> 24,
// 					pPolicyEx->RemoteIP >> 16 & 0xFF,
// 					pPolicyEx->RemoteIP >> 8 & 0xFF,
// 					pPolicyEx->RemoteIP & 0xFF,
// 					pPolicyEx->RemotePort));
// 			}
// 			ExFreeToPagedLookasideList(&g_FilePolicyPool, pFilePolicy);
// 			return TRUE;
// 		}
// 	}
//
// //get process name	
// 	do{
// 		if(FlagOn(inMetaValues->currentMetadataValues,FWPS_METADATA_FIELD_PROCESS_PATH) && inMetaValues->processPath)
// 		{
// 			memcpy(pFilePolicy->FileName,inMetaValues->processPath->data,inMetaValues->processPath->size);
// 			pFilePolicy->pTmpFile = ParseFileName(pFilePolicy->FileName);
// 			if(pFilePolicy->pTmpFile)
// 			{
// 				ANSI_STRING aName;
// 				aName.Buffer = pFilePolicy->ProcessName;
// 				aName.Length = 0;
// 				aName.MaximumLength = MAX_FILENAME;
// 				W2C(&aName,pFilePolicy->pTmpFile);
// 				DeleteProcessNameExt(pFilePolicy->ProcessName);
// 				pFilePolicy->ProcessName[PROCESS_NAME_LEN-1] = 0;
// 				_strupr(pFilePolicy->ProcessName);
// 				//KdPrint(("DenyWFPConnect: ProcName=%s\n",pFilePolicy->ProcessName));
// 				break;
// 			}
// 		}
// 		
// 		if(!SearchProcessName(Pid,pFilePolicy->ProcessName))
// 		{
// 			GetProcessName(pFilePolicy->ProcessName);
// 			_strupr(pFilePolicy->ProcessName);
// 		}
// 	}while(FALSE);
//
// 	if((0 == strcmp(pFilePolicy->ProcessName,"SYSTEM"))||
// 		(0 == strcmp(pFilePolicy->ProcessName,"SVCHOST")))
// 	{
// //		KdPrint(("DenyWFPConnect: Pass process =%s,Path=%ws\n",pFilePolicy->ProcessName,pFilePolicy->FileName));
// 		ExFreeToPagedLookasideList(&g_FilePolicyPool, pFilePolicy);
// 		return FALSE;
// 	}
//
// 	if(bIPV6)
// 	{
// //		RtlIpv6AddressToStringW((in6_addr *)pPolicyEx->RemoteIPV6,pFilePolicy->FileName+384);
// 		swprintf(pFilePolicy->FileName,L"#:\\%x-%x-%x-%x-%x-%x-%x-%x\\%d",
// 			pPolicyEx->RemoteIPV6[0],
// 			pPolicyEx->RemoteIPV6[1],
// 			pPolicyEx->RemoteIPV6[2],
// 			pPolicyEx->RemoteIPV6[3],
// 			pPolicyEx->RemoteIPV6[4],
// 			pPolicyEx->RemoteIPV6[5],
// 			pPolicyEx->RemoteIPV6[6],
// 			pPolicyEx->RemoteIPV6[7],
// 			pPolicyEx->RemotePort);
// 	}
// 	else
// 	{
// 		swprintf(pFilePolicy->FileName,L"#:\\%d.%d.%d.%d\\%d",
// 			pPolicyEx->RemoteIP >> 24,
// 			pPolicyEx->RemoteIP >> 16 & 0xFF,
// 			pPolicyEx->RemoteIP >> 8 & 0xFF,
// 			pPolicyEx->RemoteIP & 0xFF,
// 			pPolicyEx->RemotePort);
// 	}
//
// 	pFilePolicy->Pid = Pid;
//
// #ifdef SUPPORT_MULTIUSER
// 	pFilePolicy->pUserCtx = GetPidUserCtx(Pid);;
// #endif
// 	pFilePolicy->PolicyProcName[0] = POLICY_SEPRATOR_ANSI;
// 	strcat(pFilePolicy->PolicyProcName,pFilePolicy->ProcessName);
// 	strcat(pFilePolicy->PolicyProcName,"|");
//
// 	GetNetPolicy(pFilePolicy);
//
// 	//	KdPrint(("DenyWFPConnect: connect, Pid=%d,Policy=%x,%s access %ws!\n",
// 	//			Pid,pFilePolicy->dwPolicy,pFilePolicy->ProcessName,pFilePolicy->FileName));
//
// 	if(FlagOn(pFilePolicy->dwPolicy,POLICY_PROGNET))
// 	{
// 		KdPrint(("DenyWFPConnect[DENY]: connect, Pid=%d,Policy=%x,%s access %ws is denied!\n",
// 			Pid,pFilePolicy->dwPolicy,pFilePolicy->ProcessName,pFilePolicy->FileName));
//
// 		uDest.Buffer =(WCHAR *)pFilePolicy->PolicyProcName;
// 		uDest.MaximumLength = uDest.Length = 26 * sizeof(WCHAR);
// 		if(NT_SUCCESS(C2W(&uDest,pFilePolicy->ProcessName)))
// 		{
// 			RtlMoveMemory(pFilePolicy->FileName + 256,pFilePolicy->FileName,wcslen(pFilePolicy->FileName)*sizeof(WCHAR));
// 			swprintf(pFilePolicy->FileName,L"%ws access %ws is denied!",
// 				(WCHAR *)pFilePolicy->PolicyProcName,&pFilePolicy->FileName[256]);
// 			NotifyWin32(pFilePolicy->FileName,pFilePolicy->Pid,PROCESSTYPE_ACCESSNET_DENIED,0,0);
// 		}
//
// 		ExFreeToPagedLookasideList(&g_FilePolicyPool, pFilePolicy);
// 		return TRUE;
// 	}
//
// 	KdPrint(( "DenyWFPConnect: Connect layerId=%x,Pid=%d,LocalPort=%d,LocalIp=%d.%d.%d.%d,NetPath=%ws\n",
// 				inFixedValues->layerId,
// 				Pid,
// 				pPolicyEx->LocalPort,
// 				pPolicyEx->LocalIP >> 24,
// 				pPolicyEx->LocalIP >> 16 & 0xFF,
// 				pPolicyEx->LocalIP >> 8 & 0xFF,
// 				pPolicyEx->LocalIP & 0xFF,
// 				pFilePolicy->FileName));
//
// 	KdPrint(( "DenyWFPConnect: Connect,Pid=%d,Proc=%s,Name = %ws\n",Pid,pFilePolicy->ProcessName,pFilePolicy->FileName));
// 	ExFreeToPagedLookasideList(&g_FilePolicyPool, pFilePolicy);

	return FALSE;
}



/* ++

This is the classifyFn function for the ALE connect (v4 and v6) callout.
For an initial classify (where the FWP_CONDITION_FLAG_IS_REAUTHORIZE flag
is not set), it is queued to the connection list for inspection by the
worker thread. For re-auth, we first check if it is triggered by an ealier
FwpsCompleteOperation0 call by looking for an pended connect that has been
inspected. If found, we remove it from the connect list and return the 
inspection result; otherwise we can conclude that the re-auth is triggered 
by policy change so we queue it to the packet queue to be process by the 
worker thread like any other regular packets.

-- */

void
NetConnectCallout(
				   IN const FWPS_INCOMING_VALUES0* inFixedValues,
				   IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
				   IN OUT void* layerData,
				   IN const FWPS_FILTER0* filter,
				   IN UINT64 flowContext,
				   OUT FWPS_CLASSIFY_OUT0* classifyOut
				   )
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(filter);
	//
	// We don't have the necessary right to alter the classify, exit.
	//
	if(!FlagOn(classifyOut->rights,FWPS_RIGHT_ACTION_WRITE))
	{
		KdPrint(( "NetConnectCallout: no right, layerId=%x,Pid=%d\n",inFixedValues->layerId,inMetaValues->processId));
		return ;
	}

	classifyOut->actionType = FWP_ACTION_PERMIT;

	ULONG Pid = 0;

	if(FlagOn(inMetaValues->currentMetadataValues,FWPS_METADATA_FIELD_PROCESS_ID))
	{
		Pid = (ULONG)inMetaValues->processId;
		KdPrint(( "NetConnectCallout: currentMetadataValues=%x,Pid=%d,gPid=%d\n",inMetaValues->currentMetadataValues,Pid,PsGetCurrentProcessId()));
	}

	if(!Pid) 
	{
		Pid = (ULONG) PsGetCurrentProcessId();
//		KdPrint(( "NetConnectCallout: Pid=%d,inPid=%d\n",Pid,inMetaValues->currentMetadataValues));
	}
	
	if(!Pid)
	{
		return;
	}

#if 0
#ifdef SUPPORT_MULTIUSER
	CUserCtx *pUserCtx = GetPidUserCtx(Pid);
	if(!pUserCtx)
	{
		return;
	}
	if((!FlagOn(pUserCtx->NetPolicyFlag,NETPOLICYFLAG_TDI) && !g_NetPolicyNoConnectNums) || 
		(WORKMODE_NORMAL != pUserCtx->WorkMode))
	{
		return;
	}

//notes:
//PsGetCurrentThreadId() may = 0

	if((Pid == pUserCtx->RelatedPid)||(Pid == pUserCtx->OurProcessID)||!pUserCtx->bStartFilter)
	{
		return;
	}
#else
	if((!FlagOn(g_NetPolicyFlag,NETPOLICYFLAG_TDI) && !g_NetPolicyNoConnectNums) || 
		(WORKMODE_NORMAL != g_WorkMode))
	{
		KdPrint(("NetConnectCallout: PassConnFlag, PolicyFlag=%x,ConnectNums=%x,WorkMod=%x\n",g_NetPolicyFlag,g_NetPolicyNoConnectNums,g_WorkMode));
		return;
	}
	if((Pid == g_RelateProcessPid) ||(Pid == g_OurProcessID)||!g_bStartFilter)
	{
		KdPrint(("NetConnectCallout: PassConnPid, Pid=%d,OurThreadID=%d,RelateProcessPid=%d,OurProcessID=%d,bStartFilter=%x\n",Pid,g_OurThreadID,g_RelateProcessPid,g_OurProcessID,g_bStartFilter));
		return;
	}
#endif

#endif
	if(DenyWFPConnect(inFixedValues,inMetaValues,Pid))
	{
		classifyOut->actionType = FWP_ACTION_BLOCK;
		ClearFlag(classifyOut->rights,FWPS_RIGHT_ACTION_WRITE);
	}
	return;

}


NTSTATUS
NetConnectNotify(
				 IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
				 IN const GUID* filterKey,
				 IN const FWPS_FILTER0* filter
				 )
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	return STATUS_SUCCESS;
}




//
//must support IRQL = DISPATCH_LEVEL.
//return
//TRUE: Dennied 
//FALSE: pass through
//
//FWPM_LAYER_OUTBOUND_TRANSPORT_V4
//FWPM_LAYER_OUTBOUND_TRANSPORT_V6
  BOOL DenyWFPSend(IN const FWPS_INCOMING_VALUES0* inFixedValues)
{
	BOOLEAN bIPV6 = FALSE;
	// PCNetPolicyEx pPolicyEx  = (PCNetPolicyEx) ExAllocateFromPagedLookasideList(&g_PagedFileName);
	// if(pPolicyEx == NULL)
	// {
	// 	return FALSE;
	// }
	//
	// RtlZeroMemory(pPolicyEx,MAX_FILENAME_BYTES);
	// pPolicyEx->Protocol = NETPROTOCOL_TCP;

	switch(inFixedValues->layerId)	
	{
		case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
			// pPolicyEx->RemoteIP = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32; 
			// pPolicyEx->RemotePort = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
			// pPolicyEx->LocalIP = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32; 
			// pPolicyEx->LocalPort = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint16;
		{
				UINT32 remoteIP = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32;
				UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16;
				UINT32 localIP = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32;
				UINT16 localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16;
		}
			break;
		case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
			// RtlCopyMemory(pPolicyEx->RemoteIPV6,inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS].value.byteArray16, sizeof(FWP_BYTE_ARRAY16));
			// ntohV6(pPolicyEx->RemoteIPV6);
			// pPolicyEx->RemotePort = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_PORT].value.uint16;
			// RtlCopyMemory(pPolicyEx->LocalIPV6,inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS].value.byteArray16, sizeof(FWP_BYTE_ARRAY16));
			// ntohV6(pPolicyEx->LocalIPV6);
			// pPolicyEx->LocalPort = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_PORT].value.uint16;
			// bIPV6 = TRUE;
			break;
		default:
			KdPrint(( "DenyWFPSend: NO LAYER layerId=%x\n",inFixedValues->layerId));
			// ExFreeToPagedLookasideList(&g_PagedFileName, pPolicyEx);
			return FALSE;
			break;

	}

// #if 0
// 	if(bIPV6)
// 	{
// 		//RtlIpv6AddressToStringW((in6_addr *)pPolicyEx->RemoteIPV6,pFilePolicy->FileName+384);
// 		KdPrint(("DenyWFPSend: Send layerId=%x,Pid=%d,lIp=%x,lPort=%d,rIp=%x-%x-%x-%x-%x-%x-%x-%x,rPort=%d\n",
// 			inFixedValues->layerId,
// 			PsGetCurrentProcessId(),
// 			pPolicyEx->LocalIP,
// 			pPolicyEx->LocalPort,
// 			pPolicyEx->RemoteIPV6[0],
// 			pPolicyEx->RemoteIPV6[1],
// 			pPolicyEx->RemoteIPV6[2],
// 			pPolicyEx->RemoteIPV6[3],
// 			pPolicyEx->RemoteIPV6[4],
// 			pPolicyEx->RemoteIPV6[5],
// 			pPolicyEx->RemoteIPV6[6],
// 			pPolicyEx->RemoteIPV6[7],
// 			pPolicyEx->RemotePort));
// 	}
// 	else
// 	{
//
// 		KdPrint(("DenyWFPSend: Send layerId=%x,Pid=%d,lIp=%d.%d.%d.%d,lPort=%d,rIP=%x,rPort=%d\n",
// 					inFixedValues->layerId,
// 					PsGetCurrentProcessId(),
// 					pPolicyEx->LocalIP >> 24,
// 					pPolicyEx->LocalIP >> 16 & 0xFF,
// 					pPolicyEx->LocalIP >> 8 & 0xFF,
// 					pPolicyEx->LocalIP & 0xFF,
// 					pPolicyEx->LocalPort,
// 					pPolicyEx->RemoteIP,
// 					pPolicyEx->RemotePort));
// 	}
//
// #endif
//
// 	CheckNetSendPolicy(pPolicyEx);
//
// 	if(FlagOn(pPolicyEx->nPolicy,NETPOLICY_NOSEND))
// 	{
// 		if(bIPV6)
// 		{
// 		KdPrint(("DenyWFPSend[DENY]: Send Denied,Pid=%d,LocalPort=%d,RemoteIp=%x-%x-%x-%x-%x-%x-%x-%x,port=%d\n",
// 			PsGetCurrentProcessId(),
// 			pPolicyEx->LocalPort,
// 			pPolicyEx->RemoteIPV6[0],
// 			pPolicyEx->RemoteIPV6[1],
// 			pPolicyEx->RemoteIPV6[2],
// 			pPolicyEx->RemoteIPV6[3],
// 			pPolicyEx->RemoteIPV6[4],
// 			pPolicyEx->RemoteIPV6[5],
// 			pPolicyEx->RemoteIPV6[6],
// 			pPolicyEx->RemoteIPV6[7],
// 			pPolicyEx->RemotePort));		
// 		}
// 		else
// 		{
// 		KdPrint(( "DenyWFPSend[DENY]: Send Denied,Pid=%d,LocalPort=%d,RemoteIp=%d.%d.%d.%d,port=%d\n",
// 			PsGetCurrentProcessId(),
// 			pPolicyEx->LocalPort,
// 			pPolicyEx->RemoteIP >> 24,
// 			pPolicyEx->RemoteIP >> 16 & 0xFF,
// 			pPolicyEx->RemoteIP >> 8 & 0xFF,
// 			pPolicyEx->RemoteIP & 0xFF,
// 			pPolicyEx->RemotePort));
// 		}
// 		ExFreeToPagedLookasideList(&g_PagedFileName, pPolicyEx);
// 		return TRUE;
// 	}
//
// 	ExFreeToPagedLookasideList(&g_PagedFileName, pPolicyEx);
	return FALSE;
}



//check send
void
NetSendCallout(
				  IN const FWPS_INCOMING_VALUES0* inFixedValues,
				  IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
				  IN OUT void* layerData,
				  IN const FWPS_FILTER0* filter,
				  IN UINT64 flowContext,
				  OUT FWPS_CLASSIFY_OUT0* classifyOut
				  )
				  /* ++

				  This is the classifyFn function for the Transport (v4 and v6) callout.
				  packets (inbound or outbound) are ueued to the packet queue to be processed 
				  by the worker thread.

				  -- */
{

	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(filter);

	//
	// We don't have the necessary right to alter the classify, exit.
	//
	
	if(!FlagOn(classifyOut->rights,FWPS_RIGHT_ACTION_WRITE))
	{
		KdPrint(( "NetSendCallout: no right, layerId=%x,Pid=%d\n",inFixedValues->layerId,inMetaValues->processId));
		return;
	}

	classifyOut->actionType = FWP_ACTION_PERMIT;

	// if(!g_NetPolicyNoSendNums)
	// {
	// 	return;
	// }
	ULONG Pid = 0;

	if(FlagOn(inMetaValues->currentMetadataValues,FWPS_METADATA_FIELD_PROCESS_ID))
	{
		Pid = (ULONG)inMetaValues->processId;
		KdPrint(( "NetSendCallout: currentMetadataValues=%x,Pid=%d,gPid=%d\n",inMetaValues->currentMetadataValues,Pid,PsGetCurrentProcessId()));
	}

	if(!Pid) 
	{
		Pid = (ULONG) PsGetCurrentProcessId();
//		KdPrint(( "NetSendCallout: Pid=%d,inPid=%d\n",Pid,inMetaValues->currentMetadataValues));
	}
	
	if(!Pid)
	{
		return;
	}

#if 0
#ifdef SUPPORT_MULTIUSER
	CUserCtx * pUserCtx = GetPidUserCtx(Pid);

	if(!pUserCtx)
	{
		return;
	}

	if((Pid == pUserCtx->RelatedPid)||(Pid == pUserCtx->OurProcessID) ||!pUserCtx->bStartFilter)
	{
		return;
	}
#else
	if((Pid == g_RelateProcessPid)||(Pid == g_OurProcessID)||!g_bStartFilter||(WORKMODE_NORMAL != g_WorkMode))
	{
		KdPrint(("NetSendCallout: PassSendPid, Pid=%d,OurThreadID=%d,RelateProcessPid=%d,OurProcessID=%d,bStartFilter=%x\n",Pid,g_OurThreadID,g_RelateProcessPid,g_OurProcessID,g_bStartFilter));
		return;
	}
#endif

	if(DenyWFPSend(inFixedValues))
	{
		classifyOut->actionType = FWP_ACTION_BLOCK;
		ClearFlag(classifyOut->rights,FWPS_RIGHT_ACTION_WRITE);
	}
#endif

	return;
}


NTSTATUS
NetSendNotify(
				IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
				IN const GUID* filterKey,
				IN const FWPS_FILTER0* filter
				)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	return STATUS_SUCCESS;
}


///////////////////

NTSTATUS
AddWFPFilter(
			 IN const wchar_t* filterName,
			 IN const wchar_t* filterDesc,
			 IN const GUID* layerKey,
			 IN const GUID* calloutKey
			 )
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_FILTER0 filter = {0};

	filter.layerKey = *layerKey;
	filter.displayData.name = (wchar_t*)filterName;
	filter.displayData.description = (wchar_t*)filterDesc;

	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	filter.action.calloutKey = *calloutKey;
	filter.subLayerKey = FILELOCK_NET_SUBLAYER;
	filter.weight.type = FWP_EMPTY; // auto-weight.
	filter.rawContext = 0;

	status = FwpmFilterAdd0(
		g_EngineHandle,
		&filter,
		NULL,
		NULL);

	KdPrint(("FwpmFilterAdd0: Name=%ws,status =%x\n",filterName,status));

	return status;
}


/* ++

This function registers callouts and filters at the following layers 
to intercept inbound or outbound connect attempts.
-- */

NTSTATUS
RegisterALEClassifyCallouts(
							IN const GUID* layerKey,
							IN const GUID* calloutKey,
							IN void* deviceObject,
							OUT UINT32* calloutId
							)

{
	NTSTATUS status = STATUS_SUCCESS;

	FWPS_CALLOUT0 sCallout = {0};
	FWPM_CALLOUT0 mCallout = {0};

	FWPM_DISPLAY_DATA0 displayData = {0};

	BOOLEAN calloutRegistered = FALSE;

	sCallout.calloutKey = *calloutKey;

	sCallout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN0)NetConnectCallout;
	sCallout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN0) NetConnectNotify;
	
	status = FwpsCalloutRegister0(
		deviceObject,
		&sCallout,
		calloutId
		);
	
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RegisterALEClassifyCallouts: FwpsCalloutRegister0 error,status =%x\n",status));
		goto Exit;
	}
	calloutRegistered = TRUE;

	displayData.name = L"FileLock ALE Callout";
	displayData.description = L"FileLock ALE Classify";

	mCallout.calloutKey = *calloutKey;
	mCallout.displayData = displayData;
	mCallout.applicableLayer = *layerKey;

	status = FwpmCalloutAdd0(
		g_EngineHandle,
		&mCallout,
		NULL,
		NULL
		);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("RegisterALEClassifyCallouts: FwpmCalloutAdd0 error,status =%x\n",status));
		goto Exit;
	}

	status = AddWFPFilter(
		L"FileLock ALE Filter",
		L"FileLock Network Filter for Windows",
		layerKey,
		calloutKey
		);

Exit:

	if (!NT_SUCCESS(status))
	{
		if (calloutRegistered)
		{
			FwpsCalloutUnregisterById0(*calloutId);
			*calloutId = 0;
		}
	}

	return status;
}

NTSTATUS
RegisterTransportCallouts(
						  IN const GUID* layerKey,
						  IN const GUID* calloutKey,
						  IN void* deviceObject,
						  OUT UINT32* calloutId
						  )
						  /* ++

						  This function registers callouts and filters that intercept transport 
						  traffic at the following layers --
						  //send
						  FWPM_LAYER_OUTBOUND_TRANSPORT_V4
						  FWPM_LAYER_OUTBOUND_TRANSPORT_V6
						  //recv
						  FWPM_LAYER_INBOUND_TRANSPORT_V4
						  FWPM_LAYER_INBOUND_TRANSPORT_V6

						  -- */
{
	NTSTATUS status = STATUS_SUCCESS;

	FWPS_CALLOUT0 sCallout = {0};
	FWPM_CALLOUT0 mCallout = {0};

	FWPM_DISPLAY_DATA0 displayData = {0};

	BOOLEAN calloutRegistered = FALSE;

	sCallout.calloutKey = *calloutKey;

	sCallout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN0)NetSendCallout;
	sCallout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN0)NetSendNotify;

	status = FwpsCalloutRegister0(
		deviceObject,
		&sCallout,
		calloutId
		);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RegisterTransportCallouts: FwpsCalloutRegister0 error,status =%x\n",status));
		goto Exit;
	}
	calloutRegistered = TRUE;

	displayData.name = L"Transport FileLock Callout";
	displayData.description = L"FileLock inbound/outbound transport traffic";

	mCallout.calloutKey = *calloutKey;
	mCallout.displayData = displayData;
	mCallout.applicableLayer = *layerKey;

	status = FwpmCalloutAdd0(
		g_EngineHandle,
		&mCallout,
		NULL,
		NULL
		);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("RegisterTransportCallouts: FwpmCalloutAdd0 error,status =%x\n",status));
		goto Exit;
	}

	status = AddWFPFilter(
		L"FileLock Filter",
		L"FileLock traffic",
		layerKey,
		calloutKey
		);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

Exit:

	if (!NT_SUCCESS(status))
	{
		if (calloutRegistered)
		{
			FwpsCalloutUnregisterById0(*calloutId);
			*calloutId = 0;
		}
	}

	return status;
}


/* ++

This function registers dynamic callouts and filters that intercept 
transport traffic at ALE AUTH_CONNECT/AUTH_RECV_ACCEPT and 
INBOUND/OUTBOUND transport layers.

Callouts and filters will be removed during DriverUnload.

-- */

NTSTATUS
RegisterCallouts(
				 IN void* deviceObject
				 )
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_SUBLAYER0 SubLayer;

	BOOLEAN engineOpened = FALSE;
	BOOLEAN inTransaction = FALSE;

	FWPM_SESSION0 session = {0};

	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	status = FwpmEngineOpen0(
		NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&session,
		&g_EngineHandle
		);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RegisterCallouts: FwpmEngineOpen0 error,status =%x\n", status));
		goto Exit;
	}

	engineOpened = TRUE;

	status = FwpmTransactionBegin0(g_EngineHandle, 0);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RegisterCallouts: FwpmTransactionBegin0 error,status =%x\n", status));
		goto Exit;
	}

	inTransaction = TRUE;

	RtlZeroMemory(&SubLayer, sizeof(FWPM_SUBLAYER0)); 

	SubLayer.subLayerKey = FILELOCK_NET_SUBLAYER;
	SubLayer.displayData.name = L"FileLock Sub-Layer";
	SubLayer.displayData.description = L"Sub-Layer of FileLock callouts";
	SubLayer.flags = 0;
	SubLayer.weight = 0; // must be less than the weight of 
	// FWPM_SUBLAYER_UNIVERSAL to be
	// compatible with Vista's IpSec
	// implementation.

	status = FwpmSubLayerAdd0(g_EngineHandle, &SubLayer, NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RegisterCallouts: FwpmSubLayerAdd0 error,status =%x\n", status));
		goto Exit;
	}

	/*
	https://docs.microsoft.com/zh-cn/windows/desktop/FWP/filter-arbitration
	UDP:
	sendto: FWPM_LAYER_ALE_AUTH_CONNECT_V4
	data: FWPM_LAYER_DATAGRAM_DATA_V4
	TCP:
	connect: FWPM_LAYER_ALE_AUTH_CONNECT_V4
	data: FWPM_LAYER_STREAM_V4
	TCP segments: FWPM_LAYER_OUTBOUND_TRANSPORT_V4
	*/
	//filter RemoteAddrV4

	status = RegisterALEClassifyCallouts(
		&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
		&FILELOCK_NET_ALE_FLOW_ESTABLISHED_V4,
		deviceObject,
		&g_AleEstablishedCalloutIdV4
		);
	
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RegisterCallouts: FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4 error,status =%x\n", status));
		goto Exit;
	}
	
	status = RegisterALEClassifyCallouts(
		&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
		&FILELOCK_NET_ALE_FLOW_ESTABLISHED_V6,
		deviceObject,
		&g_AleEstablishedCalloutIdV6
		);
	
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RegisterCallouts: FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6 error,status =%x\n", status));
		goto Exit;
	}

	status = RegisterTransportCallouts(
		&FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
		&FILELOCK_NET_OUTBOUND_TRANSPORT_CALLOUT_V4,
		deviceObject,
		&g_OutboundTlCalloutIdV4
		);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RegisterCallouts: FWPM_LAYER_OUTBOUND_TRANSPORT_V4 error,status =%x\n", status));
		goto Exit;
	}

	status = RegisterTransportCallouts(
		&FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
		&FILELOCK_NET_OUTBOUND_TRANSPORT_CALLOUT_V6,
		deviceObject,
		&g_OutboundTlCalloutIdV6
		);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RegisterCallouts: FWPM_LAYER_OUTBOUND_TRANSPORT_V6 error,status =%x\n", status));
		goto Exit;
	}

	status = FwpmTransactionCommit0(g_EngineHandle);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("RegisterCallouts: FwpmTransactionCommit0 error,status =%x\n", status));
		goto Exit;
	}
	inTransaction = FALSE;

Exit:

	if (!NT_SUCCESS(status))
	{
		if (inTransaction)
		{
			FwpmTransactionAbort0(g_EngineHandle);
		}
		if (engineOpened)
		{
			FwpmEngineClose0(g_EngineHandle);
			g_EngineHandle = NULL;
		}
	}

	return status;
}

void
UnregisterCallouts()
{
	FwpmEngineClose0(g_EngineHandle);
	g_EngineHandle = NULL;

	FwpsCalloutUnregisterById0(g_OutboundTlCalloutIdV6);
	FwpsCalloutUnregisterById0(g_OutboundTlCalloutIdV4);

	FwpsCalloutUnregisterById0(g_AleEstablishedCalloutIdV6);
	FwpsCalloutUnregisterById0(g_AleEstablishedCalloutIdV4);
}

VOID
WFPUnload(
		  IN  PDRIVER_OBJECT driverObject
		  )
{

	UNREFERENCED_PARAMETER(driverObject);

	KdPrint(("WFPUnload: called\n"));

	UnregisterCallouts();

	IoDeleteDevice(g_DeviceObjectWFP);

}


NTSTATUS
DriverEntry(
			   IN  PDRIVER_OBJECT  driverObject,
			   IN  PUNICODE_STRING registryPath
			   )
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING deviceName;

	RtlInitUnicodeString(
		&deviceName,
		L"\\Device\\FileLockNet"
		);

	status = IoCreateDevice(
		driverObject, 
		0, 
		&deviceName, 
		FILE_DEVICE_NETWORK, 
		FILE_DEVICE_SECURE_OPEN, 
		FALSE, 
		&g_DeviceObjectWFP
		);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("DriverEntryWFP: Create device =%wZ failed,status =%x\n",&deviceName, status));
		goto Exit;
	}

	status = RegisterCallouts(g_DeviceObjectWFP);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("DriverEntryWFP: RegisterCallouts failed,status =%x\n",status));
		goto Exit;
	}

//	driverObject->DriverUnload = WFPUnload;

Exit:

	if (!NT_SUCCESS(status))
	{
		if (g_EngineHandle != NULL)
		{
			UnregisterCallouts();
		}

		if (g_DeviceObjectWFP)
		{
			IoDeleteDevice(g_DeviceObjectWFP);
		}
	}
	KdPrint(("DriverEntryWFP: status =%x\n",status));
	return status;
}
}
#endif
