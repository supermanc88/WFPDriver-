#ifdef __cplusplus
extern "C" {
#endif

#include "wfptest.h"
// #define INITGUID
#include <guiddef.h>


#define LOG_STRING "WFPDriver: "
#define WFP_DEVICE_NAME L"\\Device\\WFPDriver_Device"
#define WFP_SYM_LINK_NAME L"\\DosDevices\\WFPDriver_Device_SYM"

#define MyKdPrint(_x_)\
	KdPrint((LOG_STRING));\
	KdPrint(_x_)

PDEVICE_OBJECT g_DeviceObject = NULL;
HANDLE g_hEngine = NULL;
UINT32 g_RegisterCalloutId = 0;
UINT32 g_AddCalloutId = 0;
UINT64 g_FilterId = 0;



VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	MyKdPrint(("驱动卸载\n"));
	UNICODE_STRING SymbolicName;
	RtlInitUnicodeString(&SymbolicName, WFP_SYM_LINK_NAME);
	IoDeleteSymbolicLink(&SymbolicName);
	MyKdPrint(("删除符号链接\n"));

	if(g_DeviceObject)
	{
		IoDeleteDevice(g_DeviceObject);
		MyKdPrint(("删除设备\n"));
	}
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = STATUS_SUCCESS;

	MyKdPrint(("Enter DriverEntry"));

	DriverObject->DriverUnload = DriverUnload;

	//开始创建WFP所使用的设备对象

	UNICODE_STRING DeviceName;
	UNICODE_STRING SymbolicName;
	RtlInitUnicodeString(&DeviceName, WFP_DEVICE_NAME);
	RtlInitUnicodeString(&SymbolicName, WFP_SYM_LINK_NAME);

	status = IoCreateDevice(DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&g_DeviceObject);

	if(!NT_SUCCESS(status))
	{
		return status;
	}

	MyKdPrint(("设备对象创建成功\n"));

	IoCreateSymbolicLink(&SymbolicName, &DeviceName);

	return status;
}

/*
 * 这里初始化WFP
 * 打开Filter引擎
 * 注册和添加Callout
 * 添加子层
 * 添加过滤器
 */
NTSTATUS InitWFP()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	do
	{
		g_hEngine = OpenFilterEngine();
		if(g_hEngine == NULL)
		{
			break;
		}
		if(!NT_SUCCESS(WFPRegisterCallouts(g_DeviceObject)))
		{
			break;
		}
		if(NT_SUCCESS(WFPAddCallouts()))
		{
			break;
		}
		if(NT_SUCCESS(WFPAddSubLayers()))
		{
			break;
		}
		if(NT_SUCCESS(WFPAddFilter()))
		{
			break;
		}
	}
	while (false);

	return status;
}
NTSTATUS WFPRegisterCallouts(PDEVICE_OBJECT DeviceObject)
{
	FWPS_CALLOUT1 callout = { 0 };
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UINT32 calloutId;

	callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
	callout.flags = 0;
	callout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN1)WFPClassifyFn1;
	callout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN1)WFPNotifyFn1;
	callout.flowDeleteFn = WFPFlowDeleteFn;

	status = FwpsCalloutRegister1(g_DeviceObject, &callout, &calloutId);

	g_RegisterCalloutId = calloutId;

	return status;
}

NTSTATUS WFPAddCallouts()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UINT32 calloutId = 0;

	FWPM_CALLOUT callout = { 0 };
	// 添加callout之前一定要确认Filter引擎是否打开
	if(g_hEngine == NULL)
	{
		return status;
	}

	callout.displayData.name = (wchar_t*)L"WFPCalloutName";
	callout.displayData.description = (wchar_t*)L"WFPCalloutDesc";
	// 关联到刚才注册的callout
	callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
	//需要把这个callout应用到哪个Filter Layer上
	// 具体参考 https://docs.microsoft.com/zh-cn/windows/desktop/FWP/management-filtering-layer-identifiers-
	callout.applicableLayer = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;

	FwpmCalloutAdd0(g_hEngine, &callout, NULL, &calloutId);

	g_AddCalloutId = calloutId;

	return status;
}

HANDLE OpenFilterEngine()
{
	FWPM_SESSION0 session = { 0 };
	HANDLE hEngine = NULL;
	FwpmEngineOpen0(NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&session,
		&hEngine);
	return hEngine;
}

NTSTATUS WFPAddSubLayers()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	FWPM_SUBLAYER subLayer = { 0 };
	subLayer.flags = 0;
	subLayer.displayData.description = (wchar_t*)L"WFPSubLayerDesc";
	subLayer.displayData.name = (wchar_t*)L"WFPSubLayerName";
	subLayer.subLayerKey = WFP_SAMPLE_SUBLAYER_GUID;
	subLayer.weight = 65535;

	if(g_hEngine)
	{
		status = FwpmSubLayerAdd0(g_hEngine, &subLayer, NULL);
	}

	return status;
}

NTSTATUS WFPAddFilter()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	FWPM_FILTER0 filter = { 0 };
	FWPM_FILTER_CONDITION0 filterCondition[1] = { 0 };
	UINT64 filterId;

	if(g_hEngine == NULL)
	{
		return status;
	}

	filter.displayData.name = (wchar_t*)L"WPFFilterName";
	filter.displayData.description = (wchar_t*)L"WPFFilterDesc";
	filter.flags = 0;
	// 关联分层
	filter.layerKey = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
	// 关联子层
	filter.subLayerKey = WFP_SAMPLE_SUBLAYER_GUID;
	filter.weight.type = FWP_EMPTY;
	filter.numFilterConditions = 1;
	filter.filterCondition = filterCondition;
	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	// 关联callout
	filter.action.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;


	status = FwpmFilterAdd(g_hEngine, &filter, NULL, &filterId);

	g_FilterId = filterId;

	if(NT_SUCCESS(status))
	{
		return status;
	}


	return status;
}


VOID UnInitWFP()
{
	CloseFilterEngine();
	WFPRemoveFilter();
	WFPRemoveSubLayers();
	WFPRemoveCallouts();
	WFPUnRegisterCallouts();
}

VOID CloseFilterEngine()
{
	if(g_hEngine)
	{
		FwpmEngineClose0(g_hEngine);
	}
	g_hEngine = NULL;
}

VOID WFPUnRegisterCallouts()
{
	if(g_hEngine)
	{
		FwpsCalloutUnregisterById0(g_RegisterCalloutId);
	}
}

VOID WFPRemoveCallouts()
{
	if(g_hEngine)
	{
		FwpmCalloutDeleteById0(g_hEngine, g_AddCalloutId);
	}
}

VOID WFPRemoveSubLayers()
{
	if(g_hEngine)
	{
		FwpmSubLayerDeleteByKey(g_hEngine, &WFP_SAMPLE_SUBLAYER_GUID);
	}
}

VOID WFPRemoveFilter()
{
	if(g_hEngine)
	{
		FwpmFilterDeleteById0(g_hEngine, g_FilterId);
	}
}

void WFPClassifyFn1(
	const FWPS_INCOMING_VALUES0 *inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
	void *layerData,
	const void *classifyContext,
	const FWPS_FILTER1 *filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT0 *classifyOut
)
{
	MyKdPrint(("Enter WFPClassifyFn1\n"));

	classifyOut->actionType = FWP_ACTION_PERMIT;
}

NTSTATUS WFPNotifyFn1(
	FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	const GUID *filterKey,
	FWPS_FILTER1 *filter
)
{
	MyKdPrint(("Enter WFPNotifyFn1\n"));
	return STATUS_SUCCESS;
}

VOID NTAPI
WFPFlowDeleteFn(
	IN UINT16  layerId,
	IN UINT32  calloutId,
	IN UINT64  flowContext
)
{
	MyKdPrint(("Enter WFPFlowDeleteFn\n"));
}


#ifdef __cplusplus
}
#endif
