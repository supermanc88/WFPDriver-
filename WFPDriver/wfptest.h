#pragma once
#ifndef _WFPTEST_H_
#define _WFPTEST_H_

#include <ntddk.h>
#include <ndis.h>
#include <fwpmk.h>
#include <fwpsk.h>
#include <Fwpmu.h>
#include "initguid.h"


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

HANDLE OpenFilterEngine();
NTSTATUS WFPRegisterCallouts(PDEVICE_OBJECT DeviceObject);
NTSTATUS WFPAddCallouts();
NTSTATUS WFPAddSubLayers();
NTSTATUS WFPAddFilter();

VOID UnInitWFP();
VOID CloseFilterEngine();
VOID WFPUnRegisterCallouts();
VOID WFPRemoveCallouts();
VOID WFPRemoveSubLayers();
VOID WFPRemoveFilter();

void WFPClassifyFn1(
	const FWPS_INCOMING_VALUES0 *inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
	void *layerData,
	const void *classifyContext,
	const FWPS_FILTER1 *filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT0 *classifyOut
	);

NTSTATUS WFPNotifyFn1(
	FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	const GUID *filterKey,
	FWPS_FILTER1 *filter
	);

VOID NTAPI
WFPFlowDeleteFn(
	IN UINT16  layerId,
	IN UINT32  calloutId,
	IN UINT64  flowContext
);



// {D969FC67-6FB2-4504-91CE-A97C3C32AD36}
DEFINE_GUID(WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID, 0xd969fc67, 0x6fb2, 0x4504, 0x91, 0xce, 0xa9, 0x7c, 0x3c, 0x32, 0xad, 0x36);

// {ED6A516A-36D1-4881-BCF0-ACEB4C04C21C}
DEFINE_GUID(WFP_SAMPLE_SUBLAYER_GUID, 
			0xed6a516a, 0x36d1, 0x4881, 0xbc, 0xf0, 0xac, 0xeb, 0x4c, 0x4, 0xc2, 0x1c);
#endif
