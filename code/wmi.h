#ifndef __COMMON_WMI_H_
#define __COMMON_WMI_H_

typedef struct _wmi_class_property
{
	char identifierType;
	void* pResult;
	wchar_t* propertyName;
} wmi_class_property_t;

struct _wmi_class_info;
typedef int(__stdcall *FnWmiHandler)(struct _wmi_class_info* pInstance);

typedef struct _wmi_class_info
{
	wchar_t className[32];
	void* pStruct;
	uint32_t structSize;
	FnWmiHandler fnWmiHandler;
	wmi_class_property_t* pClassProperties;
} wmi_class_info_t;

HRESULT __cdecl wmi_extract_arg(VARIANT* pvArg, char vType, BOOL* pbFreeArg, va_list* marker);
HRESULT __cdecl wmi_get_value(char vType, void* pResult, IDispatch* pDisp, LPCOLESTR szMember, ...);
HRESULT __stdcall wmi_enum_begin(IEnumVARIANT** ppEnum, IDispatch* pDisp);
HRESULT __stdcall wmi_enum_next(IEnumVARIANT* pEnum, IDispatch** ppDisp);
IDispatch* __stdcall wmi_get_service(const wchar_t* name);
int __stdcall wmi_obtain_info(IDispatch* pWmiService, pvoid_t pWmiClass);

#endif // __COMMON_WMI_H_
