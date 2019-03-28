#include "zmodule.h"
#include "wmi.h"
#include "win32stream.h"

/* Maximum number of arguments for a member */
#define DH_MAX_ARGS 25

/* Maximum length of a member string */
#define DH_MAX_MEMBER 512

HRESULT __cdecl wmi_extract_arg(VARIANT* pvArg, char vType, BOOL* pbFreeArg, va_list* marker)
{
    HRESULT hr = NOERROR;

    *pbFreeArg = FALSE;

    switch (vType) {
        case 'w':
            V_VT(pvArg) = VT_UI2;
            V_UI2(pvArg) = va_arg(*marker, WORD);
            break;
        case 'd':
            V_VT(pvArg) = VT_I4;
            V_I4(pvArg) = va_arg(*marker, LONG);
            break;
        case 'u':
            V_VT(pvArg) = VT_UI4;
            V_UI4(pvArg) = va_arg(*marker, ULONG);
            break;
        case 'q':
            V_VT(pvArg) = VT_UI8;
            V_UI8(pvArg) = va_arg(*marker, ULONG64);
            break;
        case 'e':
            V_VT(pvArg) = VT_R8;
            V_R8(pvArg) = va_arg(*marker, DOUBLE);
            break;
        case 'b':
            V_VT(pvArg) = VT_BOOL;
            V_BOOL(pvArg) = ( va_arg(*marker, BOOL) ? VARIANT_TRUE : VARIANT_FALSE );
            break;
        case 'm':
            V_VT(pvArg) = VT_ERROR;
            V_ERROR(pvArg) = DISP_E_PARAMNOTFOUND;
            break;
        case 'S':
            {
                LPOLESTR szTemp = va_arg(*marker, LPOLESTR);

                V_VT(pvArg) = VT_BSTR;
                V_BSTR(pvArg) = fn_SysAllocString(szTemp);

                if (V_BSTR(pvArg) == NULL && szTemp != NULL) hr = E_OUTOFMEMORY;

                *pbFreeArg = TRUE;
                break;
            }
        case 'o':
            V_VT(pvArg) = VT_DISPATCH;
            V_DISPATCH(pvArg) = va_arg(*marker, IDispatch *);
            break;
        case 'p':
#ifndef _WIN64
            V_VT(pvArg) = VT_I4;
            V_I4(pvArg) = (LONG) va_arg(*marker, LPVOID);
#else
            V_VT(pvArg) = VT_I8;
            V_I8(pvArg) = (LONGLONG) va_arg(*marker, LPVOID);
#endif
            break;
        default:
            hr = E_INVALIDARG;
            break;
    }

    return hr;
}

HRESULT __cdecl wmi_get_value(char vType, void* pResult, IDispatch* pDisp, LPCOLESTR szMember, ...)
{
    HRESULT hr = NOERROR;
    va_list marker;
    VARIANT vtResult;
    VARTYPE returnType;
    wchar_t szCopy[DH_MAX_MEMBER];
    LPWSTR szTemp = szCopy;
    SIZE_T cchDest = ARRAYSIZE(szCopy);
    VARIANT vtArgs[DH_MAX_ARGS];
    BOOL bFreeList[DH_MAX_ARGS];
    UINT cArgs, iArg = DH_MAX_ARGS;
    BOOL bInArguments = FALSE;
    DISPPARAMS dp  = { 0 };
    DISPID dispID;
    UINT uiArgErr;

    va_start(marker, szMember);

    if (pResult == NULL || pDisp == NULL || szMember == NULL) {
        return E_INVALIDARG;
    }

    switch (vType) {
        case 'w': returnType = VT_UI2; break;
        case 'd': returnType = VT_I4; break;
        case 'u': returnType = VT_UI4; break;
        case 'q': returnType = VT_UI8; break;
        case 'e': returnType = VT_R8; break;
        case 'b': returnType = VT_BOOL; break;
        case 'S': returnType = VT_BSTR; break;
        case 'o': returnType = VT_DISPATCH; break;
#ifndef _WIN64
        case 'p': returnType = VT_I4; break;
#else
        case 'p': returnType = VT_I8; break;
#endif
        default:
            return E_INVALIDARG;
    }

    do {
        if (cchDest-- == 0) {
            return E_INVALIDARG;
        }
    } while (*szTemp++ = *szMember++);

    pDisp->lpVtbl->AddRef(pDisp);

    for (szTemp = szCopy; *szTemp; ++szTemp) {
        if (!bInArguments && (*szTemp == L'(' || *szTemp == L' ' || *szTemp == L'=') ) {
            bInArguments = TRUE;

            *szTemp = L'\0';
        }
        else if  (*szTemp == L'%') {
            if (!bInArguments) {
                bInArguments = TRUE;
                *szTemp = L'\0';
            }

            if (--iArg == -1) {
                hr = E_INVALIDARG;
                break;
            }

            ++szTemp;

            hr = wmi_extract_arg(&vtArgs[iArg], (char)*szTemp, &bFreeList[iArg], &marker);

            if (FAILED(hr)) {
                break;
            }
        }
    }

    if (SUCCEEDED(hr)) {
        cArgs = DH_MAX_ARGS - iArg;
        szTemp = szCopy;
        hr = pDisp->lpVtbl->GetIDsOfNames(pDisp, &IID_NULL, (LPOLESTR*)&szTemp, 1, LOCALE_USER_DEFAULT, &dispID);

        if (SUCCEEDED(hr)) {
            fn_VariantInit(&vtResult);

            dp.cArgs  = cArgs;
            dp.rgvarg = &vtArgs[DH_MAX_ARGS - cArgs];

            hr = pDisp->lpVtbl->Invoke(pDisp, dispID, &IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET|DISPATCH_METHOD, &dp, &vtResult, NULL, &uiArgErr);
        }

        for (iArg = DH_MAX_ARGS - cArgs; iArg < DH_MAX_ARGS; ++iArg) {
            if (bFreeList[iArg]) {
                fn_VariantClear(&vtArgs[iArg]);
            }
        }

        if (SUCCEEDED(hr) && vtResult.vt != returnType && returnType != VT_EMPTY) {
            hr = fn_VariantChangeType(&vtResult, &vtResult, 16 , returnType);
            if (FAILED(hr)) {
                fn_VariantClear(&vtResult);
            }
        }
    }
    else {
        for (++iArg; iArg < DH_MAX_ARGS; ++iArg) {
            if (bFreeList[iArg]) {
                fn_VariantClear(&vtArgs[iArg]);
            }
        }
    }

    pDisp->lpVtbl->Release(pDisp);

    if (FAILED(hr)) {
        return hr;
    }

    switch (vType) {
        case 'w':
            *((WORD*)pResult) = V_UI2(&vtResult);
            break;
        case 'd':
            *((LONG*) pResult) = V_I4(&vtResult);
            break;
        case 'u':
            *((ULONG*)pResult) = V_UI4(&vtResult);
            break;
        case 'q':
            *((ULONG64*)pResult) = V_UI8(&vtResult);
            break;
        case 'e':
            *((DOUBLE*) pResult) = V_R8(&vtResult);
            break;
        case 'b':
            *((BOOL*) pResult) = V_BOOL(&vtResult);
            break;
        case 'S':
            *((LPWSTR*) pResult) = V_BSTR(&vtResult);
            break;
        case 'o':
            *((IDispatch**) pResult) = V_DISPATCH(&vtResult);
            if (V_DISPATCH(&vtResult) == NULL) hr = E_NOINTERFACE;
            break;
        case 'p':
#ifndef _WIN64
            *((LPVOID *) pResult) = (LPVOID) V_I4(&vtResult);
#else
            *((LPVOID *) pResult) = (LPVOID) V_I8(&vtResult);
#endif
            break;
    }

    va_end(marker);

    return hr;
}

HRESULT __stdcall wmi_enum_begin(IEnumVARIANT** ppEnum, IDispatch* pDisp)
{
    HRESULT hr;
    DISPPARAMS dp = {0};
    VARIANT vtResult;

    if (pDisp == NULL) {
        return E_INVALIDARG;
    }

    hr = pDisp->lpVtbl->Invoke(pDisp, DISPID_NEWENUM, &IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD | DISPATCH_PROPERTYGET, &dp, &vtResult, NULL, NULL);

    if (FAILED(hr)) {
        return hr;
    }

    if (vtResult.vt == VT_DISPATCH) {
        hr = vtResult.pdispVal->lpVtbl->QueryInterface(vtResult.pdispVal, &IID_IEnumVARIANT, (void **) ppEnum);
    }
    else if (vtResult.vt == VT_UNKNOWN) {
        hr = vtResult.punkVal->lpVtbl->QueryInterface(vtResult.punkVal, &IID_IEnumVARIANT, (void **) ppEnum);
    }
    else {
        hr = E_NOINTERFACE;
    }

    fn_VariantClear(&vtResult);

    return hr;
}

HRESULT __stdcall wmi_enum_next(IEnumVARIANT* pEnum, IDispatch** ppDisp)
{
    VARIANT vtResult;
    HRESULT hr;

    if (pEnum == NULL) {
        return E_INVALIDARG;
    }

    hr = pEnum->lpVtbl->Next(pEnum, 1, &vtResult, NULL);

    if (hr == S_OK) {
        if (vtResult.vt == VT_DISPATCH) {
            *ppDisp = vtResult.pdispVal;
        }
        else {
            hr = fn_VariantChangeType(&vtResult, &vtResult, 0, VT_DISPATCH);
            if (SUCCEEDED(hr)) {
                *ppDisp = vtResult.pdispVal;
            }
            else {
                fn_VariantClear(&vtResult);
            }
        }
    }

    return hr;
}


IDispatch* __stdcall wmi_get_service(const wchar_t* name)
{
	IDispatch* pWmiService = NULL;
	if (FAILED(fn_CoGetObject(name, NULL, &IID_IDispatch, &pWmiService))) {
		return NULL;
	}
	return pWmiService;
}

int __stdcall wmi_obtain_info(IDispatch* pWmiService, pvoid_t pWmiClass)
{
	int ret = 0;
    wchar_t selectBuffer[128];
    IDispatch* pServiceLocator = NULL;
	wmi_class_info_t* pClassInfo = (wmi_class_info_t*)pWmiClass;
	IEnumVARIANT * pServiceEnumerator = NULL;
	IDispatch* pServiceItem = NULL;
	wmi_class_property_t* pClassPropInfo;

	do {
		fn_lstrcpyW(selectBuffer, L"SELECT * FROM ");
		fn_lstrcatW(selectBuffer, pClassInfo->className);

		if (FAILED(wmi_get_value('o', &pServiceLocator, pWmiService, L"ExecQuery(%S)", selectBuffer))) {
			break;
		}

		if (SUCCEEDED(wmi_enum_begin(&pServiceEnumerator, pServiceLocator))) {
			while (!ret && wmi_enum_next(pServiceEnumerator, &pServiceItem) == NOERROR) {
				__stosb((uint8_t*)pClassInfo->pStruct, 0, pClassInfo->structSize);

				for (pClassPropInfo = pClassInfo->pClassProperties; pClassPropInfo->identifierType != 0; ++pClassPropInfo) {
					wmi_get_value(pClassPropInfo->identifierType, pClassPropInfo->pResult, pServiceItem, pClassPropInfo->propertyName);
				}

				ret = pClassInfo->fnWmiHandler(pClassInfo);
				
				pClassPropInfo = pClassInfo->pClassProperties;				
				for (; pClassPropInfo->identifierType != 0; ++pClassPropInfo) {
					if (pClassPropInfo->identifierType == 'S') {
						fn_SysFreeString(*(BSTR*)pClassPropInfo->pResult);
					}
				}

				pServiceItem->lpVtbl->Release(pServiceItem);
				pServiceItem = NULL;
				
			}
			if (pServiceItem != NULL) {
				pServiceItem->lpVtbl->Release(pServiceItem);
			}
			pServiceEnumerator->lpVtbl->Release(pServiceEnumerator);
		}
	} while (0);

    if (pServiceLocator != NULL) {
        pServiceLocator->lpVtbl->Release(pServiceLocator);
    }
	return ret;
}
