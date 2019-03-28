#include "zmodule.h"
#include "privilege.h"
#include "memory.h"
#include "logger.h"

NTSTATUS __stdcall privelege_enable(HANDLE hToken, const char* privName)
{
	TOKEN_PRIVILEGES tpk;
	LUID luid;

	if (!fn_LookupPrivilegeValueA(NULL, privName, &luid)) {
		return native_last_status();
	}

	// adjust the privileges of the current process to include the shutdown privilege
	tpk.PrivilegeCount = 1;
	tpk.Privileges[0].Luid = luid;
	tpk.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!fn_AdjustTokenPrivileges(hToken, FALSE, &tpk, 0, NULL, NULL)) {
		return native_last_status();
	}

	return STATUS_SUCCESS;
}

uint32_t __stdcall privilege_check_sid_in_groups(PTOKEN_GROUPS groups, DWORD subAuthority1)
{
	uint32_t i;
	uint32_t mask = 0;
	BYTE sidBuffer[256];
	PSID pSID = (PSID)&sidBuffer;
	SID_IDENTIFIER_AUTHORITY sidAuth = SECURITY_NT_AUTHORITY;

	if (!fn_AllocateAndInitializeSid(&sidAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, subAuthority1, 0, 0, 0, 0, 0, 0, &pSID)) {
		LOG("AllocateAndInitializeSid failed with error 0x%08X", fn_GetLastError());
		return mask;
	}

	// Loop through the group SIDs looking for the administrator SID.
	for (i = 0; i < groups->GroupCount; ++i) {
		if (fn_EqualSid(pSID, groups->Groups[i].Sid)) {
			if (groups->Groups[i].Attributes & SE_GROUP_ENABLED) {
				mask |= 2;
			}
			else if (groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY) {
				mask |= 1;
			}
		}
	}

	if (pSID != NULL) {
		fn_FreeSid(pSID);
	}

	return mask;
}

uint32_t __stdcall privelege_get_security_mask(HANDLE hToken)
{
	PTOKEN_GROUPS groups;
	PTOKEN_MANDATORY_LABEL mandatoryLabel;
	uint32_t securityMask = 0;
	uint32_t groupVal;
	ULONG subAuthority;
	ULONG returnLength;
	TOKEN_ELEVATION elevation;

	do {
		if (!NT_SUCCESS(native_query_token_variable_size(hToken, TokenGroups, &groups))) {
			LOG("GetTokenInformation(TokenGroups) failed with error 0x%08X", native_last_status());
			break;
		}

		groupVal = privilege_check_sid_in_groups(groups, DOMAIN_ALIAS_RID_ADMINS);
		if (groupVal > 0) {
			LOG("Running with admin rights (Full: %s)", (groupVal & 2 ? "yes" : "no"));
			securityMask |= ACCESS_ADMIN | (groupVal & 2 ? ACCESS_FULL : 0);
		}
		else {
			groupVal = privilege_check_sid_in_groups(groups, DOMAIN_ALIAS_RID_GUESTS);
			if (groupVal > 0) {
				securityMask |= ACCESS_GUEST | (groupVal & 2 ? ACCESS_FULL : 0);
				LOG("Running with guest rights (Full: %s)", (groupVal & 2 ? "yes" : "no"));
			}
			else {
				groupVal = privilege_check_sid_in_groups(groups, DOMAIN_ALIAS_RID_USERS);
				if (groupVal > 0) {
					LOG("Running with user rights (Full: %s)", (groupVal & 2 ? "yes" : "no"));
					securityMask |= ACCESS_USER | (groupVal & 2 ? ACCESS_FULL : 0);
				}
			}
		}		
	} while (0);

	if (groups != NULL) {
		memory_free(groups);
	}
	
	do {
		if (!NT_SUCCESS(native_query_token_variable_size(hToken, TokenIntegrityLevel, &mandatoryLabel))) {
			LOG("GetTokenInformation(TokenGroups) failed with error 0x%08X", native_last_status());
			break;
		}

		subAuthority = *fn_RtlSubAuthoritySid(mandatoryLabel->Label.Sid, 0);
		switch (subAuthority) {
			case SECURITY_MANDATORY_UNTRUSTED_RID:
				LOG("Running with Untrusted integrity level");
				securityMask |= MANDATORY_LEVEL_UNTRUSTED;
				break;
			case SECURITY_MANDATORY_LOW_RID:
				LOG("Running with Low integrity level");
				securityMask |= MANDATORY_LEVEL_LOW;
				break;
			case SECURITY_MANDATORY_MEDIUM_RID:
				LOG("Running with Medium integrity level");
				securityMask |= MANDATORY_LEVEL_MEDIUM;
				break;
			case SECURITY_MANDATORY_HIGH_RID:
				LOG("Running with High integrity level");
				securityMask |= MANDATORY_LEVEL_HIGH;
				break;
			case SECURITY_MANDATORY_SYSTEM_RID:
				LOG("Running with System integrity level");
				securityMask |= MANDATORY_LEVEL_SYSTEM;
				break;
			case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:
				LOG("Running with Protected integrity level");
				securityMask |= MANDATORY_LEVEL_SECUREPROCESS;
				break;
		}
	} while (0);

	if (mandatoryLabel != NULL) {
		memory_free(mandatoryLabel);
	}

	if (NT_SUCCESS(fn_NtQueryInformationToken(hToken, TokenElevation, &elevation, sizeof(TOKEN_ELEVATION), &returnLength))) {
		if (!!elevation.TokenIsElevated) {
			LOG("Running as Elevated process");
			securityMask |= IS_ELEVATED;
		}
	}

    if (_pZmoduleBlock->sysInfo.osMajorVer <= 5) {
        // Ёмулируем IntegrityLevel дл€ XP.
        if (securityMask & ACCESS_ADMIN) {
            LOG("Running with Emulated High integrity level (XP)");
            securityMask |= (securityMask & ACCESS_FULL) ? MANDATORY_LEVEL_HIGH : MANDATORY_LEVEL_MEDIUM;
        }
        else if (securityMask & ACCESS_USER) {
            LOG("Running with Emulated Medium integrity level (XP)");
            securityMask |= MANDATORY_LEVEL_MEDIUM;
        }
        else {
            LOG("Running with Emulated Low integrity level (XP)");
            securityMask |= MANDATORY_LEVEL_LOW;
        }
    }

	return securityMask;
}
