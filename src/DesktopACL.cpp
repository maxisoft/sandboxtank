// copy pasted from
// https://www.installsetupconfig.com/win32programming/windowstationsdesktops13_4.html
#include "DesktopACL.h"
#include <sddl.h>

#define RTN_OK     0
#define RTN_ERROR 13

constexpr ACCESS_MASK WINSTA_ALL = (WINSTA_ACCESSCLIPBOARD | WINSTA_ACCESSGLOBALATOMS |
	WINSTA_CREATEDESKTOP | WINSTA_ENUMDESKTOPS |
	WINSTA_ENUMERATE | WINSTA_EXITWINDOWS |
	WINSTA_READATTRIBUTES | WINSTA_READSCREEN |
	WINSTA_WRITEATTRIBUTES | DELETE |
	READ_CONTROL | WRITE_DAC |
	WRITE_OWNER);

constexpr DWORD DESKTOP_ALL = (DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW |
	DESKTOP_ENUMERATE | DESKTOP_HOOKCONTROL |
	DESKTOP_JOURNALPLAYBACK | DESKTOP_JOURNALRECORD |
	DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP |
	DESKTOP_WRITEOBJECTS | DELETE |
	READ_CONTROL | WRITE_DAC |
	WRITE_OWNER);

constexpr ACCESS_MASK GENERIC_ACCESS = (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);

namespace maxisoft::sandbox
{

	
	std::wstring ObtainUserSidString(HANDLE hToken)
	{
		std::wstring ret{};
		PTOKEN_USER ptu = NULL;
		DWORD dwSize = 0;
		if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize)
			&& ERROR_INSUFFICIENT_BUFFER != GetLastError())
		{
			return FALSE;
		}
		if (NULL != (ptu = (PTOKEN_USER)LocalAlloc(LPTR, dwSize)))
		{
			LPTSTR StringSid = NULL;
			if (!GetTokenInformation(hToken, TokenUser, ptu, dwSize, &dwSize))
			{
				LocalFree((HLOCAL)ptu);
				return FALSE;
			}
			if (ConvertSidToStringSid(ptu->User.Sid, &StringSid))
			{
				ret = StringSid;
				LocalFree((HLOCAL)StringSid);
				LocalFree((HLOCAL)ptu);
				return ret;
			}
			LocalFree((HLOCAL)ptu);
		}
		return ret;
	}


	BOOL ObtainSid(HANDLE hToken, PSID *psid)

	{
		BOOL                    bSuccess = FALSE; // assume function will
												  // fail
		DWORD                   dwIndex;
		DWORD                   dwLength = 0;
		TOKEN_INFORMATION_CLASS tic = TokenGroups;
		PTOKEN_GROUPS           ptg = NULL;

		__try
		{
			// 
			// determine the size of the buffer
			// 
			if (!GetTokenInformation(
				hToken,
				tic,
				(LPVOID)ptg,
				0,
				&dwLength
			))
			{
				const auto lerr = GetLastError();
				if (lerr == ERROR_INSUFFICIENT_BUFFER)
				{
					ptg = (PTOKEN_GROUPS)HeapAlloc(
						GetProcessHeap(),
						HEAP_ZERO_MEMORY,
						dwLength
					);
					if (ptg == NULL)
						__leave;
				}
				else
					__leave;
			}

			// 
			// obtain the groups the access token belongs to
			// 
			if (!GetTokenInformation(
				hToken,
				tic,
				(LPVOID)ptg,
				dwLength,
				&dwLength
			))
				__leave;

			// 
			// determine which group is the logon sid
			// 
			for (dwIndex = 0; dwIndex < ptg->GroupCount; dwIndex++)
			{
				if ((ptg->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID)
					== SE_GROUP_LOGON_ID)
				{
					// 
					// determine the length of the sid
					// 
					dwLength = GetLengthSid(ptg->Groups[dwIndex].Sid);

					// 
					// allocate a buffer for the logon sid
					// 
					*psid = (PSID)HeapAlloc(
						GetProcessHeap(),
						HEAP_ZERO_MEMORY,
						dwLength
					);
					if (*psid == NULL)
						__leave;

					// 
					// obtain a copy of the logon sid
					// 
					if (!CopySid(dwLength, *psid, ptg->Groups[dwIndex].Sid))
						__leave;

					// 
					// break out of the loop because the logon sid has been
					// found
					// 
					break;
				}
			}

			// 
			// indicate success
			// 
			bSuccess = TRUE;
		}
		__finally
		{
			// 
			// free the buffer for the token group
			// 
			if (ptg != NULL)
				HeapFree(GetProcessHeap(), 0, (LPVOID)ptg);
		}

		return bSuccess;

	}

	void RemoveSid(PSID *psid)
	{
		HeapFree(GetProcessHeap(), 0, (LPVOID)*psid);
	}

	BOOL AddTheAceWindowStation(HWINSTA hwinsta, PSID psid)
	{

		ACCESS_ALLOWED_ACE   *pace = nullptr;
		ACL_SIZE_INFORMATION aclSizeInfo;
		BOOL                 bDaclExist;
		BOOL                 bDaclPresent;
		BOOL                 bSuccess = FALSE; // assume function will
											   //fail
		DWORD                dwNewAclSize = 0;
		DWORD                dwSidSize = 0;
		DWORD                dwSdSizeNeeded = 0;
		PACL                 pacl = nullptr;
		PACL                 pNewAcl = nullptr;
		PSECURITY_DESCRIPTOR psd = NULL;
		PSECURITY_DESCRIPTOR psdNew = NULL;
		PVOID                pTempAce = nullptr;
		SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
		unsigned int         i = 0;

		__try
		{
			pNewAcl = nullptr;
			// 
			// obtain the dacl for the windowstation
			// 
			if (!GetUserObjectSecurity(
				hwinsta,
				&si,
				psd,
				dwSidSize,
				&dwSdSizeNeeded
			))
				if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				{
					psd = (PSECURITY_DESCRIPTOR)HeapAlloc(
						GetProcessHeap(),
						HEAP_ZERO_MEMORY,
						dwSdSizeNeeded
					);
					if (psd == NULL)
						__leave;

					psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(
						GetProcessHeap(),
						HEAP_ZERO_MEMORY,
						dwSdSizeNeeded
					);
					if (psdNew == NULL)
						__leave;

					dwSidSize = dwSdSizeNeeded;

					if (!GetUserObjectSecurity(
						hwinsta,
						&si,
						psd,
						dwSidSize,
						&dwSdSizeNeeded
					))
						__leave;
				}
				else
					__leave;

			// 
			// create a new dacl
			// 
			if (!InitializeSecurityDescriptor(
				psdNew,
				SECURITY_DESCRIPTOR_REVISION
			))
				__leave;

			// 
			// get dacl from the security descriptor
			// 
			if (!GetSecurityDescriptorDacl(
				psd,
				&bDaclPresent,
				&pacl,
				&bDaclExist
			))
				__leave;

			// 
			// initialize
			// 
			ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
			aclSizeInfo.AclBytesInUse = sizeof(ACL);

			// 
			// call only if the dacl is not NULL
			// 
			if (pacl != NULL)
			{
				// get the file ACL size info
				if (!GetAclInformation(
					pacl,
					(LPVOID)&aclSizeInfo,
					sizeof(ACL_SIZE_INFORMATION),
					AclSizeInformation
				))
					__leave;
			}

			// 
			// compute the size of the new acl
			// 
			dwNewAclSize = aclSizeInfo.AclBytesInUse + (2 *
				sizeof(ACCESS_ALLOWED_ACE)) + (2 * GetLengthSid(psid)) - (2 *
					sizeof(DWORD));

			// 
			// allocate memory for the new acl
			// 
			pNewAcl = (PACL)HeapAlloc(
				GetProcessHeap(),
				HEAP_ZERO_MEMORY,
				dwNewAclSize
			);
			if (pNewAcl == NULL)
				__leave;

			// 
			// initialize the new dacl
			// 
			if (!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION))
				__leave;

			// 
			// if DACL is present, copy it to a new DACL
			// 
			if (bDaclPresent) // only copy if DACL was present
			{
				// copy the ACEs to our new ACL
				if (aclSizeInfo.AceCount)
				{
					for (i = 0; i < aclSizeInfo.AceCount; i++)
					{
						// get an ACE
						if (!GetAce(pacl, i, &pTempAce))
							__leave;

						// add the ACE to the new ACL
						if (!AddAce(
							pNewAcl,
							ACL_REVISION,
							MAXDWORD,
							pTempAce,
							((PACE_HEADER)pTempAce)->AceSize
						))
							__leave;
					}
				}
			}

			// 
			// add the first ACE to the windowstation
			// 
			pace = (ACCESS_ALLOWED_ACE *)HeapAlloc(
				GetProcessHeap(),
				HEAP_ZERO_MEMORY,
				sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) -
				sizeof(DWORD
					));
			if (pace == NULL)
				__leave;

			pace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
			pace->Header.AceFlags = CONTAINER_INHERIT_ACE |
				INHERIT_ONLY_ACE |

				OBJECT_INHERIT_ACE;
			pace->Header.AceSize = static_cast<DWORD>(sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD));
			pace->Mask = GENERIC_ACCESS;

			if (!CopySid(GetLengthSid(psid), &pace->SidStart, psid))
				__leave;

			if (!AddAce(
				pNewAcl,
				ACL_REVISION,
				MAXDWORD,
				(LPVOID)pace,
				pace->Header.AceSize
			))
				__leave;

			// 
			// add the second ACE to the windowstation
			// 
			pace->Header.AceFlags = NO_PROPAGATE_INHERIT_ACE;
			pace->Mask = WINSTA_ALL;

			if (!AddAce(
				pNewAcl,
				ACL_REVISION,
				MAXDWORD,
				(LPVOID)pace,
				pace->Header.AceSize
			))
				__leave;

			// 
			// set new dacl for the security descriptor
			// 
			if (!SetSecurityDescriptorDacl(
				psdNew,
				TRUE,
				pNewAcl,
				FALSE
			))
				__leave;

			// 
			// set the new security descriptor for the windowstation
			// 
			if (!SetUserObjectSecurity(hwinsta, &si, psdNew))
				__leave;

			// 
			// indicate success
			// 
			bSuccess = TRUE;
		}
		__finally
		{
			// 
			// free the allocated buffers
			// 
			if (pace != NULL)
				HeapFree(GetProcessHeap(), 0, (LPVOID)pace);

			if (pNewAcl != NULL)
				HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

			if (psd != NULL)
				HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

			if (psdNew != NULL)
				HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
		}

		return bSuccess;

	}

	BOOL AddTheAceDesktop(HDESK hdesk, PSID psid)
	{

		ACL_SIZE_INFORMATION aclSizeInfo;
		BOOL                 bDaclExist;
		BOOL                 bDaclPresent;
		BOOL                 bSuccess = FALSE; // assume function will
											   // fail
		DWORD                dwNewAclSize;
		DWORD                dwSidSize = 0;
		DWORD                dwSdSizeNeeded;
		PACL                 pacl = nullptr;
		PACL                 pNewAcl = nullptr;
		PSECURITY_DESCRIPTOR psd = NULL;
		PSECURITY_DESCRIPTOR psdNew = NULL;
		PVOID                pTempAce = nullptr;
		SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
		unsigned int         i;

		__try
		{
			// 
			// obtain the security descriptor for the desktop object
			// 
			if (!GetUserObjectSecurity(
				hdesk,
				&si,
				psd,
				dwSidSize,
				&dwSdSizeNeeded
			))
			{
				if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				{
					psd = (PSECURITY_DESCRIPTOR)HeapAlloc(
						GetProcessHeap(),
						HEAP_ZERO_MEMORY,
						dwSdSizeNeeded
					);
					if (psd == NULL)
						__leave;

					psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(
						GetProcessHeap(),
						HEAP_ZERO_MEMORY,
						dwSdSizeNeeded
					);
					if (psdNew == NULL)
						__leave;

					dwSidSize = dwSdSizeNeeded;

					if (!GetUserObjectSecurity(
						hdesk,
						&si,
						psd,
						dwSidSize,
						&dwSdSizeNeeded
					))
						__leave;
				}
				else
					__leave;
			}

			// 
			// create a new security descriptor
			// 
			if (!InitializeSecurityDescriptor(
				psdNew,
				SECURITY_DESCRIPTOR_REVISION
			))
				__leave;

			// 
			// obtain the dacl from the security descriptor
			// 
			if (!GetSecurityDescriptorDacl(
				psd,
				&bDaclPresent,
				&pacl,
				&bDaclExist
			))
				__leave;

			// 
			// initialize
			// 
			ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
			aclSizeInfo.AclBytesInUse = sizeof(ACL);

			// 
			// call only if NULL dacl
			// 
			if (pacl != NULL)
			{
				// 
				// determine the size of the ACL info
				// 
				if (!GetAclInformation(
					pacl,
					(LPVOID)&aclSizeInfo,
					sizeof(ACL_SIZE_INFORMATION),
					AclSizeInformation
				))
					__leave;
			}

			// 
			// compute the size of the new acl
			// 
			dwNewAclSize = aclSizeInfo.AclBytesInUse +
				sizeof(ACCESS_ALLOWED_ACE) +
				GetLengthSid(psid) - sizeof(DWORD);

			// 
			// allocate buffer for the new acl
			// 
			pNewAcl = (PACL)HeapAlloc(
				GetProcessHeap(),
				HEAP_ZERO_MEMORY,
				dwNewAclSize
			);
			if (pNewAcl == NULL)
				__leave;

			// 
			// initialize the new acl
			// 
			if (!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION))
				__leave;

			// 
			// if DACL is present, copy it to a new DACL
			// 
			if (bDaclPresent) // only copy if DACL was present
			{
				// copy the ACEs to our new ACL
				if (aclSizeInfo.AceCount)
				{
					for (i = 0; i < aclSizeInfo.AceCount; i++)
					{
						// get an ACE
						if (!GetAce(pacl, i, &pTempAce))
							__leave;

						// add the ACE to the new ACL
						if (!AddAce(
							pNewAcl,
							ACL_REVISION,
							MAXDWORD,
							pTempAce,
							((PACE_HEADER)pTempAce)->AceSize
						))
							__leave;
					}
				}
			}

			// 
			// add ace to the dacl
			// 
			if (!AddAccessAllowedAce(
				pNewAcl,
				ACL_REVISION,
				DESKTOP_ALL,
				psid
			))
				__leave;

			// 
			// set new dacl to the new security descriptor
			// 
			if (!SetSecurityDescriptorDacl(
				psdNew,
				TRUE,
				pNewAcl,
				FALSE
			))
				__leave;

			// 
			// set the new security descriptor for the desktop object
			// 
			if (!SetUserObjectSecurity(hdesk, &si, psdNew))
				__leave;

			// 
			// indicate success
			// 
			bSuccess = TRUE;
		}
		__finally
		{
			// 
			// free buffers
			// 
			if (pNewAcl != nullptr)
				HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

			if (psd != NULL)
				HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

			if (psdNew != NULL)
				HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
		}

		return bSuccess;
	}

	BOOL AddTheAceProcess(HANDLE process, PSID psid)
	{

		ACL_SIZE_INFORMATION aclSizeInfo;
		BOOL                 bDaclExist;
		BOOL                 bDaclPresent;
		BOOL                 bSuccess = FALSE; // assume function will
											   // fail
		DWORD                dwNewAclSize;
		DWORD                dwSidSize = 0;
		DWORD                dwSdSizeNeeded;
		PACL                 pacl = nullptr;
		PACL                 pNewAcl = nullptr;
		PSECURITY_DESCRIPTOR psd = NULL;
		PSECURITY_DESCRIPTOR psdNew = NULL;
		PVOID                pTempAce = nullptr;
		SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
		unsigned int         i;

		__try
		{
			// 
			// obtain the security descriptor for the desktop object
			// 
			if (!GetUserObjectSecurity(
				process,
				&si,
				psd,
				dwSidSize,
				&dwSdSizeNeeded
			))
			{
				if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				{
					psd = (PSECURITY_DESCRIPTOR)HeapAlloc(
						GetProcessHeap(),
						HEAP_ZERO_MEMORY,
						dwSdSizeNeeded
					);
					if (psd == NULL)
						__leave;

					psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(
						GetProcessHeap(),
						HEAP_ZERO_MEMORY,
						dwSdSizeNeeded
					);
					if (psdNew == NULL)
						__leave;

					dwSidSize = dwSdSizeNeeded;

					if (!GetUserObjectSecurity(
						process,
						&si,
						psd,
						dwSidSize,
						&dwSdSizeNeeded
					))
						__leave;
				}
				else
					__leave;
			}

			// 
			// create a new security descriptor
			// 
			if (!InitializeSecurityDescriptor(
				psdNew,
				SECURITY_DESCRIPTOR_REVISION
			))
				__leave;

			// 
			// obtain the dacl from the security descriptor
			// 
			if (!GetSecurityDescriptorDacl(
				psd,
				&bDaclPresent,
				&pacl,
				&bDaclExist
			))
				__leave;

			// 
			// initialize
			// 
			ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
			aclSizeInfo.AclBytesInUse = sizeof(ACL);

			// 
			// call only if NULL dacl
			// 
			if (pacl != NULL)
			{
				// 
				// determine the size of the ACL info
				// 
				if (!GetAclInformation(
					pacl,
					(LPVOID)&aclSizeInfo,
					sizeof(ACL_SIZE_INFORMATION),
					AclSizeInformation
				))
					__leave;
			}

			// 
			// compute the size of the new acl
			// 
			dwNewAclSize = aclSizeInfo.AclBytesInUse +
				sizeof(ACCESS_ALLOWED_ACE) +
				GetLengthSid(psid) - sizeof(DWORD);

			// 
			// allocate buffer for the new acl
			// 
			pNewAcl = (PACL)HeapAlloc(
				GetProcessHeap(),
				HEAP_ZERO_MEMORY,
				dwNewAclSize
			);
			if (pNewAcl == NULL)
				__leave;

			// 
			// initialize the new acl
			// 
			if (!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION))
				__leave;

			// 
			// if DACL is present, copy it to a new DACL
			// 
			if (bDaclPresent) // only copy if DACL was present
			{
				// copy the ACEs to our new ACL
				if (aclSizeInfo.AceCount)
				{
					for (i = 0; i < aclSizeInfo.AceCount; i++)
					{
						// get an ACE
						if (!GetAce(pacl, i, &pTempAce))
							__leave;

						// add the ACE to the new ACL
						if (!AddAce(
							pNewAcl,
							ACL_REVISION,
							MAXDWORD,
							pTempAce,
							((PACE_HEADER)pTempAce)->AceSize
						))
							__leave;
					}
				}
			}

			// 
			// add ace to the dacl
			// 
			if (!AddAccessAllowedAce(
				pNewAcl,
				ACL_REVISION,
				GENERIC_ACCESS,
				psid
			))
				__leave;

			// 
			// set new dacl to the new security descriptor
			// 
			if (!SetSecurityDescriptorDacl(
				psdNew,
				TRUE,
				pNewAcl,
				FALSE
			))
				__leave;

			// 
			// set the new security descriptor for the desktop object
			// 
			if (!SetUserObjectSecurity(process, &si, psdNew))
				__leave;

			// 
			// indicate success
			// 
			bSuccess = TRUE;
		}
		__finally
		{
			// 
			// free buffers
			// 
			if (pNewAcl != nullptr)
				HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

			if (psd != NULL)
				HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

			if (psdNew != NULL)
				HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
		}

		return bSuccess;
	}
}