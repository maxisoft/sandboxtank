#pragma once
#include "windows_include.hpp"
#include <datetimeapi.h>
#include <wincon.h>
#include <string>

namespace maxisoft::sandbox
{
	std::wstring ObtainUserSidString(HANDLE hToken);
	BOOL ObtainSid(HANDLE hToken, PSID *psid);
	void RemoveSid(PSID *psid);
	BOOL AddTheAceWindowStation(HWINSTA hwinsta, PSID psid);
	BOOL AddTheAceDesktop(HDESK hdesk, PSID psid);
	BOOL AddTheAceProcess(HANDLE process, PSID psid);
}

