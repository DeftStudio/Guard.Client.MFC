#pragma once
//������������
#include <windows.h>
#include <string.h>
#include <iostream>
class LoadDriver
{
public:
	std::wstring m_driverPath;
	std::wstring m_serviceName;
	void load(const wchar_t* _lpszDriverName, const wchar_t* _sysFileName)
	{
		m_serviceName = _lpszDriverName;
		m_driverPath = _sysFileName;
	}
	LoadDriver()
	{
	}
	BOOL Loaddriver();
	BOOL Undriver2();
	BOOL Undriver();
};

