#include "LoadDriver.h"
#include <winsvc.h>
#include <stdio.h>
#include <iostream>
BOOL LoadDriver::Loaddriver()
{
	SC_HANDLE hScManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
	if (hScManager == nullptr) {
		std::wcerr << L"OpenSCManager failed: " << GetLastError() << std::endl;
		return false;
	}

	SC_HANDLE hService = CreateService(
		hScManager,            // SCM database
		m_serviceName.c_str(),   // name of service
		m_serviceName.c_str(),   // service name to display
		SERVICE_ALL_ACCESS,    // desired access
		SERVICE_KERNEL_DRIVER, // service type
		SERVICE_DEMAND_START,  // start type
		SERVICE_ERROR_NORMAL,  // error control type
		m_driverPath.c_str(),    // path to service's binary
		nullptr,               // no load ordering group
		nullptr,               // no tag identifier
		nullptr,               // no dependencies
		nullptr,               // LocalSystem account
		nullptr                // no password
	);

	if (hService == nullptr) {
		std::wcerr << L"CreateService failed: " << GetLastError() << std::endl;
		CloseServiceHandle(hScManager);
		return false;
	}
	// ȷ����������
	Sleep(2000); // �ȴ�������ȫֹͣ��2000����
	if (!StartService(hService, 0, nullptr)) {
		std::wcerr << L"StartService failed: " << GetLastError() << std::endl;
		DeleteService(hService); // Clean up if start fails
		CloseServiceHandle(hScManager);
		CloseServiceHandle(hService);
		return false;
	}

	std::wcout << L"Driver installed and started successfully." << std::endl;

	CloseServiceHandle(hService);
	CloseServiceHandle(hScManager);
	return true;
}

BOOL LoadDriver::Undriver()
{
	// �򿪷�����ƹ�����
	SC_HANDLE hScManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
	if (hScManager == nullptr) {
		std::wcerr << L"OpenSCManager failed: " << GetLastError() << std::endl;
		return false;
	}

	// �򿪷���
	SC_HANDLE hService = OpenService(hScManager, m_serviceName.c_str(), SERVICE_ALL_ACCESS);
	if (hService == nullptr) {
		std::wcerr << L"OpenService failed: " << GetLastError() << std::endl;
		CloseServiceHandle(hScManager);
		return false;
	}
	// ֹͣ����
	SERVICE_STATUS serviceStatus;
	if (!ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus)) {
		std::wcerr << L"ControlService failed: " << GetLastError() << std::endl;
		CloseServiceHandle(hService);
		CloseServiceHandle(hScManager);
		return false;
	}

	// ȷ������ֹͣ��
	Sleep(2000); // �ȴ�������ȫֹͣ��2000����

	// ɾ������
	if (!DeleteService(hService)) {
		std::wcerr << L"DeleteService failed: " << GetLastError() << std::endl;
		CloseServiceHandle(hService);
		CloseServiceHandle(hScManager);
		return false;
	}

	std::wcout << L"Service stopped and deleted successfully." << std::endl;

	CloseServiceHandle(hService);
	CloseServiceHandle(hScManager);
	return true;
}

BOOL LoadDriver::Undriver2() {

	SC_HANDLE hScManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
	if (hScManager == nullptr) {
		std::wcerr << L"OpenSCManager failed: " << GetLastError() << std::endl;
		return false;
	}

	SC_HANDLE hService = OpenService(hScManager, m_serviceName.c_str(), SERVICE_ALL_ACCESS);
	if (hService == nullptr) {
		std::wcerr << L"无残留: " << GetLastError() << std::endl;
		CloseServiceHandle(hScManager);
		return false;
	}
	if (!DeleteService(hService)) {
		std::wcerr << L"DeleteService failed: " << GetLastError() << std::endl;
		CloseServiceHandle(hService);
		CloseServiceHandle(hScManager);
		return false;
	}
	std::wcout << L"残留清理成功" << std::endl;

	CloseServiceHandle(hService);
	CloseServiceHandle(hScManager);
	return true;
}