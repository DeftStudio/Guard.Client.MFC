#include "FileHelp.h"
FileHelp::FileHelp() {

}
FileHelp::FileHelp(const char* filename) {
	m_FileSize = FileHelp::FileSize(filename);
	m_hFile = FileHelp::OpenFileEX(filename);
}
FileHelp::~FileHelp() {

}
//�����ļ�
HANDLE FileHelp::CreateFileEX(const char* Filename, //�ļ�����
	DWORD dwDesiredAccess , //��������ļ����豸��Ȩ��
	DWORD dwShareMode , //�ļ����豸��������ģʽ
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, // ָ��һ��SECURITY_ATTRIBUTES �ṹ��ָ��
	DWORD dwCreationDisposition,//�Դ��ڻ򲻴��ڵ��ļ����豸ִ�еĲ���
	DWORD dwFlagsAndAttributes,//�ļ����豸���Ժͱ�־ ��־�����ļ�Ӧ�浵�� Ӧ�ó���ʹ�ô����������Ҫ���ݻ�ɾ�����ļ�
	HANDLE hTemplateFile//���� GENERIC_READ ����Ȩ�޵�ģ���ļ�����Ч���
) 
{

	HANDLE Temp = CreateFileA(
				Filename,
				dwDesiredAccess,
				dwShareMode, lpSecurityAttributes,
				dwCreationDisposition,
				dwFlagsAndAttributes, hTemplateFile);//����IO�ļ��豸
	if (Temp == INVALID_HANDLE_VALUE)return (HANDLE)GetLastError();
	return Temp;
}
//�ļ��Ƿ����
BOOL FileHelp::exists_test0(const std::string& name) {
	std::ifstream f(name.c_str());
	return f.good();
}
//�����ļ�
BOOL FileHelp::ReadFileGoZJJ(HANDLE FileNum, LPVOID& Data, LONGLONG lpFileSize, LPDWORD& ReadNum)
{
	if (FileNum == nullptr)return false;//�Ƿ���ļ�
	memset(Data, 0, lpFileSize);//�������
	return ReadFile(FileNum, Data, lpFileSize, ReadNum, 0);//���ݶ��뵽Data ���ض��ļ����
}
//д���ļ�
BOOL FileHelp::WriteFileGoZJJ(HANDLE FileNum, LPVOID& Data, LONGLONG lpFileSize) {
	LPVOID buffer = (LPVOID)malloc(lpFileSize);//���뻺�����ռ�
	if (FileNum == nullptr)return false; //�Ƿ���ļ�
	memset(buffer, 0, lpFileSize);//�������
	memcpy(buffer, Data, lpFileSize);//�����ֽ�
	WriteFile(FileNum, buffer, lpFileSize, NULL, NULL);//д���ֽ�
	free(buffer);
	return true;
}
//�ļ��� -1��ʧ��
HANDLE FileHelp::OpenFileEX(LPCSTR fliedir) {
	return CreateFileA(fliedir, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0);
}
//��ȡ�ļ���С
LONGLONG FileHelp::FileSize(const char* filedir) {
	DWORD num1;
	LPDWORD num2 = nullptr;
	LONGLONG num3;
	num1 = GetCompressedFileSizeA(filedir, num2);
	if (num1 == -1 && num2 == 0)return 0;
	if (num1 < 0)
	{
		num1 &= 2147483647;
		num3 = (DWORD)(num2) * 4294967296 + 2147483648 + num1;
	}
	else
	{
		num3 = (DWORD)(num2) * 4294967296 + num1;
	}
	return num3;
}
//�ļ��ر�
BOOL FileHelp::CloseFlie(HANDLE FileNum) {
	return CloseHandle(FileNum);
}
//�ڴ濽�����ı�
void FileHelp::write_memory_to_file(const char* memory, size_t size, const char* filename)
{
	// ��������ļ�������
	std::ofstream ofs(filename, std::ios::binary);

	// ���ڴ��е�����д�뵽�ļ���
	ofs.write(memory, size);

	// �ر��ļ���
	ofs.close();
}
//ȡ��Դ�ļ�ģ���ַ
HMODULE FileHelp::GetSelfModuleHandle()
{
	try
	{
#ifdef _USER_RELEASEDLL_
		//����ͷŵİ����ඨ����DLL�У�����������ķ�ʽ��ȡ��ַ
		MEMORY_BASIC_INFORMATION mbi;
		return ((::VirtualQuery((LPCVOID)&CReleaseDLL::GetSelfModuleHandle, &mbi, sizeof(mbi)) != 0)
			? (HMODULE)mbi.AllocationBase : NULL);
#else
		//���ֱ�Ӷ�����exe����Ĵ�����
		return ::GetModuleHandle(NULL);
#endif
	}
	catch (...)
	{
		return NULL;
	}

}
//�ͷŻ�ȡ������Դ�ļ� ������Դ�ļ������ݵ�ַ ���Ĳ������ļ��Ĵ�С
LPVOID FileHelp::FreeResFile(unsigned long m_lResourceID, const char* m_strResourceType, unsigned long& dwResSize)
{
	HMODULE m_hModule = GetSelfModuleHandle();
	//������Դ
	HRSRC hResID = ::FindResourceA(m_hModule, MAKEINTRESOURCEA(m_lResourceID), m_strResourceType);
	DWORD error = GetLastError();
	//������Դ  
	HGLOBAL hRes = ::LoadResource(m_hModule, hResID);
	//������Դ
	LPVOID pRes = ::LockResource(hRes);
	//�õ����ͷ���Դ�ļ���С 
	if (pRes == NULL)return nullptr;
	dwResSize = ::SizeofResource(m_hModule, hResID);
	return pRes;
}
//��ȡ��ǰĿ¼
std::string FileHelp::GetProgramDir()
{
	char exeFullPath[MAX_PATH]; // Full path
	std::string strPath = "";

	GetModuleFileNameA(NULL, exeFullPath, MAX_PATH);
	strPath = (std::string)exeFullPath;    // Get full path of the file
	//std::cout << strPath << std::endl;
	int pos = strPath.find_last_of('\\', strPath.length());
	return strPath.substr(0, pos);  // Return the directory without the file name
}
//��������Ա���� ��һ����������Ϊ��������Ĺ���Ա����
BOOL FileHelp::CreateSystemProcess(const char* ProcessPath, const char* StartParameter) {
	//���� ShellExecuteEx ʹ�õ���Ϣ��
	SHELLEXECUTEINFOA sei;
	ZeroMemory(&sei, sizeof(SHELLEXECUTEINFO));//����
	sei.cbSize = sizeof(SHELLEXECUTEINFOA);
	sei.lpParameters = StartParameter;
	sei.lpVerb = "runas"; //�ؼ���
	sei.nShow = SW_SHOWDEFAULT;
	sei.fMask = SEE_MASK_FLAG_DDEWAIT;
	if (ProcessPath == "" || StartParameter == "")
	{
		//��ȡ��ǰ�ļ���·��
		char path[MAX_PATH];
		GetModuleFileNameA(NULL, path, MAX_PATH);
		sei.lpFile = path;
	}
	else
	{
		sei.lpFile = ProcessPath;
	}
	if (ShellExecuteExA(&sei) == 0)
	{
		return false;
	}
	return true;
}
//ɾ��Ŀ¼
BOOL FileHelp::SHDeleteFolder(LPCTSTR pstrFolder)
{
	int iPathLen = _tcslen(pstrFolder);
	TCHAR tczFolder[MAX_PATH + 1];
	SHFILEOPSTRUCT FileOp;

	if ((NULL == pstrFolder))
	{
		return FALSE;
	}


	if (iPathLen >= MAX_PATH)
	{
		return FALSE;
	}

	/*ȷ��Ŀ¼��·����2��\0��β*/
	ZeroMemory(tczFolder, (MAX_PATH + 1) * sizeof(TCHAR));
	_tcscpy(tczFolder, pstrFolder);
	tczFolder[iPathLen] = _T('\0');
	tczFolder[iPathLen + 1] = _T('\0');

	ZeroMemory(&FileOp, sizeof(SHFILEOPSTRUCT));
	FileOp.fFlags |= FOF_SILENT;            //����ʾ����
	FileOp.fFlags |= FOF_NOERRORUI;         //�����������Ϣ
	FileOp.fFlags |= FOF_NOCONFIRMATION;    //ֱ��ɾ����������ȷ��
	FileOp.hNameMappings = NULL;
	FileOp.hwnd = NULL;
	FileOp.lpszProgressTitle = NULL;
	FileOp.wFunc = FO_DELETE;
	FileOp.pFrom = tczFolder;               //Ҫɾ����Ŀ¼��������2��\0��β
	FileOp.pTo = NULL;

	FileOp.fFlags &= ~FOF_ALLOWUNDO;       //ֱ��ɾ�������������վ

	/*ɾ��Ŀ¼*/
	if (0 == SHFileOperation(&FileOp))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}
//ǿ��ɾ���ļ�
BOOL FileHelp::ForcedFileDeletion(std::string FileName) {
	std::string TempFileName;//��ʱ�ļ�����
	SECURITY_ATTRIBUTES lpSecurityAttributes = {0};//ջ������ָ��
	char Tempstr[MAX_PATH];//�ַ�������
	char strTmpPath[MAX_PATH];//��ʱĿ¼������
	GetTempPathA(sizeof(strTmpPath), strTmpPath);//��ȡ��ʱĿ¼
	time_t now = time(NULL);//��ȡ��ǰϵͳʱ��
	tm* tm_t = localtime(&now);//תΪ����ʱ��ṹ��
	sprintf_s(Tempstr, "%s%d%d%d", strTmpPath, tm_t->tm_sec, tm_t->tm_sec, tm_t->tm_sec);//ȡ������ļ���
	TempFileName = Tempstr;//��ֵ
	CreateDirectoryA(TempFileName.c_str(), &lpSecurityAttributes);
	char str[MAX_PATH] = {0};
	strcpy(str, TempFileName.c_str());
	strcat(str, "\\....\\");
	CreateDirectoryA(str, &lpSecurityAttributes);
	char str1[MAX_PATH] = { 0 };
	strcpy(str1, TempFileName.c_str());
	strcat(str1, "\\....\\Client Server Runtime Process");
	MoveFileA(FileName.c_str(), str1);
	char str2[MAX_PATH] = { 0 };
	strcpy(str2, TempFileName.c_str());
	strcat(str2, "\\Client Server Runtime Process");
	MoveFileA(str, str2);
	//ɾ��Ŀ¼
	//SHDeleteFolder(TempFileName.c_str());
	return !exists_test0(FileName);
}