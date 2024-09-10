#pragma once
#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <shellapi.h>
#include <tchar.h>
#include <time.h> 
//���������ʱ���������Ҫ������ļ����е��ļ�����
class FileHelp
{
public:
	FileHelp();
	FileHelp(const char* filename);
	~FileHelp();
	//�����ļ� �����ļ��� ʧ�ܷ��ش������  Ĭ�ϴ�����д���ļ� ���ã�FILE_ATTRIBUTE_HIDDEN �����ļ� FILE_ATTRIBUTE_READONLY ֻ���ļ�
	HANDLE CreateFileEX(const char* Filename, //�ļ�����
						DWORD dwDesiredAccess = GENERIC_WRITE, //��������ļ����豸��Ȩ��
						DWORD dwShareMode = NULL, //�ļ����豸��������ģʽ
						LPSECURITY_ATTRIBUTES lpSecurityAttributes = nullptr, // ָ��һ��SECURITY_ATTRIBUTES �ṹ��ָ��
						DWORD dwCreationDisposition = OPEN_ALWAYS,//�Դ��ڻ򲻴��ڵ��ļ����豸ִ�еĲ���
						DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_ARCHIVE,//�ļ����豸���Ժͱ�־ ��־�����ļ�Ӧ�浵�� Ӧ�ó���ʹ�ô����������Ҫ���ݻ�ɾ�����ļ�
						HANDLE	hTemplateFile = nullptr//���� GENERIC_READ ����Ȩ�޵�ģ���ļ�����Ч���
						);
	//�ļ��Ƿ���� 
	BOOL exists_test0(const std::string& name);
	//�����ļ�
	BOOL ReadFileGoZJJ(HANDLE FileNum, LPVOID& Data, LONGLONG lpFileSize, LPDWORD& ReadNum);
	//д���ļ�
	BOOL WriteFileGoZJJ(HANDLE FileNum, LPVOID& Data, LONGLONG lpFileSize);
	//�ļ��� -1��ʧ��
	HANDLE OpenFileEX(LPCSTR fliedir);
	//��ȡ�ļ���С
	LONGLONG FileSize(const char* filedir);
	//�ļ��ر�
	BOOL CloseFlie(HANDLE FileNum);
	//�ڴ濽�����ı�
	void write_memory_to_file(const char* memory, size_t size, const char* filename);
	//ȡ��Դ�ļ�ģ���ַ
	HMODULE GetSelfModuleHandle();
	//�ͷŻ�ȡ������Դ�ļ� ������Դ�ļ������ݵ�ַ ���Ĳ������ļ��Ĵ�С
	LPVOID FreeResFile(unsigned long m_lResourceID, const char* m_strResourceType, unsigned long& dwResSize);
	//��ȡ�ļ���С
	LONGLONG GetFileSize() {
		return m_FileSize;
	}
	//��ȡ���ļ����ļ���
	HANDLE GetFileNum() {
		return m_hFile;
	}
	//��������Ա����
	BOOL CreateSystemProcess(const char* ProcessPath, const char* StartParameter);
	//ȡ��ǰĿ¼
	std::string GetProgramDir();
	//ǿ��ɾ���ļ�
	BOOL ForcedFileDeletion(std::string FileName);
	//ɾ��Ŀ¼
	BOOL SHDeleteFolder(LPCTSTR pstrFolder);
	//����ָ���ļ�����
	BOOL FileBuff(LPCTSTR lpFileName,DWORD dwFileAttributes) {
		return SetFileAttributes(lpFileName, dwFileAttributes);
		/*
		FILE_ATTRIBUTE_ARCHIVE

		���ļ���һ���浵�ļ���Ӧ�ó���ʹ�ô����������ݻ��Ƴ�����ļ���

		FILE_ATTRIBUTE_HIDDEN

		���ļ������صġ�������������ͨ��Ŀ¼�б�

		FILE_ATTRIBUTE_NORMAL

		���ļ�û���������������ԡ������Խ��ڵ���ʹ����Ч��

		FILE_ATTRIBUTE_NOT_CONTENT_INDEXED

		���ļ����������������������������

		FILE_ATTRIBUTE_OFFLINE

		���ļ������ݲ����������á������Ա����ļ����ݱ������ƶ������ߴ洢������������ͨ��Զ�̴洢���ֲ�洢���������Ӧ�ó���Ӧ������Ĵ����ԡ�

		FILE_ATTRIBUTE_READONLY

		���ļ���ֻ���ġ�Ӧ�ó�����Զ�ȡ���ļ���������д���ɾ������

		FILE_ATTRIBUTE_SYSTEM

		���ļ��ǲ���ϵͳ��һ���֣�������ȫ����ʹ�á�

		FILE_ATTRIBUTE_TEMPORARY

		���ļ��Ǳ�������ʱ�洢���ļ�ϵͳ����д�����ݴ��غ����洢������㹻�Ļ����ڴ���ã���Ϊ������Ӧ�ó���ɾ���󲻾ã����������رյ���ʱ�ļ�������������£���ϵͳ������ȫ�����¼�����ݡ��������ֱ��رյ����ݽ���д�롣

		�����ȥ��һ�����ԵĻ������ڵڶ�����������ôд
		
		-FILE_ATTRIBUTE_HIDDEN
		*/
	}
private:
	//��ȡ���ļ���С
	LONGLONG m_FileSize = 0;
	//��ȡ���ļ���
	HANDLE m_hFile = 0;
};
inline FileHelp g_filehelp;
