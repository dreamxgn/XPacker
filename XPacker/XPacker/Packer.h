#pragma once

#include <compressapi.h>

#define FILE_ALIGN 0x200
#define SECTION_ALIGN 0x1000

class Packer
{
public:

	/*
	* �洢PEͷ���� ѹ��ǰ��ѹ����Ĵ�С
	*/
	struct PackInfo
	{
		DWORD hdrSize; //PEͷѹ��ǰ��С
		DWORD comHdrSize; //PEͷѹ�����С
		DWORD secSize; //��ѹ��ǰ��С
		DWORD comSecSize; //��ѹ�����С
	};

	enum PACKSEC 
	{
		SI_SPACE,
		SI_CODE,
		SI_DATA
	};
public:
	/*
	* ��ָ��PE�ļ����мӿǴ���
	*/
	bool Pack(const char* pe);
	~Packer();
	Packer();
private:

	/*
	* ����PE�ļ��ڴ�ӳ��
	*/
	char* GetTargetPE(const char* pe);

	/*
	* ѹ��ԭPE�ļ�
	*/
	char* CompTargetPE();

	/*
	* �����ļ����
	*/
	void Clean();

	/*
	* �������ֵ
	* val��ֵ���뵽 align
	*/
	DWORD CalcAlign(DWORD val, DWORD align);

	/*
	* ����ǵ�PEͷ
	*/
	char* GetPackPEHdr();

	/*
	* ����Ǵ���
	*/
	char* GetPackCode();
	
	/*
	* �����PE�ļ�����
	*/
	bool GetPackPE(const char* packPe);
private:
	HANDLE m_hFileTargetPE;
	HANDLE m_hMapTargetPE;
	char* m_TargetBasePE;
	DWORD m_SizeTargetPE; //ԭPE�ļ��Ĵ�С
	DWORD m_PackCodeSize; //�Ǵ���ڴ�С
	char* m_PackCodeSec; //�Ǵ����
	char* m_ComData; //ѹ�����PE�ļ�����
	DWORD m_ComDataSize;//ѹ�����PE�ļ���С
	char* m_ComHdr; //��PEͷ
};

