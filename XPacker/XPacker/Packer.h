#pragma once

#include <compressapi.h>

#define FILE_ALIGN 0x200
#define SECTION_ALIGN 0x1000

class Packer
{
public:

	/*
	* 存储PE头、节 压缩前和压缩后的大小
	*/
	struct PackInfo
	{
		DWORD hdrSize; //PE头压缩前大小
		DWORD comHdrSize; //PE头压缩后大小
		DWORD secSize; //节压缩前大小
		DWORD comSecSize; //节压缩后大小
	};

	enum PACKSEC 
	{
		SI_SPACE,
		SI_CODE,
		SI_DATA
	};
public:
	/*
	* 对指定PE文件进行加壳处理
	*/
	bool Pack(const char* pe);
	~Packer();
	Packer();
private:

	/*
	* 创建PE文件内存映射
	*/
	char* GetTargetPE(const char* pe);

	/*
	* 压缩原PE文件
	*/
	char* CompTargetPE();

	/*
	* 清理文件句柄
	*/
	void Clean();

	/*
	* 计算对齐值
	* val的值对齐到 align
	*/
	DWORD CalcAlign(DWORD val, DWORD align);

	/*
	* 构造壳的PE头
	*/
	char* GetPackPEHdr();

	/*
	* 构造壳代码
	*/
	char* GetPackCode();
	
	/*
	* 构造壳PE文件数据
	*/
	bool GetPackPE(const char* packPe);
private:
	HANDLE m_hFileTargetPE;
	HANDLE m_hMapTargetPE;
	char* m_TargetBasePE;
	DWORD m_SizeTargetPE; //原PE文件的大小
	DWORD m_PackCodeSize; //壳代码节大小
	char* m_PackCodeSec; //壳代码节
	char* m_ComData; //压缩后的PE文件数据
	DWORD m_ComDataSize;//压缩后的PE文件大小
	char* m_ComHdr; //壳PE头
};

