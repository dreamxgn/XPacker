#include "pch.h"
#include "Packer.h"

#pragma comment(lib,"Cabinet.lib")

bool Packer::Pack(const char* pe)
{
    Clean();

    //��PE���ص��ڴ�(ʹ���ڴ�ӳ���ļ�)
    char* targetPE = GetTargetPE(pe);
    if (targetPE == nullptr)
    {
        return false;
    }

    //ѹ��PE
    char* comTargetData = CompTargetPE();
    if (comTargetData ==NULL)
    {
        return false;
    }

    //��ȡ�Ǵ����
    char* packCodeData = GetPackCode();
    if (packCodeData == nullptr)
    {
        return false;
    }

    //��ȡ��PEͷ
    char* packHdrData = GetPackPEHdr();
    if (packHdrData == nullptr)
    {
        return false;
    }
   
    //�����PE�ļ�
    if (GetPackPE(pe)==false)
    {
        return false;
    }


    return true;
}

Packer::~Packer()
{
    Clean();
}

Packer::Packer()
{
    m_TargetBasePE = nullptr;
    m_hMapTargetPE = nullptr;
    m_hFileTargetPE = nullptr;
}

char* Packer::GetTargetPE(const char* pe)
{
    m_hFileTargetPE= CreateFileA(pe, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_hFileTargetPE == INVALID_HANDLE_VALUE)
    {
        return nullptr;
    }

    m_hMapTargetPE=CreateFileMappingA(m_hFileTargetPE, NULL, PAGE_READONLY, 0, 0, NULL);
    if (m_hMapTargetPE == NULL)
    {
        return nullptr;
    }

    m_TargetBasePE= (char*)MapViewOfFile(m_hMapTargetPE, FILE_MAP_READ, 0, 0, 0);

    m_SizeTargetPE= GetFileSize(m_hFileTargetPE, &m_SizeTargetPE);

    return m_TargetBasePE;
}

char* Packer::CompTargetPE()
{
    //ѹ��PEͷ
    char* base = m_TargetBasePE;

    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS32* pNt = (IMAGE_NT_HEADERS32*)(base + pDos->e_lfanew);

    //PEͷ�Ĵ�С
    DWORD peHdrSize = pNt->OptionalHeader.SizeOfHeaders;

    COMPRESSOR_HANDLE compsor = NULL;
    BOOL bRet = CreateCompressor(
        COMPRESS_ALGORITHM_XPRESS_HUFF,
        NULL,
        &compsor);

    if (bRet == false)
    {
        return false;
    }

    //��ȡPEͷѹ�����С
    PackInfo pInfo = {0};

    pInfo.hdrSize = peHdrSize;

    //���peͷѹ����Ļ�����
    char* comBuffHdr = new char[pInfo.hdrSize] {0};

    //ѹ��PEͷ
    DWORD comedSize = 0;
    bRet = Compress(
        compsor,
        base,
        peHdrSize,
        comBuffHdr,
        pInfo.hdrSize,
        &comedSize);
    if (bRet == false)
    {
        return false;
    }
    pInfo.comHdrSize = comedSize; //PEͷѹ��������ݴ�С

    CloseCompressor(compsor);

    //ѹ��������
    DWORD secSize = m_SizeTargetPE - pNt->OptionalHeader.SizeOfHeaders;
    char* comBuffSec = new char[secSize] {0}; //���ڽ�����ѹ����Ļ�����

    DWORD secData = (DWORD)(base + pNt->OptionalHeader.SizeOfHeaders);

    bRet= CreateCompressor(
        COMPRESS_ALGORITHM_XPRESS_HUFF,
        NULL,
        &compsor);

    if (bRet == false)
    {
        return false;
    }

    bRet = Compress(
        compsor,
        (char*)secData,
        secSize,
        comBuffSec,
        secSize,
        &comedSize);
    if (bRet == false)
    {
        return false;
    }
    CloseCompressor(compsor);
    pInfo.secSize = secSize; //��ԭʼ��С
    pInfo.comSecSize = comedSize; //ѹ����ڵĴ�С

    DWORD comDataSize =sizeof(PackInfo)+ pInfo.comHdrSize + pInfo.comSecSize;
    char* peData = new char[comDataSize] {0};

    memcpy(peData, &pInfo,sizeof(PackInfo)); //����ѹ�����¼��Ϣ
    memcpy(peData + sizeof(PackInfo), comBuffHdr, pInfo.comHdrSize); //����PEͷ
    memcpy(peData + sizeof(PackInfo)+pInfo.comHdrSize, comBuffSec, pInfo.comSecSize); //����ѹ�����¼��Ϣ

    delete[] comBuffHdr;
    delete[] comBuffSec;

    m_ComData = peData;
    m_ComDataSize = comDataSize;
    return peData;
}

void Packer::Clean()
{
    if (m_TargetBasePE != nullptr)
    {
        UnmapViewOfFile(m_TargetBasePE);
        m_TargetBasePE = nullptr;
    }

    if (m_hMapTargetPE != nullptr)
    {
        CloseHandle(m_hMapTargetPE);
        m_hMapTargetPE = nullptr;
    }

    if (m_hFileTargetPE != nullptr)
    {
        CloseHandle(m_hFileTargetPE);
        m_hFileTargetPE = nullptr;
    }
}

DWORD Packer::CalcAlign(DWORD val, DWORD align)
{
    if (align == 0) {
        // �������ֵΪ0������ԭֵ
        return val;
    }

    if (val < align)
    {
        return align;
    }

    int num = val / align;
    return (num + 1) * align;
}

char* Packer::GetPackPEHdr()
{
    char* base = m_TargetBasePE;

    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)base;
    //ԭPE�ļ�NTͷ
    IMAGE_NT_HEADERS32* pNt = (IMAGE_NT_HEADERS32*)(base + pDos->e_lfanew);

    //ԭPEͷ��С
    DWORD peHdrSize = pNt->OptionalHeader.SizeOfHeaders;

    //�����PEͷ
    int packHdrSize = CalcAlign(peHdrSize, FILE_ALIGN);
    char* packPeHdr = new char[packHdrSize] {0};

    //����ԭPE����PE
    memcpy(packPeHdr, base, peHdrSize);

    IMAGE_DOS_HEADER* pPackDos = (IMAGE_DOS_HEADER*)packPeHdr;
    IMAGE_NT_HEADERS32* pPackNt = (IMAGE_NT_HEADERS32*)(packPeHdr + pPackDos->e_lfanew);
    IMAGE_OPTIONAL_HEADER32* pPackOpt = &(pPackNt->OptionalHeader);

    //��һ����
    IMAGE_SECTION_HEADER* pPackSecHdr = (IMAGE_SECTION_HEADER*)((char*)(&pPackNt->OptionalHeader) + pPackNt->FileHeader.SizeOfOptionalHeader);

    //����Fileͷ
    pPackNt->FileHeader.NumberOfSections = 3; //����3����
    //��ѡPEͷ��С
    pPackNt->FileHeader.SizeOfOptionalHeader = sizeof(pPackNt->OptionalHeader);
    
    //���� OptionalHeader
    pPackOpt->FileAlignment = FILE_ALIGN;
    pPackOpt->SectionAlignment = SECTION_ALIGN;
    pPackOpt->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    //�������Ŀ¼
    memset(&(pPackOpt->DataDirectory[0]), 0, sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

    //����ڱ�
    //����սڱ�
    memset(pPackSecHdr, 0, sizeof(IMAGE_SECTION_HEADER) * pPackNt->FileHeader.NumberOfSections + 2);

    //ռλ��
    memset((void*)(&pPackSecHdr[SI_SPACE]), 0, sizeof(IMAGE_SECTION_HEADER));
    pPackSecHdr[SI_SPACE].Characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA
        | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
    strcpy((char*)&(pPackSecHdr[SI_SPACE].Name[0]), ".xpack");
    pPackSecHdr[SI_SPACE].Misc.VirtualSize = CalcAlign(pNt->OptionalHeader.SizeOfImage, SECTION_ALIGN);
    pPackSecHdr[SI_SPACE].VirtualAddress = 0x1000;
    pPackSecHdr[SI_SPACE].SizeOfRawData = 0x0;
    pPackSecHdr[SI_SPACE].PointerToRawData = 0x0;


    //�Ǵ����
    memset((void*)(&pPackSecHdr[SI_CODE]), 0, sizeof(IMAGE_SECTION_HEADER));
    pPackSecHdr[SI_CODE].Characteristics = IMAGE_SCN_CNT_CODE
        | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    strcpy((char*)&(pPackSecHdr[SI_CODE].Name[0]), ".xpack1");
    pPackSecHdr[SI_CODE].Misc.VirtualSize = CalcAlign(m_PackCodeSize, SECTION_ALIGN);
    pPackSecHdr[SI_CODE].VirtualAddress = pPackSecHdr[SI_SPACE].VirtualAddress + pPackSecHdr[SI_SPACE].Misc.VirtualSize;
    pPackSecHdr[SI_CODE].SizeOfRawData = CalcAlign(m_PackCodeSize,FILE_ALIGN);
    pPackSecHdr[SI_CODE].PointerToRawData = pPackNt->OptionalHeader.SizeOfHeaders;


    //�����ݽڣ�ԭPE�ļ��ʹ�������
    memset((void*)(&pPackSecHdr[SI_DATA]), 0, sizeof(IMAGE_SECTION_HEADER));
    pPackSecHdr[SI_DATA].Characteristics =  IMAGE_SCN_MEM_READ ;
    strcpy((char*)&(pPackSecHdr[SI_DATA].Name[0]), ".xpack2");

    PackInfo* pInfo = (PackInfo*)m_ComData;

    pPackSecHdr[SI_DATA].Misc.VirtualSize = CalcAlign(sizeof(PackInfo) + pInfo->comHdrSize + pInfo->comSecSize, SECTION_ALIGN);
    pPackSecHdr[SI_DATA].VirtualAddress = pPackSecHdr[SI_CODE].VirtualAddress + pPackSecHdr[SI_CODE].Misc.VirtualSize;
    pPackSecHdr[SI_DATA].SizeOfRawData = CalcAlign(pPackSecHdr[SI_DATA].Misc.VirtualSize, FILE_ALIGN);
    pPackSecHdr[SI_DATA].PointerToRawData = pPackSecHdr[SI_CODE].PointerToRawData + pPackSecHdr[SI_CODE].SizeOfRawData;
    
    pPackOpt->AddressOfEntryPoint = pPackSecHdr[SI_CODE].VirtualAddress;
    pPackOpt->SizeOfImage = CalcAlign(pPackSecHdr[SI_DATA].VirtualAddress + pPackSecHdr[SI_DATA].Misc.VirtualSize,SECTION_ALIGN);

    m_ComHdr = packPeHdr;

    return packPeHdr;
}

char* Packer::GetPackCode()
{
    //���ؿ�PE�ļ�
    HANDLE hFilePackPe = CreateFileA("X86_Stub.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFilePackPe == INVALID_HANDLE_VALUE)
    {
        return nullptr;
    }

    HANDLE hMapPackPe = CreateFileMappingA(hFilePackPe, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapPackPe == NULL)
    {
        return nullptr;
    }

    char* packBase = (char*)MapViewOfFile(hMapPackPe, FILE_MAP_READ, 0, 0, 0);

    DWORD packPeSize = 0;
    packPeSize = GetFileSize(hFilePackPe,NULL);

    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)packBase;
    IMAGE_NT_HEADERS32* pNt = (IMAGE_NT_HEADERS32*)(packBase + pDos->e_lfanew);
    IMAGE_SECTION_HEADER* pPackSecHdr = 
        (IMAGE_SECTION_HEADER*)((char*)(&pNt->OptionalHeader) + pNt->FileHeader.SizeOfOptionalHeader);

    char* code = new char[pPackSecHdr->SizeOfRawData] {0};
    
    memcpy(code, packBase + (pPackSecHdr->PointerToRawData), pPackSecHdr->SizeOfRawData);

    m_PackCodeSize = pPackSecHdr->SizeOfRawData;
    m_PackCodeSec = code;

    UnmapViewOfFile(packBase);
    CloseHandle(hMapPackPe);
    CloseHandle(hFilePackPe);
    return code;
}

bool Packer::GetPackPE(const char* pe)
{
    const char* peName = strrchr(pe, '\\') + 1; //pe�ļ�����
    const char* peExt = strstr(peName, "."); // pe�ļ���չ��

    //����·��
    char* path = new char[strlen(pe)] {0};
    memcpy(path, pe, peName - pe);

    //�����ļ���
    char* fname = new char[strlen(pe)] {0};
    memcpy(fname, peName, peExt - peName);

    //peName-pe
    CString packPe("");
    packPe.Format("%s%s_pack%s", 
        path, 
        fname,
        peExt);
    
    IMAGE_DOS_HEADER* pPackDos = (IMAGE_DOS_HEADER*)m_ComHdr;
    IMAGE_NT_HEADERS32* pPackNt = (IMAGE_NT_HEADERS32*)(m_ComHdr + pPackDos->e_lfanew);
    IMAGE_SECTION_HEADER* pPackSecHdr = (IMAGE_SECTION_HEADER*)((char*)(&pPackNt->OptionalHeader) + pPackNt->FileHeader.SizeOfOptionalHeader);

    DWORD packPESize = pPackSecHdr[SI_DATA].PointerToRawData + pPackSecHdr[SI_DATA].SizeOfRawData;

    char* peData = new char[packPESize] {0};
    DWORD offset = 0;
    //����PEͷ
    memcpy(peData, m_ComHdr, pPackNt->OptionalHeader.SizeOfHeaders);
    offset += pPackNt->OptionalHeader.SizeOfHeaders;

    //�����Ǵ����
    memcpy(peData+ pPackSecHdr[SI_CODE].PointerToRawData,
        m_PackCodeSec, 
        m_PackCodeSize);

    //���������ݽ�
    memcpy(peData + pPackSecHdr[SI_DATA].PointerToRawData,
        m_ComData,
        m_ComDataSize);

    HANDLE hFile= CreateFileA(packPe, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    DWORD wLen = 0;
    BOOL bRet= WriteFile(hFile, peData, packPESize, &wLen, NULL);
    if (bRet == FALSE)
    {
        return false;
    }
    CloseHandle(hFile);
    return true;
}
