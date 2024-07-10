// X86_Stub.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <Windows.h>
#include <compressapi.h>

typedef void* (WINAPI*PFN_LoadProcAddress)(int hModule, const char* procName);
typedef HMODULE (WINAPI*PFN_LoadLibraryA)(LPCSTR lpLibFileName);
typedef int (WINAPI *PFN_MessageBoxA)(HWND hWnd,LPCSTR lpText, LPCSTR lpCaption,UINT uType);
typedef HMODULE (WINAPI *PFN_GetModuleHandleA)(LPCSTR lpModuleName);
typedef BOOL (WINAPI *PFN_CreateCompressor)(DWORD Algorithm,PCOMPRESS_ALLOCATION_ROUTINES AllocationRoutines, PCOMPRESSOR_HANDLE CompressorHandle);
typedef BOOL (WINAPI *PFN_Compress)(COMPRESSOR_HANDLE CompressorHandle,_In_reads_bytes_opt_(UncompressedDataSize) LPCVOID UncompressedData,_In_ SIZE_T UncompressedDataSize,_Out_writes_bytes_opt_(CompressedBufferSize) PVOID CompressedBuffer,_In_ SIZE_T CompressedBufferSize,_Out_ PSIZE_T CompressedDataSize);
typedef BOOL (WINAPI *PFN_CloseCompressor)(_In_ COMPRESSOR_HANDLE CompressorHandle);
typedef BOOL(WINAPI* PFN_CreateDecompressor)(_In_ DWORD Algorithm, _In_opt_ PCOMPRESS_ALLOCATION_ROUTINES AllocationRoutines, _Out_ PDECOMPRESSOR_HANDLE DecompressorHandle);
typedef BOOL (WINAPI *PFN_CloseDecompressor)(_In_ DECOMPRESSOR_HANDLE DecompressorHandle);
typedef BOOL (WINAPI *PFN_CloseHandle)(_In_ _Post_ptr_invalid_ HANDLE hObject);
typedef LPVOID (WINAPI *PFN_VirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_     SIZE_T dwSize, _In_     DWORD flAllocationType, _In_ DWORD flProtect);
typedef BOOL (WINAPI *PFN_VirtualFree)(_Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT, _Post_invalid_) _When_(dwFreeType == MEM_RELEASE, _Post_ptr_invalid_) LPVOID lpAddress,_In_ SIZE_T dwSize,_In_ DWORD dwFreeType);
typedef BOOL (WINAPI *PFN_VirtualProtect)(_In_  LPVOID lpAddress, _In_  SIZE_T dwSize, _In_  DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
typedef BOOL (WINAPI *PFN_Decompress)(_In_ DECOMPRESSOR_HANDLE DecompressorHandle,_In_reads_bytes_opt_(CompressedDataSize) LPCVOID CompressedData,_In_ SIZE_T CompressedDataSize,_Out_writes_bytes_opt_(UncompressedBufferSize) PVOID UncompressedBuffer,_In_ SIZE_T UncompressedBufferSize,_Out_opt_ PSIZE_T UncompressedDataSize);


int _stdcall GetTeb()
{
    int teb = 0;
    __asm 
    {
        mov eax,fs:[018h]
        mov teb,eax
    }
    return teb;
}

int _stdcall GetPeb()
{
    int teb = GetTeb();
    int peb = 0;
    __asm
    {
        mov eax,teb
        mov eax,dword ptr ds:[eax+030h]
        mov peb,eax
    }
    return peb;
}

int _stdcall GetKernel32(int peb)
{
    int hModule = 0;
    __asm
    {
        mov eax, peb;
        mov eax,dword ptr [eax+0ch]
        mov eax,[eax+0ch] //LDR
        mov eax,[eax+0ch] 
        mov eax,dword ptr [eax] //当前pe模块
        mov eax,dword ptr [eax] // ntdll.dll
        mov eax, dword ptr[eax]
        mov eax,dword ptr [eax+010h] // KERNEL32.DLL
        mov hModule,eax
    }
    return hModule;
}

void* mymemset(void* dest, int val, size_t len)
{
    unsigned char* ptr = (unsigned char*)dest;
    while (len-- > 0)
        *ptr++ = val;
    return dest;
}
void* mymemcpy(void* dest, const void* src, size_t len)
{
    char* d = (char*)dest;
    const char* s = (const char*)src;
    while (len--)
        *d++ = *s++;
    return dest;
}

int mymemcmp(const void* str1, const void* str2, size_t count)
{
    register const unsigned char* s1 = (const unsigned char*)str1;
    register const unsigned char* s2 = (const unsigned char*)str2;

    while (count-- > 0)
    {
        if (*s1++ != *s2++)
            return s1[-1] < s2[-1] ? -1 : 1;
    }
    return 0;
}
char* mystrchr(register const char* s, int c)
{
    do {
        if (*s == c)
        {
            return (char*)s;
        }
    } while (*s++);
    return (0);
}

void* _stdcall LoadProcAddress(char* hModule, const char* procName, PFN_LoadLibraryA Pfn_LoadLibraryA)
{

    IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS32* pNtHdr = (IMAGE_NT_HEADERS32*)(hModule + pDosHdr->e_lfanew);
    IMAGE_DATA_DIRECTORY* eDir = &(pNtHdr->OptionalHeader.DataDirectory[0]);

    //导出表
    IMAGE_EXPORT_DIRECTORY* pExportDir = (IMAGE_EXPORT_DIRECTORY*)(hModule + eDir->VirtualAddress);

    //函数地址表
    DWORD* addrFuncs = (DWORD*)(hModule + pExportDir->AddressOfFunctions);

    //函数名称表
    DWORD* addrNames= (DWORD*)(hModule + pExportDir->AddressOfNames);

    //函数序号表
    WORD* addrOrdinals = (WORD*)(hModule + pExportDir->AddressOfNameOrdinals);

    //序号导入
    if (((int)procName) < 0xffff)
    {
        int index = ((int)procName) - pExportDir->Base;
        DWORD addr = *(addrFuncs + index);
        return addr + hModule;
    }
    else
    {

        for (int i = 0;i < pExportDir->NumberOfNames;i++)
        {
            DWORD* namePtr = (DWORD*)((*(addrNames + i))+hModule);

            //找到了函数
            if (strcmp((const char*)namePtr, procName)==0)
            {

                WORD* ordinal = (WORD*)(addrOrdinals + i);
                DWORD addr = *(addrFuncs + (*ordinal));
                addr = (DWORD)(addr + hModule);

                DWORD exprBase = (DWORD)(hModule + eDir->VirtualAddress);
                DWORD exprSize = exprBase + eDir->Size;

                //函数转发
                if (addr > exprBase && addr< exprSize)
                {

                    char dllNameBuff[100];
                    mymemset(dllNameBuff, 0, 100);


                    DWORD pos = (DWORD)mystrchr((const char*)addr, 0x2e);
                    DWORD dllNameLen = (pos - addr) + 1;

                    mymemcpy(dllNameBuff, (char*)addr, dllNameLen - 1);
                    HMODULE hMod = Pfn_LoadLibraryA(dllNameBuff);

                    if (hMod == NULL)
                    {
                        return NULL;
                    }

                    return LoadProcAddress((char*)hMod, (char*)(addr + dllNameLen), Pfn_LoadLibraryA);
                }
                else
                {
                    return (void*)addr;
                }
            }
        }
        return NULL;
    }
}

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



char* GetHdrData(char* pComData, PFN_CreateCompressor PFN_CreateDecompressor, PFN_CloseDecompressor Pfn_CloseDecompressor, PFN_Decompress Pfn_Decompress, PFN_VirtualAlloc Pfn_VirtualAlloc)
{
    PackInfo* pInfo = (PackInfo*)pComData;

    DECOMPRESSOR_HANDLE Decompressor = NULL;
    BOOL bRet = PFN_CreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, //  Compression Algorithm
        NULL,                           //  Optional allocation routine
        &Decompressor);                 //  Handle
    if (bRet == false)
    {
        return NULL;
    }

    char* peHdr = (char*)Pfn_VirtualAlloc(NULL, pInfo->hdrSize, MEM_COMMIT, PAGE_READWRITE);
    if (peHdr == NULL)
    {
        return NULL;
    }

    char* pComHdrData = (char*)(pComData + sizeof(PackInfo));
    DWORD size = 0;
    bRet = Pfn_Decompress(
        Decompressor,
        pComHdrData,
        pInfo->comHdrSize,
        peHdr,
        pInfo->hdrSize,
        &size);

    if (bRet == false)
    {
        return NULL;
    }
    Pfn_CloseDecompressor(Decompressor);
    return peHdr;
}

char* GetSecData(char* pComData, PFN_CreateCompressor PFN_CreateDecompressor, PFN_CloseDecompressor Pfn_CloseDecompressor, PFN_Decompress Pfn_Decompress, PFN_VirtualAlloc Pfn_VirtualAlloc)
{
    DECOMPRESSOR_HANDLE Decompressor = NULL;
    BOOL bRet = PFN_CreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, //  Compression Algorithm
        NULL,                           //  Optional allocation routine
        &Decompressor);                 //  Handle
    if (bRet == false)
    {
        return NULL;
    }

    PackInfo* pInfo = (PackInfo*)pComData;
    //解压缩节
    char* peSecData = (char*)Pfn_VirtualAlloc(NULL, pInfo->secSize, MEM_COMMIT, PAGE_READWRITE);
    if (peSecData == NULL)
    {
        return NULL;
    }

    char* pComSecData = pComData + sizeof(PackInfo) + pInfo->comHdrSize;
    DWORD size = 0;
    bRet = Pfn_Decompress(
        Decompressor,
        pComSecData,
        pInfo->comSecSize,
        peSecData,
        pInfo->secSize,
        &size);

    if (bRet == false)
    {
        return NULL;
    }
    Pfn_CloseDecompressor(Decompressor);
    return peSecData;
}

BOOL  SetPEData(char* base,char* pPeHdr, char* pSecData, PackInfo* pInfo, PFN_VirtualProtect Pfn_VirtualProtect)
{
    DWORD oldProc = 0;
    BOOL bRet=Pfn_VirtualProtect(base, 0x1000, PAGE_READWRITE, &oldProc);
    if (bRet == FALSE)
    {
        return false;
    }

    mymemcpy(base, pPeHdr, pInfo->hdrSize);
    bRet = Pfn_VirtualProtect(base, 0x1000, oldProc, &oldProc);
    if (bRet == FALSE)
    {
        return false;
    }

    //拷贝节表
    IMAGE_DOS_HEADER* pPackDos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS32* pPackNt = (IMAGE_NT_HEADERS32*)(base + pPackDos->e_lfanew);
    IMAGE_OPTIONAL_HEADER32* pPackOpt = &(pPackNt->OptionalHeader);

    //第一个节
    IMAGE_SECTION_HEADER* pSec = (IMAGE_SECTION_HEADER*)((char*)(&pPackNt->OptionalHeader) + pPackNt->FileHeader.SizeOfOptionalHeader);
    for (int i = 0;i < pPackNt->FileHeader.NumberOfSections;i++)
    {
        IMAGE_SECTION_HEADER* sec = &(pSec[i]);
        bRet = Pfn_VirtualProtect(base + sec->VirtualAddress,sec->SizeOfRawData, PAGE_EXECUTE_READWRITE, &oldProc);
        if (bRet == FALSE)
        {
            return false;
        }
        mymemcpy((char*)(base + sec->VirtualAddress), (char*)((pSecData-0x400)+ sec->PointerToRawData), sec->SizeOfRawData);
    }
    return true;
}

BOOL FixImportTable(char* base, PFN_LoadLibraryA Pfn_LoadLibraryA)
{
    IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS32* pNtHdr = (IMAGE_NT_HEADERS32*)(base + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER32* pOptHdr = &(pNtHdr->OptionalHeader);

    IMAGE_DATA_DIRECTORY* impData= &(pOptHdr->DataDirectory[1]);

    IMAGE_IMPORT_DESCRIPTOR* impTable = (IMAGE_IMPORT_DESCRIPTOR*)(base + impData->VirtualAddress);

    while (true)
    {
        //遇到全0项表示导入表遍历完成
        if (impTable->FirstThunk == NULL && impTable->OriginalFirstThunk == NULL)
        {
            return true;
        }

        //DLL名称为不能为空
        if(impTable->Name==NULL)
        {
            return false;
        }

        //IAT不能为空
        if (impTable->FirstThunk == NULL)
        {
            return false;
        }

        char* dllName = (char*)(base + impTable->Name);
        HMODULE hDll= Pfn_LoadLibraryA(dllName);
        if (hDll == NULL)
        {
            return false;
        }

        DWORD* iat = (DWORD*)(base + impTable->FirstThunk);
        DWORD* intt = NULL;

        //INT表为空，从IAT获取INT
        if (impTable->OriginalFirstThunk == NULL)
        {
            intt = iat;
        }
        else
        {
            intt = (DWORD*)(base + impTable->OriginalFirstThunk);
        }

        //遍历INT
        int index = 0;
        while (true)
        {
            DWORD item = intt[index];

            //遇到 0 项说明遍历完成 
            if (item == NULL)
            {
                break;
            }

            // 高位为1，序号导出。
            DWORD addr = 0;
            if ((item & 0x80000000) == 0x80000000)
            {
                addr=(DWORD)LoadProcAddress((char*)hDll, (const char*)(item&0xffff), Pfn_LoadLibraryA);
            }
            else
            {
                IMAGE_IMPORT_BY_NAME* pName = (IMAGE_IMPORT_BY_NAME*)(item+base);
                addr = (DWORD)LoadProcAddress((char*)hDll,&(pName->Name[0]),Pfn_LoadLibraryA);
            }

            iat[index] = addr;
            index++;
        }

        impTable++;
    }

}

void Entry()
{
    char Str_LoadLibraryA[] = { 'L','o','a','d','L','i','b','r','a','r','y','A','\0'};
    char Str_MessageBoxA[] = { 'M','e','s','s','a','g','e','B','o','x','A','\0'};
    char Str_GetModuleHandleA[] = { 'G','e','t','M','o','d','u','l','e','H','a','n','d','l','e','A','\0' };

    char Str_CreateCompressor[] = { 'C','r','e','a','t','e','C','o','m','p','r','e','s','s','o','r','\0' };
    char Str_Compress[] = { 'C','o','m','p','r','e','s','s','\0' };
    char Str_CloseCompressor[] = { 'C','l','o','s','e','C','o','m','p','r','e','s','s','o','r','\0' };
    char Str_Decompress[] = { 'D','e','c','o','m','p','r','e','s','s','\0' };
    char Str_CreateDecompressor[] = { 'C','r','e','a','t','e','D','e','c','o','m','p','r','e','s','s','o','r','\0' };
    char Str_CloseDecompressor[] = { 'C','l','o','s','e','D','e','c','o','m','p','r','e','s','s','o','r','\0' };

    char Str_CloseHandle[] = { 'C','l','o','s','e','H','a','n','d','l','e','\0' };

    char Str_VirtualAlloc[] = { 'V','i','r','t','u','a','l','A','l','l','o','c','\0' };
    char Str_VirtualFree[] = { 'V','i','r','t','u','a','l','F','r','e','e','\0' };
    char Str_VirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t','\0' };


    char Str_Dll_User32[] = { 'U','s','e','r','3','2','\0' };
    char Str_Dll_Cabinet[] = { 'C','a','b','i','n','e','t','\0'};

    int peb = GetPeb();
    int hKernel32 = GetKernel32(peb);

    PFN_LoadLibraryA Pfn_LoadLibraryA = (PFN_LoadLibraryA)LoadProcAddress((char*)hKernel32, Str_LoadLibraryA, NULL);
    HMODULE hUser32 = Pfn_LoadLibraryA(Str_Dll_User32);
    PFN_MessageBoxA Pfn_MessageBoxA = (PFN_MessageBoxA)LoadProcAddress((char*)hUser32, Str_MessageBoxA, Pfn_LoadLibraryA);
    PFN_GetModuleHandleA Pfn_GetModuleHandleA = (PFN_GetModuleHandleA)LoadProcAddress((char*)hKernel32, Str_GetModuleHandleA, Pfn_LoadLibraryA);
    
    HMODULE hCabinet = Pfn_LoadLibraryA(Str_Dll_Cabinet);
    PFN_CreateCompressor Pfn_CreateCompressor = (PFN_CreateCompressor)LoadProcAddress((char*)hCabinet, Str_CreateCompressor, Pfn_LoadLibraryA);
    PFN_Compress Pfn_Compress = (PFN_Compress)LoadProcAddress((char*)hCabinet, Str_Compress, Pfn_LoadLibraryA);
    PFN_CloseCompressor Pfn_CloseCompressor = (PFN_CloseCompressor)LoadProcAddress((char*)hCabinet, Str_CloseCompressor, Pfn_LoadLibraryA);
    PFN_Decompress Pfn_Decompress = (PFN_Decompress)LoadProcAddress((char*)hCabinet, Str_Decompress, Pfn_LoadLibraryA);
    PFN_CreateDecompressor Pfn_CreateDecompressor = (PFN_CreateDecompressor)LoadProcAddress((char*)hCabinet, Str_CreateDecompressor, Pfn_LoadLibraryA);
    PFN_CloseDecompressor Pfn_CloseDecompressor = (PFN_CloseDecompressor)LoadProcAddress((char*)hCabinet, Str_CloseDecompressor, Pfn_LoadLibraryA);

    PFN_CloseHandle Pfn_CloseHandle = (PFN_CloseHandle)LoadProcAddress((char*)hKernel32, Str_CloseHandle, Pfn_LoadLibraryA);

    PFN_VirtualAlloc Pfn_VirtualAlloc = (PFN_VirtualAlloc)LoadProcAddress((char*)hKernel32, Str_VirtualAlloc, Pfn_LoadLibraryA);
    PFN_VirtualFree Pfn_VirtualFree = (PFN_VirtualFree)LoadProcAddress((char*)hKernel32, Str_VirtualFree, Pfn_LoadLibraryA);
    PFN_VirtualProtect Pfn_VirtualProtect = (PFN_VirtualProtect)LoadProcAddress((char*)hKernel32, Str_VirtualProtect, Pfn_LoadLibraryA);


    char* base= (char*)Pfn_GetModuleHandleA(NULL);

    IMAGE_DOS_HEADER* pPackDos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS32* pPackNt = (IMAGE_NT_HEADERS32*)(base + pPackDos->e_lfanew);
    IMAGE_OPTIONAL_HEADER32* pPackOpt = &(pPackNt->OptionalHeader);

    //第一个节
    IMAGE_SECTION_HEADER* pSec = (IMAGE_SECTION_HEADER*)((char*)(&pPackNt->OptionalHeader) + pPackNt->FileHeader.SizeOfOptionalHeader);
    IMAGE_SECTION_HEADER* pDataSec = &(pSec[2]);
 
    char* pComData = base + pDataSec->VirtualAddress;
    PackInfo* pInfo = (PackInfo*)pComData;
    //获取PE头
    char* pHdr= GetHdrData(pComData, Pfn_CreateDecompressor, Pfn_CloseDecompressor, Pfn_Decompress, Pfn_VirtualAlloc);
    if (pHdr == NULL)
    {
        return;
    }

    //获取节
    char* pSecData = GetSecData(pComData, Pfn_CreateDecompressor, Pfn_CloseDecompressor, Pfn_Decompress, Pfn_VirtualAlloc);
    if (pHdr == NULL)
    {
        return;
    }

    BOOL bRet = SetPEData(base,pHdr, pSecData,pInfo, Pfn_VirtualProtect);
    if (bRet == FALSE)
    {
        return;
    }

    bRet = Pfn_VirtualFree(pHdr, 0, MEM_RELEASE);
    if (bRet == FALSE)
    {
        return;
    }

    bRet = Pfn_VirtualFree(pSecData, 0, MEM_RELEASE);
    if (bRet == FALSE)
    {
        return;
    }

    //修复导入表
    bRet=FixImportTable(base, Pfn_LoadLibraryA);
    if (bRet == FALSE)
    {
        return;
    }



    DWORD oep = (DWORD)(base + pPackNt->OptionalHeader.AddressOfEntryPoint);
    __asm
    {
        jmp oep
    }

}
