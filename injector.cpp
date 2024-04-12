#define CONCAT31(x, y) (((x) << 8) | (y))
typedef unsigned char undefined;

typedef unsigned long long GUID;
typedef void *pointer32;
typedef void *pointer64;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char byte;
typedef unsigned int dword;
typedef unsigned long long qword;
typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned long long undefined8;
typedef unsigned short ushort;
typedef unsigned short wchar16;

typedef unsigned short word;
typedef unsigned long long unkbyte9;
typedef unsigned long long unkbyte10;
typedef unsigned long long unkbyte11;
typedef unsigned long long unkbyte12;
typedef unsigned long long unkbyte13;
typedef unsigned long long unkbyte14;
typedef unsigned long long unkbyte15;
typedef unsigned long long unkbyte16;
typedef unsigned long long unkuint9;
typedef unsigned long long unkuint10;
typedef unsigned long long unkuint11;
typedef unsigned long long unkuint12;
typedef unsigned long long unkuint13;
typedef unsigned long long unkuint14;
typedef unsigned long long unkuint15;
typedef unsigned long long unkuint16;
typedef unsigned long long uintlonglong;
typedef long long unkint9;
typedef long long unkint10;
typedef long long unkint11;
typedef long long unkint12;
typedef long long unkint13;
typedef long long unkint14;
typedef long long unkint15;
typedef long long unkint16;
typedef int int3;
typedef unsigned long long ulonglong;
typedef long long longlong;
typedef bool BOOL;
typedef ulonglong stack0xffffffffffffffd8;
typedef float unkfloat1;
typedef float unkfloat2;
typedef float unkfloat3;
typedef double unkfloat5;
typedef double unkfloat6;
typedef double unkfloat7;
typedef long double unkfloat9;
typedef long double unkfloat11;
typedef long double unkfloat12;
typedef long double unkfloat13;
typedef long double unkfloat14;
typedef long double unkfloat15;
typedef long double unkfloat16;
typedef void BADSPACEBASE;
typedef void code;

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID
{
    void *UniqueProcess;
    void *UniqueThread;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct
{
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion
{
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef ulong DWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__
{
    int unused;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__
{
    int unused;
};

typedef HINSTANCE HMODULE;

typedef DWORD *LPDWORD;

typedef struct HKEY__ *HKEY;

typedef uchar BYTE;

typedef BYTE *LPBYTE;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct
{
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER
{
    word Machine;
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion
{
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY
{
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY
{
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER64
{
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    pointer64 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    qword SizeOfStackReserve;
    qword SizeOfStackCommit;
    qword SizeOfHeapReserve;
    qword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags
{
    IMAGE_SCN_TYPE_NO_PAD = 8,
    IMAGE_SCN_RESERVED_0001 = 16,
    IMAGE_SCN_CNT_CODE = 32,
    IMAGE_SCN_CNT_INITIALIZED_DATA = 64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 128,
    IMAGE_SCN_LNK_OTHER = 256,
    IMAGE_SCN_LNK_INFO = 512,
    IMAGE_SCN_RESERVED_0040 = 1024,
    IMAGE_SCN_LNK_REMOVE = 2048,
    IMAGE_SCN_LNK_COMDAT = 4096,
    IMAGE_SCN_GPREL = 32768,
    IMAGE_SCN_MEM_16BIT = 131072,
    IMAGE_SCN_MEM_PURGEABLE = 131072,
    IMAGE_SCN_MEM_LOCKED = 262144,
    IMAGE_SCN_MEM_PRELOAD = 524288,
    IMAGE_SCN_ALIGN_1BYTES = 1048576,
    IMAGE_SCN_ALIGN_2BYTES = 2097152,
    IMAGE_SCN_ALIGN_4BYTES = 3145728,
    IMAGE_SCN_ALIGN_8BYTES = 4194304,
    IMAGE_SCN_ALIGN_16BYTES = 5242880,
    IMAGE_SCN_ALIGN_32BYTES = 6291456,
    IMAGE_SCN_ALIGN_64BYTES = 7340032,
    IMAGE_SCN_ALIGN_128BYTES = 8388608,
    IMAGE_SCN_ALIGN_256BYTES = 9437184,
    IMAGE_SCN_ALIGN_512BYTES = 10485760,
    IMAGE_SCN_ALIGN_1024BYTES = 11534336,
    IMAGE_SCN_ALIGN_2048BYTES = 12582912,
    IMAGE_SCN_ALIGN_4096BYTES = 13631488,
    IMAGE_SCN_ALIGN_8192BYTES = 14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL = 16777216,
    IMAGE_SCN_MEM_DISCARDABLE = 33554432,
    IMAGE_SCN_MEM_NOT_CACHED = 67108864,
    IMAGE_SCN_MEM_NOT_PAGED = 134217728,
    IMAGE_SCN_MEM_SHARED = 268435456,
    IMAGE_SCN_MEM_EXECUTE = 536870912,
    IMAGE_SCN_MEM_READ = 1073741824,
    IMAGE_SCN_MEM_WRITE = 2147483648
} SectionFlags;

union Misc
{
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER
{
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

struct IMAGE_NT_HEADERS64
{
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

typedef struct IMAGE_THUNK_DATA64 IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;

struct IMAGE_THUNK_DATA64
{
    qword StartAddressOfRawData;
    qword EndAddressOfRawData;
    qword AddressOfIndex;
    qword AddressOfCallBacks;
    dword SizeOfZeroFill;
    dword Characteristics;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY
{
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY
{
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef int PMFN;

typedef struct _s_ThrowInfo _s_ThrowInfo, *P_s_ThrowInfo;

struct _s_ThrowInfo
{
    uint attributes;
    PMFN pmfnUnwind;
    int pForwardCompat;
    int pCatchableTypeArray;
};

typedef struct _s_ThrowInfo ThrowInfo;

typedef long LONG;

typedef LONG LSTATUS;

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

typedef char CHAR;

typedef CHAR *LPCSTR;

typedef WCHAR *LPCWSTR;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER
{
    char e_magic[2];
    word e_cblp;
    word e_cp;
    word e_crlc;
    word e_cparhdr;
    word e_minalloc;
    word e_maxalloc;
    word e_ss;
    word e_sp;
    word e_csum;
    word e_ip;
    word e_cs;
    word e_lfarlc;
    word e_ovno;
    word e_res[4][4];
    word e_oemid;
    word e_oeminfo;
    word e_res2[10][10];
    dword e_lfanew;
    byte e_program[64];
};

ulonglong entry(void);
void FUN_1406031df(void);

ulonglong entry(void)
{
    byte currentByte;
    byte nextByte;
    uint byteCount;
    int loopCounter;
    uint shiftCounter;
    ulonglong result;
    byte shiftedByte;
    int loopIncrement;
    ulonglong returnAddress;
    byte *inputPtr;
    byte *data9;
    byte *outputPtr;
    BOOL carryFlag;
    BOOL currentBit;
    BOOL nextBit;
    BOOL shiftResult;
    BOOL carryResult;
    BOOL tempResult;
    BOOL overflowFlag;
    byte *inputDataPtr;
    byte *outputDataPtr;

    FUN_1406031df();
    shiftedByte = 0x80;
    outputPtr = outputDataPtr;
    do
    {
        currentByte = *inputDataPtr;
        inputDataPtr = inputDataPtr + 1;
        *outputPtr = currentByte;
        outputPtr = outputPtr + 1;
        loopIncrement = 2;
    LAB_14060307e:
        carryFlag = shiftedByte >> 7;
        shiftedByte = shiftedByte << 1;
        currentBit = carryFlag;
        if (shiftedByte == 0)
        {
            shiftedByte = *inputDataPtr;
            inputDataPtr = inputDataPtr + 1;
            currentBit = carryFlag || shiftedByte >> 7;
            shiftedByte = shiftedByte << 1 | carryFlag;
        }
    } while (!currentBit);
    carryFlag = shiftedByte >> 7;
    shiftedByte = shiftedByte << 1;
    currentBit = carryFlag;
    if (shiftedByte == 0)
    {
        shiftedByte = *inputDataPtr;
        inputDataPtr = inputDataPtr + 1;
        currentBit = carryFlag || shiftedByte >> 7;
        shiftedByte = shiftedByte << 1 | carryFlag;
    }
    if (currentBit)
    {
        carryFlag = shiftedByte >> 7;
        shiftedByte = shiftedByte << 1;
        currentBit = carryFlag;
        if (shiftedByte == 0)
        {
            shiftedByte = *inputDataPtr;
            inputDataPtr = inputDataPtr + 1;
            currentBit = carryFlag || shiftedByte >> 7;
            shiftedByte = shiftedByte << 1 | carryFlag;
        }
        if (currentBit)
        {
            carryFlag = shiftedByte >> 7;
            shiftedByte = shiftedByte << 1;
            currentBit = carryFlag;
            if (shiftedByte == 0)
            {
                shiftedByte = *inputDataPtr;
                inputDataPtr = inputDataPtr + 1;
                currentBit = carryFlag || shiftedByte >> 7;
                shiftedByte = shiftedByte << 1 | carryFlag;
            }
            nextBit = shiftedByte >> 7;
            shiftedByte = shiftedByte << 1;
            carryFlag = nextBit;
            if (shiftedByte == 0)
            {
                shiftedByte = *inputDataPtr;
                inputDataPtr = inputDataPtr + 1;
                carryFlag = nextBit || shiftedByte >> 7;
                shiftedByte = shiftedByte << 1 | nextBit;
            }
            shiftResult = shiftedByte >> 7;
            shiftedByte = shiftedByte << 1;
            nextBit = shiftResult;
            if (shiftedByte == 0)
            {
                shiftedByte = *inputDataPtr;
                inputDataPtr = inputDataPtr + 1;
                nextBit = shiftResult || shiftedByte >> 7;
                shiftedByte = shiftedByte << 1 | shiftResult;
            }
            carryResult = shiftedByte >> 7;
            shiftedByte = shiftedByte << 1;
            shiftResult = carryResult;
            if (shiftedByte == 0)
            {
                shiftedByte = *inputDataPtr;
                inputDataPtr = inputDataPtr + 1;
                shiftResult = carryResult || shiftedByte >> 7;
                shiftedByte = shiftedByte << 1 | carryResult;
            }
            tempResult = shiftedByte >> 7;
            shiftedByte = shiftedByte << 1;
            carryResult = tempResult;
            if (shiftedByte == 0)
            {
                shiftedByte = *inputDataPtr;
                inputDataPtr = inputDataPtr + 1;
                carryResult = tempResult || shiftedByte >> 7;
                shiftedByte = shiftedByte << 1 | tempResult;
            }
            overflowFlag = shiftedByte >> 7;
            shiftedByte = shiftedByte << 1;
            tempResult = overflowFlag;
            if (shiftedByte == 0)
            {
                shiftedByte = *inputDataPtr;
                inputDataPtr = inputDataPtr + 1;
                overflowFlag = tempResult || shiftedByte >> 7;
                shiftedByte = shiftedByte << 1 | tempResult;
            }
            byteCount = (((uint)currentBit << 4 | (uint)nextBit << 3 | (uint)carryResult << 2 | (uint)shiftResult << 1 | (uint)overflowFlag));
            if (byteCount != 0)
            {
                byteCount = (uint)outputPtr[-(ulonglong)byteCount];
            }
            *outputPtr = (byte)byteCount;
            outputPtr = outputPtr + 1;
            loopIncrement = 2;
        }
        else
        {
            currentByte = *inputDataPtr;
            inputDataPtr = inputDataPtr + 1;
            nextByte = currentByte >> 1;
            returnAddress = (ulonglong)nextByte;
            if (nextByte == 0)
            {
                return (longlong)outputPtr - (longlong)outputDataPtr & 0xffffffff;
            }
            data9 = outputPtr + -returnAddress;
            for (result = (ulonglong)(((currentByte & 1) != 0) + 2); result != 0; result = result - 1)
            {
                *outputPtr = *data9;
                data9 = data9 + 1;
                outputPtr = outputPtr + 1;
            }
            loopIncrement = 1;
        }
    }
    else
    {
        loopCounter = 1;
        do
        {
            carryFlag = shiftedByte >> 7;
            shiftedByte = shiftedByte << 1;
            currentBit = carryFlag;
            if (shiftedByte == 0)
            {
                shiftedByte = *inputDataPtr;
                inputDataPtr = inputDataPtr + 1;
                currentBit = carryFlag || shiftedByte >> 7;
                shiftedByte = shiftedByte << 1 | carryFlag;
            }
            loopCounter = loopCounter * 2 + (uint)currentBit;
            carryFlag = shiftedByte >> 7;
            shiftedByte = shiftedByte << 1;
            currentBit = carryFlag;
            if (shiftedByte == 0)
            {
                shiftedByte = *inputDataPtr;
                inputDataPtr = inputDataPtr + 1;
                currentBit = carryFlag || shiftedByte >> 7;
                shiftedByte = shiftedByte << 1 | carryFlag;
            }
        } while (currentBit);
        loopCounter = loopCounter - loopIncrement;
        loopIncrement = 1;
        if (loopCounter != 0)
        {
            byteCount = CONCAT31((int3)loopCounter + -1, *inputDataPtr);
            inputDataPtr = inputDataPtr + 1;
            returnAddress = (ulonglong)byteCount;
            result = 1;
            do
            {
                carryFlag = shiftedByte >> 7;
                shiftedByte = shiftedByte << 1;
                currentBit = carryFlag;
                if (shiftedByte == 0)
                {
                    shiftedByte = *inputDataPtr;
                    inputDataPtr = inputDataPtr + 1;
                    currentBit = carryFlag || shiftedByte >> 7;
                    shiftedByte = shiftedByte << 1 | carryFlag;
                }
                byteCount = (int)result * 2 + (uint)currentBit;
                result = (ulonglong)byteCount;
                carryFlag = shiftedByte >> 7;
                shiftedByte = shiftedByte << 1;
                currentBit = carryFlag;
                if (shiftedByte == 0)
                {
                    shiftedByte = *inputDataPtr;
                    inputDataPtr = inputDataPtr + 1;
                    currentBit = carryFlag || shiftedByte >> 7;
                    shiftedByte = shiftedByte << 1 | carryFlag;
                }
            } while (currentBit);
            if (byteCount < 32000)
            {
                if (0x4ff < byteCount)
                {
                    data9 = outputPtr + -(ulonglong)byteCount;
                    for (result = (ulonglong)((byteCount + 1) + loopIncrement); result != 0; result = result - 1)
                    {
                        *outputPtr = *data9;
                        data9 = data9 + 1;
                        outputPtr = outputPtr + 1;
                    }
                    goto LAB_14060307e;
                }
                if (byteCount < 0x80)
                    goto LAB_14060319b;
            }
            else
            {
            LAB_14060319b:
                result = (ulonglong)((byteCount + 2) + loopIncrement);
            }
            data9 = outputPtr + -(ulonglong)byteCount;
            for (; result != 0; result = result - 1)
            {
                *outputPtr = *data9;
                data9 = data9 + 1;
                outputPtr = outputPtr + 1;
            }
            goto LAB_14060307e;
        }
        result = 1;
        do
        {
            carryFlag = shiftedByte >> 7;
            shiftedByte = shiftedByte << 1;
            currentBit = carryFlag;
            if (shiftedByte == 0)
            {
                shiftedByte = *inputDataPtr;
                inputDataPtr = inputDataPtr + 1;
                currentBit = carryFlag || shiftedByte >> 7;
                shiftedByte = shiftedByte << 1 | carryFlag;
            }
            result = (ulonglong)((int)result * 2 + (uint)currentBit);
            carryFlag = shiftedByte >> 7;
            shiftedByte = shiftedByte << 1;
            currentBit = carryFlag;
            if (shiftedByte == 0)
            {
                shiftedByte = *inputDataPtr;
                inputDataPtr = inputDataPtr + 1;
                currentBit = carryFlag || shiftedByte >> 7;
                shiftedByte = shiftedByte << 1 | carryFlag;
            }
        } while (currentBit);
        data9 = outputPtr + -returnAddress;
        for (; result != 0; result = result - 1)
        {
            *outputPtr = *data9;
            data9 = data9 + 1;
            outputPtr = outputPtr + 1;
        }
    }
    goto LAB_14060307e;
}

void FUN_1406031df(void)
{
    code *functionPointer;
    ulonglong *stackPointer;
    code *returnAddress;
    ulonglong stackVar1;
    code *stackVar2;
    ulonglong stackVar3;
    code *stackVar4;

    stackPointer = (ulonglong *)&stackVar3;
    functionPointer = (code *)((long long)returnAddress + 0x1a3fa3);
    stackVar4 = returnAddress;
    if (*(int *)((long long)returnAddress + 0x75ab7) == 0)
    {
        stackVar3 = 0;
        stackVar1 = 0;
        stackVar2 = functionPointer;
        stackVar4 = functionPointer;
        (*(void (*)())returnAddress)();
        stackPointer = &stackVar1;
        functionPointer = (code *)((long long)returnAddress + 0x1cf);
    }
    ((void (*)(ulonglong, ulonglong))(*(long long *)functionPointer + 0x84e84))(*(ulonglong *)((long long)stackPointer + 0x20), *(ulonglong *)((long long)stackPointer + 0x18));
    return;
}
