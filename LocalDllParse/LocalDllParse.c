#include <Windows.h>
#include <stdio.h>
#include "Header.h"



//Taken from : https://newbedev.com/c-library-to-read-exe-version-from-linux
#define READ_BYTE(p) (((unsigned char*)(p))[0])
#define READ_WORD(p) ((((unsigned char*)(p))[0]) | ((((unsigned char*)(p))[1]) << 8))
#define READ_DWORD(p) ((((unsigned char*)(p))[0]) | ((((unsigned char*)(p))[1]) << 8) | \
    ((((unsigned char*)(p))[2]) << 16) | ((((unsigned char*)(p))[3]) << 24))

#define PAD(x) (((x) + 3) & 0xFFFFFFFC)

int PrintVersion(const char* version, int offs)
{
	offs = PAD(offs);
	WORD len = READ_WORD(version + offs);
	offs += 2;
	WORD valLen = READ_WORD(version + offs);
	offs += 2;
	WORD type = READ_WORD(version + offs);
	offs += 2;
	char info[200];
	int i;
	for (i = 0; i < 200; ++i)
	{
		WORD c = READ_WORD(version + offs);
		offs += 2;

		info[i] = c;
		if (!c)
			break;
	}
	offs = PAD(offs);
	if (type != 0) //TEXT
	{
		char value[200];
		for (i = 0; i < valLen; ++i)
		{
			WORD c = READ_WORD(version + offs);
			offs += 2;
			value[i] = c;
		}
		value[i] = 0;
		if (strlen(info) > 0)
		{
			//This is an identifer in memory, no need to print it
			if (_stricmp(info, "040904b0") != 0)
			{
				printf("[+] %s: %s\n", info, value);
			}
		}

	}
	else
	{
		if (_stricmp(info, "VS_VERSION_INFO") == 0)
		{
			//fixed is a VS_FIXEDFILEINFO
			const char* fixed = version + offs;
			WORD fileA = READ_WORD(fixed + 10);
			WORD fileB = READ_WORD(fixed + 8);
			WORD fileC = READ_WORD(fixed + 14);
			WORD fileD = READ_WORD(fixed + 12);
			WORD prodA = READ_WORD(fixed + 18);
			WORD prodB = READ_WORD(fixed + 16);
			WORD prodC = READ_WORD(fixed + 22);
			WORD prodD = READ_WORD(fixed + 20);
			printf("\tFile: %d.%d.%d.%d\n", fileA, fileB, fileC, fileD);
			printf("\tProd: %d.%d.%d.%d\n", prodA, prodB, prodC, prodD);
		}
		offs += valLen;
	}
	while (offs < len)
		offs = PrintVersion(version, offs);
	return PAD(offs);

}

//Find the resources in each module
VOID ParseResource(HMODULE hMod)
{
	char* pBaseAddr = (char*)hMod;

	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
	IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;

	// Parsing resource data
	IMAGE_DATA_DIRECTORY* pResourceDir = &pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	IMAGE_RESOURCE_DIRECTORY* resSec = (IMAGE_RESOURCE_DIRECTORY*)(pBaseAddr + pResourceDir->VirtualAddress);

	if (resSec == NULL) return;
	size_t namesNum = resSec->NumberOfNamedEntries;
	size_t idsNum = resSec->NumberOfIdEntries;
	size_t totalEntries = namesNum + idsNum;

	IMAGE_RESOURCE_DIRECTORY_ENTRY* typeEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(resSec + 1);

	//Iterate through all resources checking type
	for (size_t i = 0; i < totalEntries; i++) {

		//16 == RT_VERSION
		if (typeEntry[i].Id == 16)
		{
			//If it isn't a directory, something went wrong
			if (typeEntry[i].DataIsDirectory == 0)
				return;

			DWORD offset = typeEntry[i].OffsetToDirectory;

			//Get the offset to the version directory
			IMAGE_RESOURCE_DIRECTORY* versionDirectory = (IMAGE_RESOURCE_DIRECTORY*)(pBaseAddr + pResourceDir->VirtualAddress + (offset & 0x7FFFFFFF));

			size_t namesNum_ver = versionDirectory->NumberOfNamedEntries;
			size_t idsNum_ver = versionDirectory->NumberOfIdEntries;
			size_t totalEntries_ver = namesNum_ver + idsNum_ver;

			
			IMAGE_RESOURCE_DIRECTORY_ENTRY* et_ver = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(versionDirectory + 1);

			//Next level down to get the language entry
			if (et_ver->DataIsDirectory == 1)
			{
				offset = et_ver->OffsetToDirectory;
				IMAGE_RESOURCE_DIRECTORY* langDir = (IMAGE_RESOURCE_DIRECTORY*)(pBaseAddr + pResourceDir->VirtualAddress + (offset & 0x7FFFFFFF));

				size_t namesNum_lang = langDir->NumberOfNamedEntries;
				size_t idsNum_lang = langDir->NumberOfIdEntries;
				size_t totalEntries_lang = namesNum_lang + idsNum_lang;

				IMAGE_RESOURCE_DIRECTORY_ENTRY* et_lang = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(langDir + 1);

				offset = et_lang->OffsetToData;

				//Actual resource entry
				PIMAGE_RESOURCE_DATA_ENTRY resource = (PIMAGE_RESOURCE_DATA_ENTRY)(pBaseAddr + pResourceDir->VirtualAddress + (offset & 0x7FFFFFFF));
				LPVOID rsrc_data = (LPVOID)(pBaseAddr + (resource->OffsetToData));
				DWORD rsrc_size = resource->Size;

				//Don't need the size because we are manually parsing memory
				PrintVersion((const char*)rsrc_data, 0);

			}

		}

	}

}

//Standard PEB stuff
VOID FindLoadedDlls() {

	// get the offset of Process Environment Block
#ifdef _M_IX86 
	mPEB* ProcEnvBlk = (mPEB*)__readfsdword(0x30);
#else
	mPEB* ProcEnvBlk = (mPEB*)__readgsqword(0x60);
#endif

	mPEB_LDR_DATA* Ldr = ProcEnvBlk->Ldr;
	LIST_ENTRY* ModuleList = NULL;

	ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* pStartListEntry = ModuleList->Flink;

	for (LIST_ENTRY* pListEntry = pStartListEntry;
		pListEntry != ModuleList;
		pListEntry = pListEntry->Flink) {

		// get current Data Table Entry
		mLDR_DATA_TABLE_ENTRY* pEntry = (mLDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

		//Skip these
		if (_wcsicmp(pEntry->BaseDllName.Buffer, L"ntdll.dll") == 0)
			continue;
		if (_wcsicmp(pEntry->BaseDllName.Buffer, L"kernel32.dll") == 0)
			continue;
		if (_wcsicmp(pEntry->BaseDllName.Buffer, L"KERNELBASE.dll") == 0)
			continue;
		if (_wcsicmp(pEntry->BaseDllName.Buffer, L"msvcrt.dll") == 0)
			continue;

		//Current module name
		wprintf(L"[*]%s\n", pEntry->BaseDllName.Buffer);
		ParseResource((HMODULE)pEntry->DllBase);
		printf("\n\n");

	}

}





int main()
{

	//Done for demonstration purposes
	LoadLibraryA("amsi.dll");
	FindLoadedDlls();

}

