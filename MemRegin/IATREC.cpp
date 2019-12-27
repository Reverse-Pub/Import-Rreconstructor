#include "IATREC.h"

void getShortPathName(OUT LPSTR shortPath, IN LPCSTR fullpath)
{
	char name[MAX_PATH] = { 0 }, ext[MAX_PATH] = { 0 };
	_splitpath(fullpath, NULL, NULL, name, ext);
	sprintf(shortPath, "%s%s", name, ext);
}

IATREC::IATREC(DWORD processId)
{
	this->processId = processId;	
	peImageNew = peImageTarget = targetModule = NULL;
	targetModuleSize = 0;
}


IATREC::~IATREC()
{
	if (this->hProcess)
		CloseHandle(this->hProcess);
}

ULONG IATREC::Align(ULONG x, ULONG alignSize)
{
	DWORD result = (x % alignSize == 0) ? x : x + (alignSize - (x % alignSize));
	return result;
}

//remake https://stackoverflow.com/questions/26572459/c-get-module-base-address-for-64bit-application
HMODULE IATREC::getTargetModuleImageBase()
{
	HMODULE baseAddress = 0;	
	HMODULE *moduleArray;
	LPBYTE  moduleArrayBytes;
	DWORD  bytesRequired;

	if (hProcess)
	{
		if (EnumProcessModules(hProcess, NULL, 0, &bytesRequired))
		{
			if (bytesRequired)
			{
				moduleArrayBytes = (LPBYTE)LocalAlloc(LPTR, bytesRequired);

				if (moduleArrayBytes)
				{
					unsigned int moduleCount;

					moduleCount = bytesRequired / sizeof(HMODULE);
					moduleArray = (HMODULE *)moduleArrayBytes;

					if (EnumProcessModules(hProcess, moduleArray, bytesRequired, &bytesRequired))
						baseAddress = moduleArray[0];
					LocalFree(moduleArrayBytes);
				}
			}
		}
	}
	return baseAddress;
}

//получает список подгруженных имён модулей и базовыми адресами тапа: {kernel32.dll, 0x7fff0000}
void IATREC::getLoadModules()
{	
	listOfModules.clear();
	if (hProcess)
	{
		DWORD bytesRequired;
		HMODULE *moduleArray;

		if (EnumProcessModules(hProcess, NULL, 0, &bytesRequired))
		{
			if (bytesRequired)
			{
				LPBYTE moduleArrayBytes = (LPBYTE)LocalAlloc(LPTR, bytesRequired);

				if (moduleArrayBytes)
				{
					unsigned int moduleCount;

					moduleCount = bytesRequired / sizeof(HMODULE);
					moduleArray = (HMODULE *)moduleArrayBytes;

					if (EnumProcessModules(hProcess, moduleArray, bytesRequired, &bytesRequired))
					{
						ITEMINFO module;
						char moduleName[MAX_PATH] = { 0 };
						char shortModule[MAX_PATH] = { 0 };
						for (int i = 0; i < moduleCount; i++)
						{
							GetModuleFileNameExA(hProcess, moduleArray[i], (LPSTR)moduleName, sizeof(moduleName));
							getShortPathName(shortModule, moduleName);

							module.name = string(shortModule);
							module.address = (ULONG)moduleArray[i];

							listOfModules.push_back(module);
						}
					}

					LocalFree(moduleArrayBytes);
				}
			}
		}
	}
}

ULONG IATREC::addNewIat(DWORD sizeForDllNames, DWORD sizeForThunkArray, DWORD sizeForFunctionNames)
{
	char *newSecName = ".newiat";
	PIMAGE_NT_HEADERS pOldNtHeader = (PIMAGE_NT_HEADERS)VA(peImageNew, ((PIMAGE_DOS_HEADER)peImageNew)->e_lfanew);
	int newSecSize = Align(sizeForDllNames + sizeForThunkArray + sizeForFunctionNames, pOldNtHeader->OptionalHeader.SectionAlignment);
	DWORD lastSectionNumber = pOldNtHeader->FileHeader.NumberOfSections;
	DWORD oldHeaderSize = pOldNtHeader->OptionalHeader.SizeOfHeaders;
	ULONG newSize = pOldNtHeader->OptionalHeader.SizeOfImage + newSecSize;

	LPVOID newPe = VirtualAlloc(NULL, newSize, MEM_COMMIT, PAGE_READWRITE);
	MoveMemory(newPe, peImageNew, oldHeaderSize);

	PIMAGE_NT_HEADERS pNewNtHeader = (PIMAGE_NT_HEADERS)VA(newPe, ((PIMAGE_DOS_HEADER)newPe)->e_lfanew);
	//DWORD a = Align(0x11, 0x10);
	PIMAGE_SECTION_HEADER firstSection = IMAGE_FIRST_SECTION(pNewNtHeader);
	PIMAGE_SECTION_HEADER pLastSection = &firstSection[lastSectionNumber - 1];

	PIMAGE_SECTION_HEADER newSection = &firstSection[lastSectionNumber];
	DWORD rawOffsetDelta = 0;
	if ((ULONG)newSection + sizeof(IMAGE_SECTION_HEADER) > VA(newPe, pNewNtHeader->OptionalHeader.SizeOfHeaders))
	{
		rawOffsetDelta = pNewNtHeader->OptionalHeader.SizeOfHeaders;
		pNewNtHeader->OptionalHeader.SizeOfHeaders = Align(pNewNtHeader->OptionalHeader.SizeOfHeaders + sizeof(IMAGE_SECTION_HEADER), pNewNtHeader->OptionalHeader.SizeOfHeaders);
		rawOffsetDelta = pNewNtHeader->OptionalHeader.SizeOfHeaders - rawOffsetDelta;
	}


	MoveMemory(newSection->Name, newSecName, 8);
	//SizeOfRawData - пофикшен
	newSection->VirtualAddress = pLastSection->VirtualAddress + pLastSection->SizeOfRawData;
	newSection->SizeOfRawData = newSecSize;
	newSection->Misc.VirtualSize = newSecSize;
	newSection->PointerToRawData = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;
	newSection->Characteristics = 0xC0000040;	//for IAT

	memset((LPVOID)VA(newPe, newSection->VirtualAddress), 0x00, newSecSize);

	pNewNtHeader->OptionalHeader.SizeOfImage += newSecSize;
	pNewNtHeader->FileHeader.NumberOfSections++;
	pNewNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress = newSection->VirtualAddress;
	pNewNtHeader->OptionalHeader.DataDirectory[1].Size = newSection->SizeOfRawData;
	

	PIMAGE_SECTION_HEADER firstOldSection = IMAGE_FIRST_SECTION(pOldNtHeader);
	PIMAGE_SECTION_HEADER firstNewSection = IMAGE_FIRST_SECTION(pNewNtHeader);

	for (int i = 0; i < pOldNtHeader->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER pOldSection = &firstOldSection[i];
		PIMAGE_SECTION_HEADER pNewSection = &firstNewSection[i];
		pNewSection->SizeOfRawData = pOldSection->SizeOfRawData + rawOffsetDelta;
		MoveMemory((LPVOID)VA(newPe, pNewSection->VirtualAddress), (LPVOID)VA(peImageNew, pOldSection->VirtualAddress), pOldSection->Misc.VirtualSize);
	}


	VirtualFree(peImageNew, pOldNtHeader->OptionalHeader.SizeOfImage, MEM_RELEASE);
	peImageNew = newPe;	
	return newSize;
}

HMODULE IATREC::getMuduleAddress(string searchName, vector<ITEMINFO> modules)
{
	for (vector<ITEMINFO>::const_iterator module = modules.begin(); module != modules.end(); ++module)
		if ((*module).name == searchName)
			return (HMODULE)(*module).address;
	return NULL;
}

//Копирует размапленный pe модуль из указанного контекста процесса, начиная с moduleBase и до конца в Buf
DWORD IATREC::dumpFromMemRegion(HANDLE hProcess, LPVOID moduleBase, DWORD moduleSize, OUT LPVOID buf)
{
	MEMORY_BASIC_INFORMATION pMbi;
	ULONG address = 0;
	DWORD size = sizeof(MEMORY_BASIC_INFORMATION);
	PVOID prevRegionAddress = 0;
	SYSTEM_INFO systemInfo = { 0 };
	LPVOID pointer = buf;
	DWORD readed = 0;
	DWORD result = 1;

	address = (ULONG)moduleBase;
	while (address < (ULONG)moduleBase + moduleSize)
	{
		VirtualQueryEx(hProcess, (LPCVOID)address, &pMbi, size);
		if (pMbi.State == MEM_COMMIT)
		{
			if (prevRegionAddress != pMbi.AllocationBase)
				prevRegionAddress = pMbi.BaseAddress;

			result &= ReadProcessMemory(hProcess, (LPVOID)address, pointer, pMbi.RegionSize, &readed);

			if (!result)
				break;
		}
		address += (DWORD)pMbi.RegionSize;
		pointer = (LPVOID)((ULONG)pointer + pMbi.RegionSize);
	}
	return result;
}

vector<ITEMINFO> IATREC::getAllFunctionExports(HANDLE hProcess, HMODULE mudule)
{
	vector<ITEMINFO> result;
	LPVOID peFile = NULL;
	IMAGE_DOS_HEADER dosHeader = { 0 };
	IMAGE_NT_HEADERS ntHeader = { 0 };
	DWORD readed = 0, status = 0;
	LPVOID exportTable = NULL;

	ReadProcessMemory(hProcess, mudule, &dosHeader, sizeof(dosHeader), &readed);
	ReadProcessMemory(hProcess, (LPVOID)VA(mudule, dosHeader.e_lfanew), &ntHeader, sizeof(ntHeader), &readed);

	peFile = VirtualAlloc(NULL, ntHeader.OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	status = dumpFromMemRegion(hProcess, mudule, ntHeader.OptionalHeader.SizeOfImage, peFile);

	if (status)
	{
		PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)(VA(peFile, ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
		ULONG_PTR *names = (ULONG_PTR *)VA(peFile, pExportTable->AddressOfNames);
		WORD *ordunals = (WORD *)VA(peFile, pExportTable->AddressOfNameOrdinals);
		ULONG_PTR *addresses = (ULONG_PTR *)VA(peFile, pExportTable->AddressOfFunctions);
		ITEMINFO item;

		for (int i = 0; i < pExportTable->NumberOfNames; i++)
		{
			char * functionName = (char *)VA(peFile, names[i]);
			WORD ordinal = VA(peFile, ordunals[i]);
			ULONG address = VA(mudule, addresses[ordinal]);
			item.address = address;
			item.name = string(functionName);
			result.push_back(item);
		}
		return result;

	}

}

void IATREC::getAllModulesFunctions()
{
	DWORD status = true;
	IMAGE_DOS_HEADER dosHeader = { 0 };
	IMAGE_NT_HEADERS ntHeader = { 0 };
	DWORD bytesRead = 0;	

	listOfFunctions.clear();

	
	for (vector<ITEMINFO>::const_iterator module = listOfModules.begin(); module != listOfModules.end(); ++module)
	{		
		if (module->address != (ULONG)targetModule)
		{
			status &= ReadProcessMemory(hProcess, (LPVOID)module->address, &dosHeader, sizeof(dosHeader), &bytesRead);
			status &= ReadProcessMemory(hProcess, (LPVOID)((ULONG)module->address + dosHeader.e_lfanew), &ntHeader, sizeof(ntHeader), &bytesRead);

			LPVOID peModuleImage = VirtualAlloc(NULL, ntHeader.OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);

			status &= dumpFromMemRegion(hProcess, (LPVOID)module->address, ntHeader.OptionalHeader.SizeOfImage, peModuleImage);

			if (status)
			{				
				ULONG rvaExp = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;				
				if (rvaExp)
				{
					PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)(VA(peModuleImage, rvaExp));
					ULONG_PTR *names = (ULONG_PTR *)VA(peModuleImage, pExportTable->AddressOfNames);
					WORD *ordunals = (WORD *)VA(peModuleImage, pExportTable->AddressOfNameOrdinals);
					ULONG_PTR *addresses = (ULONG_PTR *)VA(peModuleImage, pExportTable->AddressOfFunctions);
					ITEMINFO item;

					for (int i = 0; i < pExportTable->NumberOfNames; i++)
					{
						char * functionName = (char *)VA(peModuleImage, names[i]);
						WORD ordinal = VA(peModuleImage, ordunals[i]);
						ULONG address = VA(module->address, addresses[ordinal]);
						item.address = address;
						item.name = string(functionName);
						listOfFunctions.push_back(item);
					}
				}
			}

			VirtualFree(peModuleImage, ntHeader.OptionalHeader.SizeOfImage, MEM_RELEASE);
		}
	}
}

string IATREC::getFuncNameByAddress(ULONG address)
{
	for (vector<ITEMINFO>::iterator func = listOfFunctions.begin(); func != listOfFunctions.end(); ++func)
	{
		if (func->address == address)
			return func->name;
	}
	return "";
}

void IATREC::fixIAT(DWORD sizeForDllNames, DWORD sizeForThunkArray, DWORD sizeForFunctionNames)
{
	
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)VA(peImageTarget, ((PIMAGE_DOS_HEADER)peImageTarget)->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImportTableOrigin = (PIMAGE_IMPORT_DESCRIPTOR)VA(peImageTarget, pNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress);
	
	PIMAGE_NT_HEADERS pNewNtHeader = (PIMAGE_NT_HEADERS)VA(peImageNew, ((PIMAGE_DOS_HEADER)peImageNew)->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImportTableNew = (PIMAGE_IMPORT_DESCRIPTOR)VA(peImageNew, pNewNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress);
	
	
	ULONG_PTR pStartDllName = (ULONG)pImportTableNew + sizeof(IMAGE_IMPORT_DESCRIPTOR) * listOfModules.size();
	PIMAGE_THUNK_DATA pStartFirstThunk = (PIMAGE_THUNK_DATA)(pStartDllName + sizeForDllNames);
	ULONG_PTR pStartFuncName = (ULONG)pStartFirstThunk + sizeForThunkArray;
		
	LPSTR currentDllName = (LPSTR)pStartDllName;
	LPSTR currentFuncName = (LPSTR)pStartFuncName;
	PIMAGE_THUNK_DATA currentFirstThunk = pStartFirstThunk;

	PIMAGE_IMPORT_DESCRIPTOR newImportTable = pImportTableNew;

	for (PIMAGE_IMPORT_DESCRIPTOR importTable = pImportTableOrigin, newImportTable = pImportTableNew; 
								  importTable->FirstThunk; 
								  importTable++, newImportTable++)
	{
		string dllName = string((LPCSTR)VA(peImageTarget, importTable->Name));		
		

		newImportTable->Characteristics = 0;
		newImportTable->Name = (ULONG)currentDllName - (ULONG)peImageNew;			//RVA of dll names
		lstrcpyA(currentDllName, dllName.c_str());
		newImportTable->FirstThunk = (ULONG)currentFirstThunk - (ULONG)peImageNew;	//RVA of thunk array
		
		for (PIMAGE_THUNK_DATA pThunkOrigin = (PIMAGE_THUNK_DATA)VA(peImageTarget, importTable->FirstThunk);
							   pThunkOrigin->u1.Function; 
							   pThunkOrigin++)
		{
			DWORD address = pThunkOrigin->u1.AddressOfData;			
			string discoveredFuncName = getFuncNameByAddress(address);
			
			lstrcpyA(currentFuncName + 2, discoveredFuncName.c_str());
			currentFirstThunk->u1.Function = (ULONG)currentFuncName - (ULONG)peImageNew;	//RVA of function name
			printf("0x%08x : %s\n", address, discoveredFuncName.c_str());
			currentFuncName = currentFuncName + discoveredFuncName.length() + 2;
			currentFirstThunk++;
		}
		currentFirstThunk++;		//00000000 thunk in the end of array
		currentDllName = currentDllName + dllName.length() + 1;
	}

	return;
}

void IATREC::fixIAT_(DWORD sizeForDllNames, DWORD sizeForThunkArray, DWORD sizeForFunctionNames)
{

	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)VA(peImageTarget, ((PIMAGE_DOS_HEADER)peImageTarget)->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImportTableOrigin = (PIMAGE_IMPORT_DESCRIPTOR)VA(peImageTarget, pNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress);

	PIMAGE_NT_HEADERS pNewNtHeader = (PIMAGE_NT_HEADERS)VA(peImageNew, ((PIMAGE_DOS_HEADER)peImageNew)->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImportTableNew = (PIMAGE_IMPORT_DESCRIPTOR)VA(peImageNew, pNewNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress);	
	
	PIMAGE_THUNK_DATA pStartFirstThunk = (PIMAGE_THUNK_DATA)VA(pNewNtHeader, pImportTableNew->FirstThunk);
	ULONG_PTR pStartDllName = VA(pNewNtHeader, pImportTableNew->Name);
	
	ULONG_PTR pStartFuncName = max((ULONG)pStartFirstThunk + sizeForThunkArray, (ULONG)pStartDllName + sizeForDllNames);
			  pStartFuncName = max((ULONG)pStartFuncName, (ULONG)pStartFirstThunk + sizeForThunkArray);

	LPSTR currentDllName = (LPSTR)pStartDllName;
	LPSTR currentFuncName = (LPSTR)pStartFuncName;
	PIMAGE_THUNK_DATA currentFirstThunk = pStartFirstThunk;

	PIMAGE_IMPORT_DESCRIPTOR newImportTable = pImportTableNew;

	ZeroMemory(pImportTableNew, pNewNtHeader->OptionalHeader.DataDirectory[1].Size);

	for (PIMAGE_IMPORT_DESCRIPTOR importTable = pImportTableOrigin, newImportTable = pImportTableNew;
		importTable->FirstThunk;
		importTable++, newImportTable++)
	{
		string dllName = string((LPCSTR)VA(peImageTarget, importTable->Name));


		newImportTable->Characteristics = 0;
		newImportTable->Name = (ULONG)currentDllName - (ULONG)peImageNew;			//RVA of dll names
		lstrcpyA(currentDllName, dllName.c_str());
		newImportTable->FirstThunk = (ULONG)currentFirstThunk - (ULONG)peImageNew;	//RVA of thunk array

		for (PIMAGE_THUNK_DATA pThunkOrigin = (PIMAGE_THUNK_DATA)VA(peImageTarget, importTable->FirstThunk);
			pThunkOrigin->u1.Function;
			pThunkOrigin++)
		{
			DWORD address = pThunkOrigin->u1.AddressOfData;
			string discoveredFuncName = getFuncNameByAddress(address);

			lstrcpyA(currentFuncName + 2, discoveredFuncName.c_str());
			currentFirstThunk->u1.Function = (ULONG)currentFuncName - (ULONG)peImageNew;	//RVA of function name
			printf("0x%08x : %s\n", address, discoveredFuncName.c_str());
			currentFuncName = currentFuncName + discoveredFuncName.length() + 2;
			currentFirstThunk++;
		}
		currentFirstThunk++;		//00000000 thunk in the end of array
		currentDllName = currentDllName + dllName.length() + 1;
	}

	return;
}

BOOL IATREC::readTargetImagePe()
{
	BOOL status = true;
	
	if (targetModule)
	{
		IMAGE_DOS_HEADER dosHeader = { 0 };
		IMAGE_NT_HEADERS ntHeader = { 0 };
		DWORD bytesRead = 0;

		status &= ReadProcessMemory(hProcess, targetModule, &dosHeader, sizeof(dosHeader), &bytesRead);
		status &= ReadProcessMemory(hProcess, (LPVOID)((ULONG)targetModule + dosHeader.e_lfanew), &ntHeader, sizeof(ntHeader), &bytesRead);
		
		peImageTarget = VirtualAlloc(NULL, ntHeader.OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
		if (peImageTarget)
		{
			//читаем все заголовки
			status = ReadProcessMemory(hProcess, targetModule, peImageTarget, ntHeader.OptionalHeader.SizeOfHeaders, &bytesRead);

			//копируем все секции целевого pe-шника
			PIMAGE_SECTION_HEADER firstSectionHeader = IMAGE_FIRST_SECTION((PIMAGE_NT_HEADERS)((ULONG)peImageTarget + dosHeader.e_lfanew));

			for (int i = 0; i < ntHeader.FileHeader.NumberOfSections; i++)
			{
				PIMAGE_SECTION_HEADER pSection = &firstSectionHeader[i];

				LPVOID p = (LPVOID)VA(peImageTarget, pSection->VirtualAddress);
				status &= ReadProcessMemory(hProcess, (LPVOID)VA(targetModule, pSection->VirtualAddress), p, pSection->SizeOfRawData, &bytesRead);
			}

		}

		peImageNew = VirtualAlloc(NULL, ntHeader.OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
		MoveMemory(peImageNew, peImageTarget, ntHeader.OptionalHeader.SizeOfImage);
		targetModuleSize = ntHeader.OptionalHeader.SizeOfImage;
	}
	return status;
}

//set raw size equal virtual size
void IATREC::fixSectionHeaders()
{
	
	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(peImageNew);
	PIMAGE_NT_HEADERS pNtHeader = PIMAGE_NT_HEADERS(VA(peImageNew, pDosHeader->e_lfanew));

	PIMAGE_SECTION_HEADER pFirstSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER pSection = &pFirstSectionHeader[i];

		DWORD virtualSize = Align(pSection->Misc.VirtualSize, pNtHeader->OptionalHeader.SectionAlignment);			
		pSection->SizeOfRawData = virtualSize;
		pSection->PointerToRawData = pSection->VirtualAddress;
	}

}

DWORD IATREC::calcNewIATsize(DWORD &sizeForDllNames, DWORD &sizeForThunkArray, DWORD &sizeForFunctionNames)
{
	int i = 0;
	DWORD total = 0, status = true, bytesRead = 0;
	sizeForDllNames = sizeForThunkArray = sizeForFunctionNames = 0;

	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(peImageTarget);
	PIMAGE_NT_HEADERS pNtHeader = PIMAGE_NT_HEADERS(VA(peImageTarget, pDosHeader->e_lfanew));
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)VA(peImageTarget, pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	if (pImportTable)
	{
		for (PIMAGE_IMPORT_DESCRIPTOR currentImportDll = pImportTable, i = 0; currentImportDll->FirstThunk; currentImportDll++, i++)
		{
			LPSTR dllName = (LPSTR)VA(peImageTarget, currentImportDll->Name);
			sizeForDllNames += lstrlenA(dllName) + 1;

			for (PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA)VA(peImageTarget, currentImportDll->FirstThunk); pThunk->u1.Function; pThunk++)
			{
				string discoveredFuncName = getFuncNameByAddress(pThunk->u1.Function);
				sizeForFunctionNames += (discoveredFuncName.length() + 3);	//2 byte to ordinal and 1 to NULL term
				sizeForThunkArray += sizeof(IMAGE_THUNK_DATA);
			}
			sizeForThunkArray += sizeof(IMAGE_THUNK_DATA);	//00000000 thunks
		}
		total = sizeForDllNames + sizeForThunkArray + sizeForFunctionNames;
	}

	return total;
}

void IATREC::analize()
{	
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	targetModule = getTargetModuleImageBase();

	readTargetImagePe();

	getLoadModules();

	getAllModulesFunctions();
}

BOOLEAN IATREC::dumpIt(LPSTR fileName)
{
	DWORD status = 0, error = 0;
	HANDLE hDumpFile = 0;

	analize();

	fixSectionHeaders();

	hDumpFile = CreateFileA(fileName, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (fileName != INVALID_HANDLE_VALUE)
	{
		DWORD sizeForDllNames, sizeForThunkArray, sizeForFunctionNames;
		DWORD newIATsize = calcNewIATsize(sizeForDllNames, sizeForThunkArray, sizeForFunctionNames);
		
		//ULONG  peImageNewSize = addNewIat(sizeForDllNames, sizeForThunkArray, sizeForFunctionNames);
		//fixIAT(sizeForDllNames, sizeForThunkArray, sizeForFunctionNames);
		fixIAT_(sizeForDllNames, sizeForThunkArray, sizeForFunctionNames);
		status = WriteFile(hDumpFile, peImageNew, targetModuleSize, NULL, 0);
	}

	CloseHandle(hDumpFile);
	return status;
}