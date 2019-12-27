#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <vector>
#include <iostream>
#include <algorithm>

#define VA(imageBase, RVA) ((ULONG)imageBase + (ULONG)RVA)

using namespace std;


typedef struct {
	string name;
	ULONG address;
} ITEMINFO;

class IATREC
{
private:	
	DWORD processId;
	HANDLE hProcess;
	HMODULE targetModule;
	LPVOID peImageTarget;
	LPVOID peImageNew;
	DWORD targetModuleSize;

	vector<ITEMINFO> listOfModules;
	vector<ITEMINFO> listOfFunctions;

	ULONG Align(ULONG x, ULONG alignSize);
	HMODULE getTargetModuleImageBase();
	void getLoadModules();

	ULONG addNewIat(DWORD sizeForDllNames, DWORD sizeForThunkArray, DWORD sizeForFunctionNames);
	void fixIAT(DWORD sizeForDllNames, DWORD sizeForThunkArray, DWORD sizeForFunctionNames);
	void IATREC::fixIAT_(DWORD sizeForDllNames, DWORD sizeForThunkArray, DWORD sizeForFunctionNames);

	HMODULE getMuduleAddress(string searchName, vector<ITEMINFO> modules);
	DWORD dumpFromMemRegion(HANDLE hProcess, LPVOID moduleBase, DWORD moduleSize, OUT LPVOID buf);
	vector<ITEMINFO> getAllFunctionExports(HANDLE hProcess, HMODULE mudule);
	string getFuncNameByAddress(ULONG address);	

	BOOL readTargetImagePe();
		
	void getAllModulesFunctions();

	DWORD calcNewIATsize(DWORD &sizeForDllNames, DWORD &sizeForThunkArray, DWORD &sizeForFunctionNames);

	void fixSectionHeaders();

	void fixDump();

	void analize();
	
public:
	IATREC(DWORD processId);
	BOOLEAN dumpIt(LPSTR fileName);
	~IATREC();
};

