#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>


#include <iostream>

#include "IATREC.h"

using namespace std;


DWORD getProccessID(LPSTR procName)
{

	HANDLE hSnapshot;
	PROCESSENTRY32 Entry;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	Entry.dwSize = sizeof(Entry);
	if (Process32First(hSnapshot, &Entry))
	{
		CHAR szProcessName[MAX_PATH] = "";
		WideCharToMultiByte(CP_ACP, 0, Entry.szExeFile, -1, szProcessName, MAX_PATH, NULL, NULL);

		if (!strcmp(procName, szProcessName))
			return Entry.th32ProcessID;

		while (Process32Next(hSnapshot, &Entry))
		{
			WideCharToMultiByte(CP_ACP, 0, Entry.szExeFile, -1, szProcessName, MAX_PATH, NULL, NULL);
			if (!strcmp(procName, szProcessName))
				return Entry.th32ProcessID;
		}
	}

	return 0;
}

void main()
{	
	DWORD pid = getProccessID("CRACKME.EXE");
	LPSTR dumpToFile= "D:\\Languages\\fasm\\dz\\other\\dump.exe";

	IATREC importRec(pid);
	importRec.dumpIt(dumpToFile);
}

