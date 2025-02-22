#include <Windows.h>
#include <iostream>
#include <Psapi.h>
#include <TlHelp32.h>
#include <sddl.h>
#include <iomanip>
#include <tchar.h>
#include <vector>
#include <unordered_map>
#include <string.h>

using namespace std;

wstring GetUser(DWORD processID);
double GetCPUUsage(HANDLE hProcess, DWORD processID);
SIZE_T GetMemoryUsage(HANDLE hProcess);

void PrintProcessInfo(const wstring& processName, DWORD processID, bool requiresAdmin)
{
    wstring username = GetUser(processID);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

    double cpuUsage = (hProcess != NULL) ? GetCPUUsage(hProcess, processID) : 0.0;
    SIZE_T memoryUsage = (hProcess != NULL) ? GetMemoryUsage(hProcess) : 0;

    wcout << L"| " << left << setw(25) << processName
        << L" | " << right << setw(8) << processID
        << L" | " << left << setw(20) << (requiresAdmin ? L"Requires Admin" : username)
        << L" | " << setw(8) << fixed << setprecision(2) << cpuUsage << L"%"
        << L" | " << setw(10) << memoryUsage / 1024 << L" KB |" << endl;

    if (hProcess) CloseHandle(hProcess);
}

void PrintTableHeader()
{
    wcout << L"\n===================================================================================================" << endl;
    wcout << L"| " << left << setw(25) << L"Process Name"
        << L" | " << right << setw(8) << L"PID"
        << L" | " << left << setw(20) << L"Status"
        << L" | " << setw(8) << L"CPU %"
        << L" | " << setw(10) << L"Memory KB |" << endl;
    wcout << L"===================================================================================================" << endl;
}

wstring GetUser(DWORD processID)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (!hProcess)
        return L"Access Denied";

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        CloseHandle(hProcess);
        return L"Access Denied";
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (dwSize == 0)
    {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return L"Unknown";
    }

    TOKEN_USER* pTokenUser = (TOKEN_USER*)new BYTE[dwSize];
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize))
    {
        delete[] pTokenUser;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return L"Unknown";
    }

    WCHAR szUserName[256], szDomainName[256];
    DWORD dwUserSize = sizeof(szUserName) / sizeof(WCHAR);
    DWORD dwDomainSize = sizeof(szDomainName) / sizeof(WCHAR);
    SID_NAME_USE sidType;

    if (!LookupAccountSid(NULL, pTokenUser->User.Sid, szUserName, &dwUserSize, szDomainName, &dwDomainSize, &sidType))
    {
        delete[] pTokenUser;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return L"Unknown";
    }

    wstring username = wstring(szDomainName) + L"\\" + wstring(szUserName);

    delete[] pTokenUser;
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return username;
}

double GetCPUUsage(HANDLE hProcess, DWORD processID)
{
    static unordered_map<DWORD, ULONGLONG> lastCPUTime;
    static unordered_map<DWORD, ULONGLONG> lastSysTime;

    FILETIME ftCreate, ftExit, ftKernel, ftUser, ftNow;

    if (!GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser))
        return 0.0;

    GetSystemTimeAsFileTime(&ftNow);

    ULARGE_INTEGER ulSysTime, ulUserTime, ulNow;
    ulSysTime.LowPart = ftKernel.dwLowDateTime;
    ulSysTime.HighPart = ftKernel.dwHighDateTime;
    ulUserTime.LowPart = ftUser.dwLowDateTime;
    ulUserTime.HighPart = ftUser.dwHighDateTime;
    ulNow.LowPart = ftNow.dwLowDateTime;
    ulNow.HighPart = ftNow.dwHighDateTime;

    ULONGLONG totalTime = ulSysTime.QuadPart + ulUserTime.QuadPart;
    ULONGLONG nowTime = ulNow.QuadPart;

    if (lastCPUTime.find(processID) == lastCPUTime.end())
    {
        lastCPUTime[processID] = totalTime;
        lastSysTime[processID] = nowTime;
        return 0.0;
    }

    ULONGLONG prevCPUTime = lastCPUTime[processID];
    ULONGLONG prevSysTime = lastSysTime[processID];

    ULONGLONG cpuDiff = totalTime - prevCPUTime;
    ULONGLONG sysDiff = nowTime - prevSysTime;

    lastCPUTime[processID] = totalTime;
    lastSysTime[processID] = nowTime;

    if (sysDiff == 0) return 0.0;

    double cpuUsage = (double)(cpuDiff * 100) / sysDiff;

    return cpuUsage;
}

    SIZE_T GetMemoryUsage(HANDLE hProcess)
    {
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
        {
            return pmc.WorkingSetSize;
        }
        return 0;
    }


wstring GetProcessNameBySnapshot(DWORD processID)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return L"<unknown>";

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32))
    {
        do
        {
            if (pe32.th32ProcessID == processID)
            {
                CloseHandle(hSnapshot);
                return pe32.szExeFile;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return L"<unknown>";
}

int main()
{
    DWORD aProcesses[1024], cbNeeded, cProcesses;

    wcout << L"Scanning processes...\n" << endl;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        wcout << L"Error: Unable to retrieve process list! Error: " << GetLastError() << endl;
        return 1;
    }

    cProcesses = cbNeeded / sizeof(DWORD);
    wcout << L"Number of processes detected: " << cProcesses << endl;

    PrintTableHeader();

    int processCount = 0, adminProcessCount = 0;

    for (unsigned int i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
            bool requiresAdmin = false;
            wstring processName = L"<unknown>";

            if (hProcess == NULL && GetLastError() == 5)
            {
                requiresAdmin = true;
                processName = GetProcessNameBySnapshot(aProcesses[i]);
                adminProcessCount++;
            }
            else if (hProcess != NULL)
            {
                TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
                HMODULE hMod;
                DWORD cbNeeded;

                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
                {
                    GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
                    processName = szProcessName;
                }
                CloseHandle(hProcess);
                processCount++;
            }

            PrintProcessInfo(processName, aProcesses[i], requiresAdmin);
        }
    }

    wcout << L"===================================================================================================" << endl;
    wcout << L"Total processes displayed: " << processCount << endl;
    wcout << L"Processes requiring admin : " << adminProcessCount << endl;
    wcout << endl;

    return 0;
}