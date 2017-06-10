#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <iostream>
#include <cstring>
#include <string>

#define MINIMUM_REMOTE_THREAD PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
#define MINIMUM_THREAD_ACCESS THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME

#define tm_x86
#ifndef ADWORD
#define ADWORD DWORD
#endif

#ifdef tm_x86
#define ADWORD DWORD
#define REIP Eip
#endif

#ifdef tm_amd64
#define ADWORD DWORD64
#define REIP Rip
#endif


typedef HANDLE(__stdcall* openthread)(ADWORD, BOOL, ADWORD);

using namespace std;

struct DataInj
{

	ADWORD		eip;
	ADWORD		pid;
	ADWORD		tid;
	ADWORD		thaddress;
	ADWORD		instraddr;
	ADWORD		LoadLib;
	ADWORD		FreeLib;
	ADWORD		kernel;
	ADWORD		hProc;
	ADWORD		hTh;
	string		strThProcess;
	string		strReProcess;
	string		path;
	
};
	

class excpt
{
	
	private:
	
		string msg;
	
	public:
	
		excpt(const string &);
		excpt(const char*);
		~excpt();
		const string& what() const	{ return msg; }
};

class Injector
{

	private :
	
		ADWORD pID;
		ADWORD tID;
		ADWORD eip;
		bool byPid;
		DWORD threadaddress;
		ADWORD neip;
		CONTEXT context;
		string strThisProcess;
		string strProcess;
		string strDll;
		string Path;
		LPVOID address;
		LPVOID code_address;
		LPVOID aLoadLibrary;
		LPVOID aFreeLibrary;
		BOOL ready;
		BOOL loaded;
		HANDLE hProcess;
		HANDLE hThread;
		HMODULE kernel;
		openthread Open_Thread;
		
	public :
	
		Injector(char* szProcess, char* szDllName);
		Injector(DWORD pid, char* szDllName);
		~Injector();
		
		BOOL 				RemoteThread();
		BOOL				FreeRemoteThread();
		BOOL				EnsureDllInjected();
		BOOL				EnsureDllEjected();
		BOOL				ThreadRedirect();
		BOOL				FreeRedirect();
		BYTE*				CodeRedirect(ADWORD, ADWORD, ADWORD);
		ADWORD 				GetProcessIdFromProcName(char*);
		ADWORD				GetFirstThreadIdFromProcId(ADWORD);
		HMODULE				GetRemoteModuleHandle(ULONG, char*);
		void				GetPathForDll();
		void 				Init();
		void				CleanUp();
		ADWORD				GetThreadAddress() { return threadaddress; }
		DataInj*			GetData();
		string 				GetCurrentProcessName();
		BYTE*				RedirectCode(ADWORD, ADWORD, ADWORD, ADWORD&);
		
		
};

excpt::excpt(const string &str)
{
	msg = str;
}

excpt::excpt(const char* szmsg)
{
	msg = szmsg;
}

excpt::~excpt() { msg.clear(); }

Injector::Injector(char* szProcName, char* szDllName)
{

	strProcess = szProcName;
	strDll = szDllName;
	threadaddress = 0;
	pID = tID = eip = neip = 0;
	code_address = address = aLoadLibrary = aFreeLibrary = NULL;
	hProcess = hThread = NULL;
	kernel = NULL;
	ready = false;
	loaded = false;
	byPid = false;

}

Injector::Injector(DWORD pid, char* szDllName)
{
	strProcess = "";
	strDll = szDllName;
	threadaddress = 0;
	pID = pid;
	tID = eip = neip = 0;
	code_address = address = aLoadLibrary = aFreeLibrary = NULL;
	hProcess = hThread = NULL;
	kernel = NULL;
	ready = false;
	loaded = false;
	byPid = true;
}

Injector::~Injector() { }

void Injector::Init()
{
	if (loaded) throw excpt("Dll already injected");
	if (ready) throw excpt("Init already called. CleanUp() first");
	
	kernel = GetModuleHandle("kernel32.dll");
	if (!kernel) throw excpt("Cannot get handle for kernel32.dll");
	if (!byPid)
	{
		pID	= GetProcessIdFromProcName(const_cast<char*>(strProcess.c_str()));
		if (!pID) throw excpt("Cannot get Process ID with specified name");
	}
	tID = GetFirstThreadIdFromProcId(pID);
	strThisProcess = GetCurrentProcessName();
	
	aLoadLibrary = (LPVOID) GetProcAddress(kernel, "LoadLibraryA");
	if (!aLoadLibrary) throw excpt("Cannot get LoadLibrary address");

	aFreeLibrary = (LPVOID) GetProcAddress(kernel, "FreeLibrary");
	if (!aFreeLibrary) throw excpt("Cannot get FreeLibrary address");

	Open_Thread = (openthread) GetProcAddress(kernel, "OpenThread");
	GetPathForDll();
	ready = true;

}

void Injector::GetPathForDll()
{

	char path[MAX_PATH];
	GetModuleFileName(NULL, path, MAX_PATH);
	string p(path);
	size_t pos= p.find(strThisProcess);
	p.erase(pos, p.size() - pos);
	p += strDll;
	Path = p;
	
}

ADWORD Injector::GetProcessIdFromProcName(char* procname)
{
	PROCESSENTRY32 pe;
	HANDLE thSnapshot;
	BOOL retval, ProcFound = false;

	thSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if(thSnapshot == INVALID_HANDLE_VALUE) throw excpt("CreateToolhelp32Snapshot failed");

	pe.dwSize = sizeof(PROCESSENTRY32);

    retval = Process32First(thSnapshot, &pe);

	while(retval)
	{
		
		string p = pe.szExeFile;
		if(p.find(procname) != p.npos )
		{
			return pe.th32ProcessID;
		}

		retval    = Process32Next(thSnapshot,&pe);
		pe.dwSize = sizeof(PROCESSENTRY32);
    }

	return 0;
}

string Injector::GetCurrentProcessName()
{

	PROCESSENTRY32 pe;
	HANDLE thSnapshot;
	BOOL retval, ProcFound = false;
	ADWORD thispid = GetCurrentProcessId();

	thSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if(thSnapshot == INVALID_HANDLE_VALUE) throw excpt("CreateToolhelp32Snapshot failed");

	pe.dwSize = sizeof(PROCESSENTRY32);

    retval = Process32First(thSnapshot, &pe);

	while(retval)
	{
		if (pe.th32ProcessID == thispid) {
		
			strThisProcess = pe.szExeFile;
			string p = pe.szExeFile;
			return p;
		}
		retval    = Process32Next(thSnapshot,&pe);
		pe.dwSize = sizeof(PROCESSENTRY32);
    }

	return ("");
}

HMODULE	Injector::GetRemoteModuleHandle(ULONG pId, char* module)
{

	MODULEENTRY32 modEntry;
    HANDLE tlh = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pId);

    modEntry.dwSize = sizeof(MODULEENTRY32);
    Module32First(tlh, &modEntry);

    do
    {
        if(!_stricmp(modEntry.szModule, module))	{
            return modEntry.hModule;
			}
        modEntry.dwSize = sizeof(MODULEENTRY32);
    }
    while(Module32Next(tlh, &modEntry));

    return NULL;
}

ADWORD	Injector::GetFirstThreadIdFromProcId(ADWORD pid)
{

	THREADENTRY32 te;
	HANDLE thSnapshot;
	BOOL retval, ThreadFound = false;

	thSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if(thSnapshot == INVALID_HANDLE_VALUE)	throw excpt("CreateToolhelp32Snapshot failed");

	te.dwSize = sizeof(THREADENTRY32);
	
	retval = Thread32First(thSnapshot, &te);
	
	while (retval)
	{
	
		if (te.th32OwnerProcessID == pid) return te.th32ThreadID;
		retval = Thread32Next(thSnapshot, &te);
		te.dwSize = sizeof(THREADENTRY32);
		
	}
	
	return 0;
	
}

BOOL Injector::RemoteThread()
{

	if (!ready) return false;
	if (!pID) return false;
	if (loaded) throw excpt("Dll already injected");


	hProcess = OpenProcess(MINIMUM_REMOTE_THREAD, false, static_cast<DWORD>(pID));
	if (hProcess == INVALID_HANDLE_VALUE) throw excpt("Cannot open specified process");

	address = (LPVOID) VirtualAllocEx(hProcess, NULL, Path.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!address) throw excpt("Cannot allocate memory on specified process");

	if (!WriteProcessMemory(hProcess, address, Path.c_str(), Path.size() + 1, NULL)) 
		throw excpt("Cannot write on specified process memory");

	hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE) aLoadLibrary, address, NULL, NULL);

	if (hThread == INVALID_HANDLE_VALUE) throw excpt("Cannot create remote thread");
	
	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &threadaddress);
	if (!threadaddress) throw excpt ("invalid thread address.");


	//loaded = EnsureDllInjected();
	loaded = true;
	return loaded;

}

BOOL Injector::FreeRemoteThread()
{

	if (!loaded) throw excpt("Dll is not injected");

	hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE) aFreeLibrary, (LPVOID) threadaddress, NULL, NULL);
	if (hThread == INVALID_HANDLE_VALUE) excpt("Cannot create remote thread to eject Dll");

	WaitForSingleObject(hThread, INFINITE);
	DWORD exit = 0;
	GetExitCodeThread(hThread, &exit);
	if (!exit) throw excpt("invalid thread address");
	loaded = !EnsureDllEjected();

	return loaded;

}

void Injector::CleanUp()
{
	if (!ready) return;
	if (address)	VirtualFreeEx(hProcess, address, 0, MEM_RELEASE);
	if (code_address) VirtualFreeEx(hProcess, code_address, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	FreeLibrary(kernel);

	aLoadLibrary = aFreeLibrary = address = NULL;
	pID = tID = eip = 0;
	threadaddress = 0;
	hProcess = hThread = NULL;
	kernel = NULL;

	ready = false;

}

BOOL Injector::EnsureDllInjected()
{

	if (GetRemoteModuleHandle(static_cast<ULONG>(pID), const_cast<char*>(strDll.c_str())))
		return true;

	return false;

}

BOOL Injector::EnsureDllEjected()
{

	return (!EnsureDllInjected());

}

DataInj *Injector::GetData()
{

	DataInj* m = new DataInj();
	m->pid = pID;
	m->tid = tID;
	m->eip = eip;
	m->thaddress = threadaddress;
	m->LoadLib = (ADWORD) aLoadLibrary;
	m->FreeLib = (ADWORD) aFreeLibrary;
	m->kernel = (ADWORD) kernel;
	m->hProc = (ADWORD) hProcess;
	m->hTh = (ADWORD) hThread;
	m->strThProcess = strThisProcess;
	m->strReProcess = strProcess;
	m->path = Path;
	m->instraddr = (ADWORD) code_address;
	return m;
	
};


BYTE* Injector::RedirectCode(ADWORD Eip,ADWORD Ruta,ADWORD func, ADWORD &_outcodesize)
{
	BYTE *codeBuff;
	ADWORD codesize = 0;

	codeBuff= new BYTE[100];
	BYTE* begin = codeBuff;
	//push eip vieja
	*codeBuff=0x68;
	codeBuff++;
	*((ADWORD*)codeBuff)=Eip;
	codeBuff+=sizeof(ADWORD);

	*codeBuff=0x9C; //pushfd
	codeBuff++;
	*codeBuff=0x60;  //pushad
	codeBuff++;

	//push path
	*codeBuff=0x68;
	codeBuff++;
	*((ADWORD*)codeBuff)=Ruta;
	codeBuff+=sizeof(ADWORD);

	//mov eax,nLoadLib
	*codeBuff=0xB8;
	codeBuff++;
	*((ADWORD*)codeBuff)=func;
	codeBuff+=sizeof(ADWORD);

	*((WORD*)codeBuff)=0xD0FF; //call eax
	codeBuff+=2;
	*codeBuff=0x61; //popad
	codeBuff++;
	*codeBuff=0x9D;  //popfd
	codeBuff++;
	*codeBuff=0xC3;   //ret
	_outcodesize = (ADWORD) (codeBuff - begin);
	return begin;
}

BOOL Injector::ThreadRedirect()
{

	if (!ready) return false;
	if (!pID) return false;
	if (!tID) throw excpt("thread ID left");
	if (loaded) throw excpt("Dll already injected");
	
	Open_Thread = (openthread) GetProcAddress(kernel, "OpenThread");
	
	hProcess = OpenProcess(MINIMUM_REMOTE_THREAD, false, static_cast<DWORD>(pID));
	if (hProcess == INVALID_HANDLE_VALUE)	throw excpt("Cannot open specified process");
	
	hThread = Open_Thread(MINIMUM_THREAD_ACCESS, false, tID);
	if (hThread == INVALID_HANDLE_VALUE) throw excpt("Cannot open specified thread");
	
	address = VirtualAllocEx(hProcess, NULL, Path.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!address)	throw excpt("Cannot allocate memory on specified process on [address = VirtualAllocEx]");
	
	if (!WriteProcessMemory(hProcess, address, Path.c_str(), Path.size() + 1, NULL))
		throw excpt("Cannot write on specified process memory");

	SuspendThread(hThread);
	context.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &context);

	eip = context.REIP;
	BYTE *instr = NULL;
	ADWORD bytecodesize = 0;
	instr = RedirectCode(eip, (ADWORD) address, (ADWORD)aLoadLibrary, bytecodesize);

	if (!instr) throw excpt("Failed RedirectCode()");
	cout << "bytecodesize : " << bytecodesize;	/////////////////////
	
	code_address = VirtualAllocEx(hProcess, NULL, bytecodesize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!code_address)	throw excpt("Cannot allocate memory on specified memory on [code_address = VirtualAllocEx]");

	
	if (!WriteProcessMemory(hProcess, code_address, instr, bytecodesize, NULL))
		throw excpt("Cannot write on specified process memory at [code_address] address");

	
	neip = (ADWORD) code_address;
	context.REIP = neip;
	context.ContextFlags = CONTEXT_CONTROL;
	SetThreadContext(hThread, &context);

	
	ResumeThread(hThread);

	cout << "thread resumed" << endl;
	Sleep(4000);
	delete[] instr;
	
	loaded = EnsureDllInjected();

	return loaded = true;
	
}

BOOL Injector::FreeRedirect()
{

	if (!tID || !pID || !neip || !loaded || !ready) return false;
	
	SuspendThread(hThread);
	GetThreadContext(hThread, &context);
	context.ContextFlags = CONTEXT_CONTROL;
	eip = context.REIP;
	
	BYTE *instr = NULL;
	LPVOID module = (LPVOID)GetRemoteModuleHandle(static_cast<ULONG>(pID), const_cast<char*>(strDll.c_str()));
	ADWORD bytecodesize = 0;
	instr = RedirectCode(eip, (ADWORD)module, (ADWORD) aFreeLibrary, bytecodesize);
	if (!instr)
	
	if (!WriteProcessMemory(hProcess, code_address, instr, bytecodesize, NULL))
	
	context.REIP = neip;

	context.ContextFlags = CONTEXT_CONTROL;
	SetThreadContext(hThread, &context);
	
	ResumeThread(hThread);
	
	Sleep(1000);
	delete[] instr;
	
	loaded = !EnsureDllEjected();
	return loaded;
	
}


ostream &operator << (ostream &out, const DataInj &t)
{

	out << "pid : " << t.pid << endl;
	out << "tid : " << t.tid << endl;
	out << hex << showbase << "threadaddress : " << t.thaddress << hex << showbase << endl;
	out << "eip : " << t.eip << endl;
	out << "strThisProcess : " << t.strThProcess << endl;
	out << "strProcess : " << t.strReProcess << endl;
	out << "Path : " << t.path << endl;
	out << "LoadLibrary : " << hex << showbase << t.LoadLib << endl;
	out << "FreeLibrary : " << t.FreeLib << endl;	
	out << "kernel : " << t.kernel << endl;
	out << "instruction address : " << t.instraddr << endl;
	out << "hProcess : " << t.hProc << endl;
	out << "hThread : " << t.hTh << hex << showbase << endl;
	return out;
	
}

