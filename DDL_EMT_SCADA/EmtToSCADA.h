#pragma once
#include <iostream>
#include <vector>
//#include "struct_enum.h"
#include <windows.h>
#include <aclapi.h>
#include <mutex>
#include <string>
//#include "security_handle.h"
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)

#ifdef EMTTOSCADA_EXPORTS
#define EMTTOSCADA_API __declspec(dllexport)
#else
#define EMTTOSCADA_API __declspec(dllimport)
#endif

#define NameFileListKKSOut "List_KKS_Out.txt"
#define NameFileListKKSIn "List_KKS_In.txt"


#define NameMutKKSInPut "Global\\mutex_KKSInPut"
#define NameMutKKSOutPut "Global\\mutex_KKSOutPut"
#define NameMemoryKKSInPut "Global\\MemoryListKKSInPut"
#define NameMemoryKKSOutPut "Global\\MemoryListKKSOutPut"

#define NameStatusMemoryGate "Global\\Status_gate_map"
#define NameMutStatusMemoryGate "Global\\Status_gate_mut"

#define NameMutMemoryInfoChannels "Global\\mutex_MemoryInfoChannels"
#define NameMemoryInfoChannels "Global\\MemoryInfoChannels"

#define NameMutexConcordKKSIn "Global\\Mutex_ConcordKKSIn"
#define NameMutexConcordKKSOut "Global\\Mutex_ConcordKKSOut"
#define NameMemoryConcordKKSIn "Global\\Memory_ConcordKKSIn"
#define NameMemoryConcordKKSOut "Global\\Memory_ConcordKKSOut"

#define SizeMapStatus 14

enum class TypeData
{
	Analog = 2,
	Discrete = 1,
	Binar = 0,
	Empty = -1
};

enum class TypeValue
{
	INPUT = 1,
	OUTPUT = 0
};


struct KKSDTS
{
	int channel = -1;
	TypeData typedata;
	int indexdts = -1;
	char KKS[10];
};

struct InfoChannels
{
	int channel = -1;

	int countAin = 0;
	int countDin = 0;
	int countBin = 0;
	int countAout = 0;
	int countDout = 0;
	int countBout = 0;

	char status = 0;
};

struct KKSConcord_RAEK
{
	char KKS[10];
	TypeData type;
	int channel;
	int indexdts;
	int indexraek;
};


struct KKS_RAEK
{
	char KKS[10];
	TypeData type;
	int index;
};

enum class CommandEmt
{
	UpdateKKSListOut = 1,
	UpdateKKSListIn = 2,
	UpdateListChannel = 4
};

enum class Status_Init
{
	OK = 0,
	Error = 1
};


std::string CreateNameMutexMemory(TypeData TD, TypeValue TV, int channel);

std::string CreateNameMemory(TypeData TD, TypeValue TV, int channel);


class SecurityHandle
{

	PSID pEveryoneSID = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	EXPLICIT_ACCESS ea;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	PACL pACL = NULL;
	SECURITY_ATTRIBUTES sa;
	DWORD lasterror;

public:


	unsigned int InitSecurityAttrubuts();
	DWORD getlasterror();
	SECURITY_ATTRIBUTES& getsecurityattrebut();
};

class Gate_EMT_SCADA
{

	SecurityHandle* security;

	std::vector<KKSDTS> VectKKSInÌem;
	std::vector<KKSDTS> VectKKSOutÌem;

	std::vector<KKS_RAEK> VectKKSIn;
	std::vector<KKS_RAEK> VectKKSOut;

	std::vector<InfoChannels> VectChannels;

	std::vector<KKSConcord_RAEK> TabConcordKKSIn;
	std::vector<KKSConcord_RAEK> TabConcordKKSOut;

	HANDLE mutex_VectChannels = NULL;

	int GetStatusMemory();

	unsigned int UpdateListKKSOutMem();
	HANDLE MutexUpdateListKKSOutMem = NULL;

	unsigned int UpdateListKKSInMem();
	HANDLE MutexUpdateListKKSInMem = NULL;

	unsigned int UpdateListChannels();



	unsigned int UpdateTabConcordKKSIn();
	unsigned int UpdateTabConcordKKSOut();

	unsigned int UpdateMemoryTabConcordIn();
	HANDLE MutexConcordKKSIn = NULL;
	HANDLE MemoryConcordKKSIn = NULL;

	unsigned int UpdateMemoryTabConcordOut();
	HANDLE MutexConcordKKSOut = NULL;
	HANDLE MemoryConcordKKSOut = NULL;

	//unsigned int DropCommand();

	HANDLE SharMemStatus = NULL;
	HANDLE MutexSharMemStatus = NULL;

	HANDLE MemoryInfoChannels = NULL;
	HANDLE MutexMemoryInfoChannels = NULL;

	int num_KKSIn = 0;
	int num_KKSOut = 0;
	int num_channels = 0;
	char* buf_status = NULL;

	unsigned int ReadListKKSOut();
	unsigned int ReadListKKSIn();

	char flag_first_init = 0b00000111;

	int result_init = 0;
	DWORD last_system_error = 0;
	Status_Init status_init = Status_Init::Error;

	unsigned int CheckStatusSharedMemory();

	std::string dir_kks_list;

public:

	Gate_EMT_SCADA();

	unsigned int ReadData(TypeData TP, void* buf, int size_buf);
	unsigned int WriteData(TypeData TP, void* buf, int size_buf);

	DWORD GetSystemError();
	int GetError();

	Status_Init GetStatusInit();

	//unsigned int ReadAnalogData(void* buf, int size_buf);
	//unsigned int ReadDiscreteData(void* buf, int size_buf);
	//unsigned int ReadBinarData(void* buf, int size_buf);

	//unsigned int WriteAnalogData(void* buf, int size_buf);
	//unsigned int WriteDiscreteData(void* buf, int size_buf);
	//unsigned int WriteBinarData(void* buf, int size_buf);
};


extern "C" EMTTOSCADA_API Gate_EMT_SCADA* createGate_EMT_DTS();