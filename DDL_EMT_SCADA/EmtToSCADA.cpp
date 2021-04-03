#include "pch.h" 
#include <iostream>
#include "EmtToSCADA.h"

#define numerror_InitSecurityAttrubuts 5
#define numerror_ReadListKKSIn 4
#define numerror_ReadListKKSOut 4

#define PATH_DIR "Global\\CURRENTDIRGATESERVER"

std::string CreateNameMutexMemory(TypeData TD, TypeValue TV, int channel)
{
    std::string str;
    str += "Global\\MUTEX_";
    if (TD == TypeData::Analog)
    {
        str += "A";
    }
    else if (TD == TypeData::Discrete)
    {
        str += "D";
    }
    else if (TD == TypeData::Binar)
    {
        str += "B";
    }

    if (TV == TypeValue::INPUT)
    {
        str += "IN";
    }
    else if (TV == TypeValue::INPUT)
    {
        str += "OUT";
    }

    str += "_CHANNEL_" + std::to_string(channel);
    return str;
}

std::string CreateNameMemory(TypeData TD, TypeValue TV, int channel)
{
    std::string str;
    str += "Global\\MAPFILE_";
    if (TD == TypeData::Analog)
    {
        str += "A";
    }
    else if (TD == TypeData::Discrete)
    {
        str += "D";
    }
    else if (TD == TypeData::Binar)
    {
        str += "B";
    }

    if (TV == TypeValue::INPUT)
    {
        str += "IN";
    }
    else if (TV == TypeValue::INPUT)
    {
        str += "OUT";
    }

    str += "_CHANNEL_" + std::to_string(channel);
    return str;
}

/// --- èíèöèàëèçàöèÿ äåñêðèïòîðà áåçîïàñíîñòè ---///
/*
 0 - îøèáêà AllocateAndInitializeSid
 1 - SetEntriesInAclA
 2 - LocalAlloc
 3 - InitializeSecurityDescriptor
 4 - SetSecurityDescriptorDacl
*/
unsigned int SecurityHandle::InitSecurityAttrubuts()
{
    std::string messeng;
    unsigned result = 0;
    DWORD res = 0;

    if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID))
    {
        lasterror = GetLastError();
        result |= 1;
        return result;
    }

    ZeroMemory(&ea, 1 * sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = KEY_ALL_ACCESS | MUTEX_ALL_ACCESS;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPTSTR)pEveryoneSID;

    res = SetEntriesInAclA(1, (PEXPLICIT_ACCESSA)&ea, NULL, &pACL);
    if (res != ERROR_SUCCESS)
    {
        lasterror = GetLastError();
        result |= 2;
        return result;
    }

    pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (pSD == NULL)
    {
        lasterror = GetLastError();
        result |= 4;
        return result;
    }

    if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
    {
        lasterror = GetLastError();
        result |= 8;
        return result;
    }

    if (!SetSecurityDescriptorDacl(pSD, TRUE, pACL, FALSE))
    {
        lasterror = GetLastError();
        result |= 16;
        return result;
    }

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    return result;
}

DWORD SecurityHandle::getlasterror()
{
    return lasterror;
}

SECURITY_ATTRIBUTES& SecurityHandle::getsecurityattrebut()
{
    return sa;
}

Gate_EMT_SCADA::Gate_EMT_SCADA()
{
    int result = 0;
    HANDLE handel_path_KKS = NULL;
    char* buf_path = NULL;
    dir_kks_list.clear();
    handel_path_KKS = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, PATH_DIR);

    if (handel_path_KKS != NULL)
    {
        buf_path = (char*)MapViewOfFile(handel_path_KKS, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (buf_path != NULL)
        {
            for (int i = 0; i < *(int*)(buf_path); i++)
            {
                dir_kks_list += *(buf_path + 4 + i);
            }
        }
    }

    security = new SecurityHandle();
    result = security->InitSecurityAttrubuts();
    if (result != 0)
    {
        result_init = result;
        last_system_error = security->getlasterror();
        return;
    }

    result = ReadListKKSOut();
    if (result != 0)
    {
        result_init |= (result << numerror_InitSecurityAttrubuts);
        //last_system_error = 0;
        return;
    }

    result = ReadListKKSIn();
    if (result != 0)
    {
        result_init |= (result << (numerror_InitSecurityAttrubuts + numerror_ReadListKKSOut));
        //last_system_error = 0;
        return;
    }

    status_init = Status_Init::OK;

    return;
}

/// --- ôóíêöèÿ ÷òåíèÿ ñïèñêà KKSIn --- /// 
/*
0 - îøèáêà îòêðûòèÿ ôàéëà
1 - îøèáêà â ôîðìàòå äàííûõ KKS
2 - îøèáêà òèïà äàííûõ KKS
3 - ïîâòðíûé èíäåêñ KKS
*/
unsigned int Gate_EMT_SCADA::ReadListKKSIn()
{
    std::string file_name;
    FILE* config_file = NULL;
    char simvol = 0;
    std::string str_info;
    std::string helpstr;
    int res_read = 0;
    int pos[2] = { 0,0 };
    int count = 0;
    char status = 0;
    unsigned int result = 0;
    auto iter = VectKKSIn.begin();

    KKS_RAEK KKS;
    char flag_err_type = 0;

    file_name.clear();
    if (!dir_kks_list.empty())
    {
        file_name += dir_kks_list;
        file_name += "\\EMT\\";
    }
    file_name += NameFileListKKSIn;

    config_file = fopen(file_name.c_str(), "r");
    if (config_file == NULL)
    {
        result |= 1;
        return result;
    }

    for (;;)
    {
        simvol = 0;
        str_info.clear();
        while (simvol != '\n' && res_read != EOF)
        {
            res_read = fscanf(config_file, "%c", &simvol);
            if ((simvol > 0x1F || simvol == '\t') && res_read != EOF) str_info += simvol;
        }

        if (res_read == EOF && str_info.empty())
        {
            break;
        }

        if (str_info.empty()) continue;

        pos[0] = str_info.find('\t', 0);
        if (pos[0] != 10) { result |= 2; continue; }

        for (int i = 0; i < 10; i++)
        {
            KKS.KKS[i] = str_info[i];
        }

        pos[0] = str_info.find('\t', pos[0] + 1);
        KKS.index = atoi(str_info.substr((size_t)pos[0] + 1).c_str());

        for (;;)
        {
            flag_err_type = 0;
            if (str_info.find("Analog") != -1) { KKS.type = TypeData::Analog; break; }
            if (str_info.find("Discrete") != -1) { KKS.type = TypeData::Discrete; break; }
            if (str_info.find("Binar") != -1) { KKS.type = TypeData::Binar; break; }

            flag_err_type = 1;
            result |= 4;
            break;
        }

        if (flag_err_type == 1) continue;

        count = 0;
        for (;;)
        {
            if (count == VectKKSIn.size()) break;
            if ((char)VectKKSIn[count].type > (char)KKS.type) { count++; continue; }
            break;
        }

        for (;;)
        {
            if (count == VectKKSIn.size()) break;
            if ((char)VectKKSIn[count].type == (char)KKS.type && VectKKSIn[count].index < KKS.index) { count++; continue; }
            break;
        }

        if (count == VectKKSIn.size())
        {
            VectKKSIn.push_back(KKS);
            continue;
        }

        if (VectKKSIn[count].index == KKS.index)
        {
            result |= 8;
            continue;
        }

        iter = VectKKSIn.begin();
        iter += count;
        VectKKSIn.insert(iter, KKS);

        if (res_read == EOF)
        {
            break;
        }
    }
    return result;
}


/// --- ôóíêöèÿ ÷òåíèÿ ñïèñêà KKSOut --- ///
/*
0 - îøèáêà îòêðûòèÿ ôàéëà
1 - îøèáêà â ôîðìàòå äàííûõ KKS
2 - îøèáêà òèïà äàííûõ KKS
3 - ïîâòðíûé èíäåêñ KKS
*/
unsigned int Gate_EMT_SCADA::ReadListKKSOut()
{
    FILE* config_file = NULL;
    char simvol = 0;
    std::string str_info;
    std::string helpstr;
    int res_read = 0;
    int pos[2] = { 0,0 };
    int count = 0;
    char status = 0;
    unsigned int result = 0;
    std::string file_name;
    auto iter = VectKKSOut.begin();

    KKS_RAEK KKS;
    char flag_err_type = 0;

    file_name.clear();
    if (!dir_kks_list.empty())
    {
        file_name += dir_kks_list;
        file_name += "\\EMT\\";
    }
    file_name += NameFileListKKSOut;

    config_file = fopen(file_name.c_str(), "r");
    if (config_file == NULL)
    {
        result |= 1;
        return result;
    }

    for (;;)
    {
        simvol = 0;
        str_info.clear();
        while (simvol != '\n' && res_read != EOF)
        {
            res_read = fscanf(config_file, "%c", &simvol);
            if ((simvol > 0x1F || simvol == '\t') && res_read != EOF) str_info += simvol;
        }

        if (res_read == EOF && str_info.empty())
        {
            break;
        }

        if (str_info.empty()) continue;

        pos[0] = str_info.find('\t', 0);
        if (pos[0] != 10) { result |= 2; continue; }

        for (int i = 0; i < 10; i++)
        {
            KKS.KKS[i] = str_info[i];
        }

        pos[0] = str_info.find('\t', pos[0] + 1);
        KKS.index = atoi(str_info.substr((size_t)pos[0] + 1).c_str());

        for (;;)
        {
            flag_err_type = 0;
            if (str_info.find("Analog") != -1) { KKS.type = TypeData::Analog; break; }
            if (str_info.find("Discrete") != -1) { KKS.type = TypeData::Discrete; break; }
            if (str_info.find("Binar") != -1) { KKS.type = TypeData::Binar; break; }

            flag_err_type = 1;
            result |= 4;
            break;
        }

        if (flag_err_type == 1) continue;

        count = 0;
        for (;;)
        {
            if (count == VectKKSOut.size()) break;
            if ((char)VectKKSOut[count].type > (char)KKS.type) { count++; continue; }
            break;
        }

        for (;;)
        {
            if (count == VectKKSOut.size()) break;
            if ((char)VectKKSOut[count].type == (char)KKS.type && VectKKSOut[count].index < KKS.index) { count++; continue; }
            break;
        }

        if (count == VectKKSOut.size())
        {
            VectKKSOut.push_back(KKS);
            continue;
        }

        if (VectKKSOut[count].index == KKS.index)
        {
            result |= 8;
            break;
        }

        iter = VectKKSOut.begin();
        iter += count;
        VectKKSOut.insert(iter, KKS);

        if (res_read == EOF)
        {
            break;
        }
    }
    return result;
}


/// --- ïðîûåðâêà ñòàòóñà îáùåé ïàìÿòè --- ///
/*
-1 - îøèáêà èíèöèàëèçàöèè ìüþòåêñà
-2 - îøèáêà èíèöèàëèçàöèè ïàìÿòè
-3 - îøèáêà îòîáðàæåíèÿ ïàìÿòè
>0 - êîä êîìàíäû
*/
int Gate_EMT_SCADA::GetStatusMemory()
{
    unsigned char status;

    unsigned int result = 0;
    if (MutexSharMemStatus == NULL)
    {
        MutexSharMemStatus = CreateMutexA(NULL, FALSE, NameMutStatusMemoryGate);
        if (MutexSharMemStatus == NULL)
        {
            last_system_error = GetLastError();
            result = -1;
            return result;
        }
    }

    if (SharMemStatus == NULL)
    {
        SharMemStatus = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, NameStatusMemoryGate);
        if (SharMemStatus == NULL)
        {
            last_system_error = GetLastError();
            result = -2;
            return result;
        }
    }

    if (buf_status == NULL)
    {
        buf_status = (char*)MapViewOfFile(SharMemStatus, FILE_MAP_ALL_ACCESS, 0, 0, SizeMapStatus);
        if (buf_status == NULL)
        {
            last_system_error = GetLastError();
            result = -3;
            return result;
        }
    }


    WaitForSingleObject(MutexSharMemStatus, INFINITE);

    num_KKSIn = *(int*)(buf_status + 2);
    num_KKSOut = *(int*)(buf_status + 6);
    num_channels = *(int*)(buf_status + 10);

    status = *(buf_status + 1);
    status |= flag_first_init;

    if ((status & 4) > 0)
    {
        *(buf_status + 1) = status & (~4);
        flag_first_init &= (~4);
        status = status & 4;
    }
    else if ((status & 2) > 0)
    {
        *(buf_status + 1) = status & (~2);
        flag_first_init &= (~2);
        status = status & 2;
    }
    else if ((status & 1) > 0)
    {
        *(buf_status + 1) = status & (~1);
        flag_first_init &= (~1);
        status = status & 1;
    }

    ReleaseMutex(MutexSharMemStatus);

    return status;
}

/// --- функция чтения списка каналов --- ///
/*
0 - ошибка инициализации мьютекса
1 - ошибка открытия памяти
2 - ошибка отображения памяти

*/
Gate_EMT_SCADA* createGate_EMT_SCADA() {
    return new Gate_EMT_SCADA();
}