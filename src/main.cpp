#include <windows.h>
#include <Aclapi.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <Wbemidl.h>

#include <string>
#include <vector>
#include <regex>
#include <cctype>

// Notes:
// - This is a C++/CMake port of the original C# logic from Daiwv/Anti-Miner.
// - It intentionally keeps the same heuristics: netstat/tasklist parsing, WMI queries,
//   naive VirusTotal "contains" checks, and ~20s polling interval.

namespace
{
    constexpr DWORD kProcessAllAccessMask = 0x001F0FFF; // Same bitmask used by the C# version.
    constexpr DWORD kScanIntervalMs = 20000;

    std::wstring GetEnvVar(const wchar_t* name)
    {
        DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
        if (needed == 0)
            return L"";

        std::wstring value;
        value.resize(needed);
        DWORD written = GetEnvironmentVariableW(name, value.data(), needed);
        if (written == 0)
            return L"";

        // GetEnvironmentVariableW includes the null terminator in "needed".
        if (!value.empty() && value.back() == L'\0')
            value.pop_back();
        return value;
    }

    void SetProtectBestEffort()
    {
        // Equivalent intent to the C# SetProtect(): insert a DENY ACE for Everyone with PROCESS_ALL_ACCESS.
        HANDLE hProcess = GetCurrentProcess();

        PACL pOldDacl = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        DWORD res = GetSecurityInfo(
            hProcess,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &pOldDacl,
            nullptr,
            &pSD);

        if (res != ERROR_SUCCESS || pOldDacl == nullptr)
        {
            if (pSD)
                LocalFree(pSD);
            return;
        }

        SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
        PSID everyoneSid = nullptr;
        if (!AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID,
                0, 0, 0, 0, 0, 0, 0, &everyoneSid))
        {
            LocalFree(pSD);
            return;
        }

        ACL_SIZE_INFORMATION aclInfo{};
        if (!GetAclInformation(pOldDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation))
        {
            FreeSid(everyoneSid);
            LocalFree(pSD);
            return;
        }

        const DWORD denyAceSize = sizeof(ACCESS_DENIED_ACE) + GetLengthSid(everyoneSid) - sizeof(DWORD);
        const DWORD newAclSize = aclInfo.AclBytesInUse + denyAceSize;
        PACL pNewDacl = static_cast<PACL>(LocalAlloc(LPTR, newAclSize));
        if (!pNewDacl)
        {
            FreeSid(everyoneSid);
            LocalFree(pSD);
            return;
        }

        if (!InitializeAcl(pNewDacl, newAclSize, ACL_REVISION))
        {
            LocalFree(pNewDacl);
            FreeSid(everyoneSid);
            LocalFree(pSD);
            return;
        }

        // Insert deny ACE first (index 0 in the C# version).
        if (!AddAccessDeniedAceEx(pNewDacl, ACL_REVISION, 0, kProcessAllAccessMask, everyoneSid))
        {
            LocalFree(pNewDacl);
            FreeSid(everyoneSid);
            LocalFree(pSD);
            return;
        }

        // Copy existing ACEs after the deny ACE.
        for (DWORD i = 0; i < aclInfo.AceCount; ++i)
        {
            LPVOID pAce = nullptr;
            if (GetAce(pOldDacl, i, &pAce))
            {
                // Append at end.
                AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pAce, static_cast<DWORD>(((PACE_HEADER)pAce)->AceSize));
            }
        }

        SetSecurityInfo(
            hProcess,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            pNewDacl,
            nullptr);

        LocalFree(pNewDacl);
        FreeSid(everyoneSid);
        LocalFree(pSD);
    }

    std::string RunHiddenCommandCaptureStdout(const std::wstring& commandLine)
    {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = nullptr;

        HANDLE hRead = nullptr;
        HANDLE hWrite = nullptr;
        if (!CreatePipe(&hRead, &hWrite, &sa, 0))
            return {};

        // Ensure the read handle isn't inherited.
        SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        si.hStdOutput = hWrite;
        si.hStdError = hWrite;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

        PROCESS_INFORMATION pi{};

        std::wstring cmd = commandLine; // CreateProcess requires writable buffer.
        BOOL ok = CreateProcessW(
            nullptr,
            cmd.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &si,
            &pi);

        CloseHandle(hWrite); // Parent closes its write end.

        if (!ok)
        {
            CloseHandle(hRead);
            return {};
        }

        std::string out;
        char buffer[4096];
        DWORD bytesRead = 0;
        while (ReadFile(hRead, buffer, static_cast<DWORD>(sizeof(buffer)), &bytesRead, nullptr) && bytesRead > 0)
        {
            out.append(buffer, buffer + bytesRead);
        }

        CloseHandle(hRead);

        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        return out;
    }

    std::vector<std::string> SplitByCRLF(const std::string& text)
    {
        std::vector<std::string> lines;
        size_t start = 0;
        while (true)
        {
            size_t pos = text.find("\r\n", start);
            if (pos == std::string::npos)
            {
                lines.emplace_back(text.substr(start));
                break;
            }
            lines.emplace_back(text.substr(start, pos - start));
            start = pos + 2;
        }
        return lines;
    }

    std::vector<std::string> RegexSplitWhitespace(const std::string& line)
    {
        // Mimic .NET Regex.Split(line, "\\s+") including leading empty token for leading spaces.
        static const std::regex re("\\s+");
        std::vector<std::string> parts;
        std::sregex_token_iterator it(line.begin(), line.end(), re, -1);
        std::sregex_token_iterator end;
        for (; it != end; ++it)
            parts.push_back(it->str());
        return parts;
    }

    bool IsDigitsOrEmpty(const std::string& s)
    {
        for (unsigned char ch : s)
        {
            if (!std::isdigit(ch))
                return false;
        }
        return true;
    }

    // --- SHA256 ---
    std::string Sha256HexUpper(const std::wstring& path)
    {
        if (path.empty())
            return {};

        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            return {};

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        std::string hex;

        DWORD cbHashObject = 0;
        DWORD cbData = 0;
        DWORD cbHash = 0;

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        {
            CloseHandle(hFile);
            return {};
        }

        if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(cbHashObject), &cbData, 0) != 0 ||
            BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(cbHash), &cbData, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return {};
        }

        std::vector<BYTE> hashObject(cbHashObject);
        std::vector<BYTE> hash(cbHash);

        if (BCryptCreateHash(hAlg, &hHash, hashObject.data(), cbHashObject, nullptr, 0, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return {};
        }

        BYTE buffer[8192];
        DWORD bytesRead = 0;
        BOOL readOk = FALSE;
        while ((readOk = ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, nullptr)) && bytesRead > 0)
        {
            BCryptHashData(hHash, buffer, bytesRead, 0);
        }

        if (!readOk)
        {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return {};
        }

        if (BCryptFinishHash(hHash, hash.data(), cbHash, 0) != 0)
        {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return {};
        }

        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);

        static const char* kHex = "0123456789ABCDEF";
        hex.reserve(cbHash * 2);
        for (BYTE b : hash)
        {
            hex.push_back(kHex[(b >> 4) & 0xF]);
            hex.push_back(kHex[b & 0xF]);
        }
        return hex;
    }

    // --- WMI ---
    struct WmiContext
    {
        bool comInitialized = false;
        IWbemLocator* loc = nullptr;
        IWbemServices* svc = nullptr;

        bool Init()
        {
            HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
                return false;
            if (SUCCEEDED(hr))
                comInitialized = true;

            // Best effort: if security already initialized, this returns RPC_E_TOO_LATE.
            hr = CoInitializeSecurity(
                nullptr, -1, nullptr, nullptr,
                RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                nullptr,
                EOAC_NONE,
                nullptr);

            if (FAILED(hr) && hr != RPC_E_TOO_LATE)
                return false;

            hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&loc);
            if (FAILED(hr))
                return false;

            BSTR ns = SysAllocString(L"ROOT\\CIMV2");
            hr = loc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc);
            SysFreeString(ns);
            if (FAILED(hr))
                return false;

            // Allow us to call WMI as current user.
            hr = CoSetProxyBlanket(
                svc,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                nullptr,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                nullptr,
                EOAC_NONE);
            if (FAILED(hr))
                return false;

            return true;
        }

        std::wstring QuerySingleString(const std::wstring& wqlQuery, const std::wstring& field)
        {
            if (!svc)
                return L"";

            IEnumWbemClassObject* enumerator = nullptr;

            BSTR lang = SysAllocString(L"WQL");
            BSTR query = SysAllocString(wqlQuery.c_str());
            HRESULT hr = svc->ExecQuery(
                lang,
                query,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr,
                &enumerator);
            SysFreeString(lang);
            SysFreeString(query);

            if (FAILED(hr) || !enumerator)
                return L"";

            IWbemClassObject* obj = nullptr;
            ULONG returned = 0;
            hr = enumerator->Next(WBEM_INFINITE, 1, &obj, &returned);
            if (FAILED(hr) || returned == 0 || !obj)
            {
                enumerator->Release();
                return L"";
            }

            VARIANT vtProp;
            VariantInit(&vtProp);
            hr = obj->Get(field.c_str(), 0, &vtProp, nullptr, nullptr);

            std::wstring result;
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR && vtProp.bstrVal)
                result = vtProp.bstrVal;

            VariantClear(&vtProp);
            obj->Release();
            enumerator->Release();
            return result;
        }

        ~WmiContext()
        {
            if (svc)
                svc->Release();
            if (loc)
                loc->Release();
            if (comInitialized)
                CoUninitialize();
        }
    };

    std::wstring MinerPath(WmiContext& wmi, const std::string& pid)
    {
        // Mimic C# regex "^[0-9]*$": accept digits and empty, reject others.
        if (!IsDigitsOrEmpty(pid))
            return L"";

        std::wstring wpid(pid.begin(), pid.end());
        std::wstring q = L"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = " + wpid;
        return wmi.QuerySingleString(q, L"ExecutablePath");
    }

    std::wstring MinerArgs(WmiContext& wmi, const std::string& pid)
    {
        if (!IsDigitsOrEmpty(pid))
            return L"";

        std::wstring wpid(pid.begin(), pid.end());
        std::wstring q = L"SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + wpid;
        return wmi.QuerySingleString(q, L"CommandLine");
    }

    // --- VirusTotal ---
    std::string HttpGetToStringWinHttp(const std::wstring& host, INTERNET_PORT port, const std::wstring& pathAndQuery)
    {
        HINTERNET hSession = WinHttpOpen(L"AntiMinerCMake/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession)
            return {};

        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
        if (!hConnect)
        {
            WinHttpCloseHandle(hSession);
            return {};
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", pathAndQuery.c_str(), nullptr, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, (port == INTERNET_DEFAULT_HTTPS_PORT) ? WINHTTP_FLAG_SECURE : 0);
        if (!hRequest)
        {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return {};
        }

        BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        if (bResults)
            bResults = WinHttpReceiveResponse(hRequest, nullptr);

        std::string response;
        if (bResults)
        {
            DWORD dwSize = 0;
            do
            {
                dwSize = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                    break;
                if (dwSize == 0)
                    break;

                std::vector<char> buf(dwSize);
                DWORD dwDownloaded = 0;
                if (!WinHttpReadData(hRequest, buf.data(), dwSize, &dwDownloaded))
                    break;

                response.append(buf.data(), buf.data() + dwDownloaded);
            } while (dwSize > 0);
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response;
    }

    bool VTrez(const std::string& sha256, const std::wstring& apiKey)
    {
        // C# behavior: always GET file/report and then naive substring search.
        // It doesn't URL-encode params; we keep the same assumption (keys/hashes are safe).

        std::wstring wSha(sha256.begin(), sha256.end());
        std::wstring query = L"/vtapi/v2/file/report?apikey=" + apiKey + L"&resource=" + wSha;

        std::string rez = HttpGetToStringWinHttp(L"www.virustotal.com", INTERNET_DEFAULT_HTTPS_PORT, query);

        if (rez.find("Miner") != std::string::npos)
            return true;
        if (rez.find("miner") != std::string::npos)
            return true;
        if (rez.find("BtcMine") != std::string::npos)
            return true;
        if (rez.find("mine") != std::string::npos)
            return true;

        return false;
    }

    void KillMiner(const std::vector<std::string>& pids, const std::vector<std::wstring>& paths)
    {
        try
        {
            for (const auto& pidStr : pids)
            {
                DWORD pid = 0;
                try
                {
                    pid = static_cast<DWORD>(std::stoul(pidStr));
                }
                catch (...)
                {
                    continue;
                }

                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                if (!h)
                    continue;
                TerminateProcess(h, 1);
                CloseHandle(h);
            }

            Sleep(1500);

            for (const auto& p : paths)
            {
                if (p.empty())
                    continue;
                DeleteFileW(p.c_str());
            }
        }
        catch (...)
        {
        }
    }

    std::string NetStat()
    {
        return RunHiddenCommandCaptureStdout(L"netstat.exe -a -n -o -p TCP");
    }

    std::string TaskList()
    {
        return RunHiddenCommandCaptureStdout(L"tasklist.exe");
    }

    void FindUnSafePort(WmiContext& wmi)
    {
        std::vector<std::string> pids;
        std::vector<std::wstring> paths;

        auto lines = SplitByCRLF(NetStat());
        const std::vector<std::string> ports = { "3333", "4444", "5555", "6666", "7777", "8888", "9999" };

        if (lines.size() < 6)
            return;

        for (size_t i = 4; i != lines.size() - 2; ++i)
        {
            auto parts = RegexSplitWhitespace(lines[i]);
            if (parts.size() <= 5)
                continue;

            for (const auto& port : ports)
            {
                if (parts[3].find(port) != std::string::npos)
                {
                    pids.push_back(parts[5]);
                    paths.push_back(MinerPath(wmi, parts[5]));
                }
            }
        }

        KillMiner(pids, paths);
    }

    void FindUnSafeAgr(WmiContext& wmi)
    {
        std::vector<std::string> pids;
        std::vector<std::wstring> paths;

        auto lines = SplitByCRLF(TaskList());
        const std::vector<std::wstring> agrs = { L"pool", L"xmr", L"monero", L"eth", L"minergate", L"nicehash", L"mine", L"mining", L"money" };

        if (lines.size() < 6)
            return;

        for (size_t i = 4; i != lines.size() - 2; ++i)
        {
            auto parts = RegexSplitWhitespace(lines[i]);
            if (parts.size() <= 1)
                continue;

            const std::string pid = parts[1];
            std::wstring cmd = MinerArgs(wmi, pid);
            if (cmd.empty())
                continue;

            for (const auto& kw : agrs)
            {
                // C# uses case-sensitive Contains.
                if (cmd.find(kw) != std::wstring::npos)
                {
                    paths.push_back(MinerPath(wmi, pid));
                    pids.push_back(pid);
                    break;
                }
            }
        }

        KillMiner(pids, paths);
    }

    void FindVirus(WmiContext& wmi, const std::wstring& apiKey)
    {
        std::vector<std::string> pids;
        std::vector<std::wstring> paths;

        auto lines = SplitByCRLF(TaskList());
        if (lines.size() < 6)
            return;

        for (size_t i = 4; i != lines.size() - 2; ++i)
        {
            auto parts = RegexSplitWhitespace(lines[i]);
            if (parts.size() <= 1)
                continue;

            const std::string pid = parts[1];
            std::wstring exePath = MinerPath(wmi, pid);
            std::string sha = Sha256HexUpper(exePath);

            if (VTrez(sha, apiKey))
            {
                pids.push_back(pid);
                paths.push_back(exePath);
            }
        }

        KillMiner(pids, paths);
    }
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    // Protect (best effort) like the C# version.
    SetProtectBestEffort();

    // VirusTotal API key: mimic original ("API_KEY" placeholder), but allow override via env var for convenience.
    std::wstring apiKey;
    apiKey = GetEnvVar(L"VT_API_KEY");
    if (apiKey.empty())
    {
#ifdef VT_API_KEY
        std::string apiKeyA = VT_API_KEY;
        apiKey.assign(apiKeyA.begin(), apiKeyA.end());
#else
        apiKey = L"API_KEY";
#endif
    }

    WmiContext wmi;
    wmi.Init(); // best effort

    while (true)
    {
        FindUnSafePort(wmi);
        FindUnSafeAgr(wmi);
        FindVirus(wmi, apiKey);
        Sleep(kScanIntervalMs);
    }
}


