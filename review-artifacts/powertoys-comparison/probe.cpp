// Contains excerpts from Microsoft PowerToys.
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License; see UPSTREAM-LICENSE in this directory.
#include <windows.h>
#include <psapi.h>
#include <winternl.h>
#include <algorithm>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <thread>
#include <future>
#include <memory>
#include <cassert>
#include <iostream>
#include <cwchar>
static int opens=0, closes=0, local_queries=0;
DWORD fake_error() { return ERROR_INSUFFICIENT_BUFFER; }
DWORD fake_remote(HANDLE, HMODULE, wchar_t* b, DWORD n) { b[0]=L'x'; b[1]=0; return n; }
DWORD fake_local(HMODULE, wchar_t* b, DWORD) {
    ++local_queries; const wchar_t* value=L"LOCAL_MODULE";
    std::copy_n(value,std::wcslen(value)+1,b); return DWORD(std::wcslen(value));
}
HANDLE fake_open(DWORD, BOOL, DWORD) { ++opens; return reinterpret_cast<HANDLE>(123); }
BOOL fake_enum(HANDLE, HMODULE*, DWORD, DWORD*) { return FALSE; }
BOOL fake_close(HANDLE) { ++closes; return TRUE; }
#define GetLastError fake_error
#undef GetModuleFileNameExW
#define GetModuleFileNameExW fake_remote
#define GetModuleFileNameW fake_local
#define OpenProcess fake_open
#undef EnumProcessModules
#define EnumProcessModules fake_enum
#define CloseHandle fake_close
constexpr size_t DefaultModulesResultSize=512;
inline std::wstring get_module_name(HANDLE process, HMODULE mod)
    {
        wchar_t buffer[MAX_PATH + 1];
        DWORD actual_length = GetModuleFileNameExW(process, mod, buffer, MAX_PATH + 1);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            const DWORD long_path_length = 0xFFFF; // should be always enough
            std::wstring long_filename(long_path_length, L'\0');
            actual_length = GetModuleFileNameW(mod, long_filename.data(), long_path_length);
            long_filename.resize(std::wcslen(long_filename.data()));
            long_filename.shrink_to_fit();
            return long_filename;
        }

        return { buffer, static_cast<UINT>(lstrlenW(buffer)) };
    }
std::vector<std::wstring> process_modules(DWORD pid)
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process)
        {
            return {};
        }

        std::vector<std::wstring> result;

        bool completed = false;
        std::vector<HMODULE> modules(DefaultModulesResultSize);
        while (!completed)
        {
            DWORD needed;
            auto status = EnumProcessModules(process, modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &needed);

            if (!status)
            {
                // Give up
                return {};
            }

            if (needed > modules.size() * sizeof(HMODULE))
            {
                // Array is too small
                modules.resize(needed / sizeof(HMODULE));
                continue;
            }

            // Okay
            modules.resize(needed / sizeof(HMODULE));

            for (auto mod : modules)
            {
                result.push_back(get_module_name(process, mod));
            }

            completed = true;
        }

        CloseHandle(process);
        return result;
    }
static constexpr bool starts_with(std::wstring_view whole, std::wstring_view part)
{
    return whole.size() >= part.size() && whole.substr(0, part.size()) == part;
}

struct ProcessInfo { DWORD pid; std::wstring name,user; std::vector<std::wstring> modules; };
std::wstring unicode_to_str(UNICODE_STRING s) { return std::wstring(s.Buffer,s.Length/sizeof(WCHAR)); }
std::wstring pid_to_user(DWORD) { return L""; }
std::vector<ProcessInfo> walk_upstream(std::vector<BYTE> memory) {
    struct { std::vector<BYTE> memory; } get_info_result{std::move(memory)};
    std::vector<ProcessInfo> result;
    auto info_ptr = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(get_info_result.memory.data());

    while (info_ptr->NextEntryOffset)
    {
        info_ptr = reinterpret_cast<decltype(info_ptr)>(reinterpret_cast<LPBYTE>(info_ptr) + info_ptr->NextEntryOffset);

        ProcessInfo item;
        item.name = unicode_to_str(info_ptr->ImageName);
        item.pid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(info_ptr->UniqueProcessId));
        item.modules = process_modules(item.pid);
        item.user = pid_to_user(item.pid);

        result.push_back(item);
    }

    return result;
}
void test_walk() {
    const size_t stride=sizeof(SYSTEM_PROCESS_INFORMATION);
    std::vector<BYTE> memory(3*stride);
    for(size_t i=0;i<3;++i) {
        SYSTEM_PROCESS_INFORMATION record{};
        record.NextEntryOffset=i==2 ? 0 : ULONG(stride);
        record.UniqueProcessId=reinterpret_cast<HANDLE>(i+1);
        record.ImageName.Buffer=const_cast<wchar_t*>(L"p");
        record.ImageName.Length=sizeof(WCHAR);
        std::memcpy(memory.data()+i*stride,&record,stride);
    }
    auto results=walk_upstream(memory);
    assert(results.size()==2 && results[0].pid==2 && results[1].pid==3);
    std::cout << "upstream process walker: records 1,2,3 -> 2,3 (first skipped, last retained)\n";
}


int main() {
    test_walk();
    opens=closes=0;
    auto path=get_module_name(reinterpret_cast<HANDLE>(123),reinterpret_cast<HMODULE>(456));
    assert(local_queries==1 && path==L"LOCAL_MODULE");
    std::cout << "upstream long-path fallback calls current-process API: confirmed (mock)\n";
    auto modules=process_modules(123);
    assert(modules.empty() && opens==1 && closes==0);
    std::cout << "upstream EnumProcessModules failure leaks opened process handle: confirmed (mock)\n";
    assert(!starts_with(L"C:\\a",L"C:\\A"));
    assert(!starts_with(L"C:\\ab",L"C:\\a\\"));
    std::cout << "upstream prefix comparison is case-sensitive and boundary respected: confirmed\n";
    auto release=std::make_shared<std::promise<void>>();
    auto wait=release->get_future();
    auto done=std::make_shared<std::promise<void>>();
    auto finished=done->get_future();
    std::thread worker([wait=std::move(wait),done]() mutable { wait.wait(); done->set_value(); });
    assert(worker.native_handle()!=nullptr);
    worker.detach();
    assert(worker.native_handle()==nullptr);
    release->set_value(); finished.wait();
    std::cout << "MSVC native_handle after detach is null: confirmed (no thread termination)\n";
}
