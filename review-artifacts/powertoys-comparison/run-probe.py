from pathlib import Path
import subprocess
out=Path(__file__).parent
src=Path(r'D:\playground\dotnet\PowerToys\src\modules\FileLocksmith\FileLocksmithLibInterop\NtdllExtensions.cpp').read_text()
paths=Path(r'D:\playground\dotnet\PowerToys\src\modules\FileLocksmith\FileLocksmithLibInterop\FileLocksmith.cpp').read_text()
def extract(text, signature):
    start=text.index(signature); brace=text.index('{',start); level=1; end=brace+1
    while level:
        if text[end]=='{': level+=1
        elif text[end]=='}': level-=1
        end+=1
    return text[start:end]
preamble=r'''// Contains excerpts from Microsoft PowerToys.
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
'''
functions=extract(src,'inline std::wstring get_module_name')+'\n'+extract(src,'std::vector<std::wstring> process_modules')+'\n'+extract(paths,'static constexpr bool starts_with')
start=src.index('    std::vector<ProcessInfo> result;',src.index('NtdllExtensions::processes()'))
end=src.index('    return result;',start)+len('    return result;')
walk=src[start:end]
extra=r'''
struct ProcessInfo { DWORD pid; std::wstring name,user; std::vector<std::wstring> modules; };
std::wstring unicode_to_str(UNICODE_STRING s) { return std::wstring(s.Buffer,s.Length/sizeof(WCHAR)); }
std::wstring pid_to_user(DWORD) { return L""; }
std::vector<ProcessInfo> walk_upstream(std::vector<BYTE> memory) {
    struct { std::vector<BYTE> memory; } get_info_result{std::move(memory)};
'''+walk+r'''
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
'''
main=r'''
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
'''
generated=preamble+functions+'\n'+extra+'\n'+main
(out/'probe.cpp').write_text('\n'.join(line.rstrip() for line in generated.splitlines())+'\n')
vs=subprocess.check_output([r'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe','-latest','-products','*','-property','installationPath'],text=True).strip()
build='@echo off\ncall "'+vs+'\\VC\\Auxiliary\\Build\\vcvars64.bat" >nul\nif errorlevel 1 exit /b %errorlevel%\ncl /nologo /EHsc /std:c++20 /W4 /WX probe.cpp /Fe:probe.exe\nif errorlevel 1 exit /b %errorlevel%\nprobe.exe\n'
(out/'build.cmd').write_text(build)
proc=subprocess.run(['cmd.exe','/d','/c',str(out/'build.cmd')],cwd=out,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
(out/'probe-output.txt').write_text(proc.stdout)
print(proc.stdout)
raise SystemExit(proc.returncode)
