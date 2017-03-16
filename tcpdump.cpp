// tcpdump.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "WinPCap.h"

static const TCHAR * STARTED = _T("Global\\tcpdump_started");
static const TCHAR * DONE = _T("Global\\tcpdump_done");
static const TCHAR * TIME_TO_EXIT = _T("Global\\tcpdump_time_to_exit");

/*-----------------------------------------------------------------------------
-----------------------------------------------------------------------------*/
bool run(LPCSTR captureFile) {
  bool ok = false;
  SECURITY_ATTRIBUTES null_dacl;
  SECURITY_DESCRIPTOR SD;
  ZeroMemory(&null_dacl, sizeof(null_dacl));
  null_dacl.nLength = sizeof(null_dacl);
  null_dacl.bInheritHandle = FALSE;
  if( InitializeSecurityDescriptor(&SD, SECURITY_DESCRIPTOR_REVISION) )
    if( SetSecurityDescriptorDacl(&SD, TRUE,(PACL)NULL, FALSE) )
      null_dacl.lpSecurityDescriptor = &SD;
  HANDLE hMustExit = CreateEvent(&null_dacl, TRUE, FALSE, TIME_TO_EXIT);
  HANDLE hDone = CreateEvent(&null_dacl, TRUE, FALSE, DONE);
  HANDLE hStarted = OpenEvent(EVENT_MODIFY_STATE, FALSE, STARTED);
  if (hStarted) {
    SetEvent(hStarted);
    CloseHandle(hStarted);
  }
  CWinPCap pcap;
  if (hMustExit && pcap.StartCapture(captureFile)) {
    ok = true;
    WaitForSingleObject(hMustExit, 3600000);  // Let it run for an hour at most
    pcap.StopCapture();
  }
  if (hDone) {
    SetEvent(hDone);
    CloseHandle(hDone);
  }
  if (hMustExit) {
    CloseHandle(hMustExit);
  }
  return ok;
}

/*-----------------------------------------------------------------------------
-----------------------------------------------------------------------------*/
bool start(LPCSTR captureFile) {
  bool ok = false;
  SECURITY_ATTRIBUTES null_dacl;
  SECURITY_DESCRIPTOR SD;
  ZeroMemory(&null_dacl, sizeof(null_dacl));
  null_dacl.nLength = sizeof(null_dacl);
  null_dacl.bInheritHandle = FALSE;
  if( InitializeSecurityDescriptor(&SD, SECURITY_DESCRIPTOR_REVISION) )
    if( SetSecurityDescriptorDacl(&SD, TRUE,(PACL)NULL, FALSE) )
      null_dacl.lpSecurityDescriptor = &SD;
  HANDLE hStarted = CreateEvent(&null_dacl, TRUE, FALSE, STARTED);

  WCHAR exe[MAX_PATH];
  GetModuleFileNameW(NULL, exe, MAX_PATH);
  WCHAR command_line[MAX_PATH * 2 + 100];
  wsprintfW(command_line, L"\"%s\" run \"%S\"", exe, captureFile);
  STARTUPINFO si;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi;
  if (CreateProcess(NULL, command_line, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    if (hStarted)
      WaitForSingleObject(hStarted, 30000);
    ok = true;
  }

  CloseHandle(hStarted);
  return ok;
}

/*-----------------------------------------------------------------------------
-----------------------------------------------------------------------------*/
bool stop() {
  bool ok = false;
  HANDLE hMustExit = OpenEvent(EVENT_MODIFY_STATE, FALSE, TIME_TO_EXIT);
  HANDLE hDone = OpenEvent(EVENT_MODIFY_STATE, FALSE, DONE);
  if (hMustExit && hDone) {
    SetEvent(hMustExit);
    WaitForSingleObject(hDone, 60000);
    ok = true;
  }
  if (hMustExit)
    CloseHandle(hMustExit);
  if (hDone)
    CloseHandle(hDone);
  return ok;
}

/*-----------------------------------------------------------------------------
-----------------------------------------------------------------------------*/
int main(int argc, char *argv[]) {
  bool ok = false;
  bool valid_command = false;
  if (argc > 1) {
    valid_command = true;
    if (!lstrcmpA(argv[1], "run") && argc > 2) {
      ok = run(argv[2]);
    } else if (!lstrcmpA(argv[1], "start") && argc > 2) {
      ok = start(argv[2]);
      if (ok)
        printf("Packet capture started\n");
      else
        printf("FAILED to start packet capture");
    } else if (!lstrcmpA(argv[1], "stop")) {
      ok = stop();
      if (ok)
        printf("Packet capture done\n");
      else
        printf("FAILED to stop packet capture");
    } else if (!lstrcmpA(argv[1], "interface")) {
      CWinPCap pcap;
      pcap.FindInterface();
    } else if (!lstrcmpA(argv[1], "check")) {
      CWinPCap pcap;
      ok = pcap.IsInstalled();
      if (ok) {
        printf("NPCap detected");
      } else {
        printf("NPCap not detected.  Please make sure it is installed and configured to start automatically.\n");
      }
    } else {
      valid_command = false;
    }
  } 

  if (!valid_command) {
    printf("Usage:\n"
           "    tcpdump start <capture file>     - Starts capturing in the background.\n"
           "    tcpdump stop                     - Stops a running capture.\n"
           "    tcpdump interface                - Display the interface name that will be used for capture.\n"
           "    tcpdump check                    - Checks WinPCap install status.\n");
  }
  return ok ? 0 : 1;
}

