#include <windows.h>
#include <winbase.h>
#include <winuser.h>
#include <string>
#include <thread>
#include <atomic>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#include <TlHelp32.h>

#define NOMINMAX

std::atomic_bool shutdown_event(false);
std::mutex log_mutex;

void log_message(const std::wstring& message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::wcout << message << std::endl;
}

void adjust_privileges() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;

    try {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            throw std::runtime_error("Failed to open process token.");
        }

        LUID luid;
        if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
            throw std::runtime_error("Failed to look up privilege value.");
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr)) {
            throw std::runtime_error("Failed to adjust token privileges.");
        }

        log_message(L"Privileges adjusted successfully.");
    }
    catch (const std::exception& e) {
        std::wstring error_message = L"Failed to adjust privileges: " + std::wstring(e.what(), e.what() + strlen(e.what()));
        log_message(error_message);
    }
}

void handle_client(HANDLE pipe) {
    DWORD bytesRead;
    char buffer[4096];

    try {
        while (true) {
            BOOL result = ReadFile(pipe, buffer, sizeof(buffer), &bytesRead, nullptr);
            if (result && bytesRead > 0) {
                std::wstring data;
                int len = MultiByteToWideChar(CP_UTF8, 0, buffer, bytesRead, nullptr, 0);
                if (len > 0) {
                    data.resize(len);
                    MultiByteToWideChar(CP_UTF8, 0, buffer, bytesRead, &data[0], len);
                }

                std::wcout << L"Received data: " << data << std::endl;

                WriteFile(pipe, buffer, bytesRead, &bytesRead, nullptr);
                std::wcout << L"Sent data back: " << data << std::endl;
            }
            else {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }
    catch (const std::exception& e) {
        std::wcerr << L"Communication error: " << e.what() << std::endl;
    }
    CloseHandle(pipe);
    std::wcout << L"Pipe connection closed." << std::endl;
}

void create_named_pipe(const std::wstring& pipe_name) {
    std::wstring pipe_path = L"\\\\.\\pipe\\" + pipe_name;

    try {
        while (!shutdown_event.load()) {
            HANDLE pipe = CreateNamedPipeW(
                pipe_path.c_str(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                104857600,
                104857600,
                500,
                nullptr
            );

            if (pipe == INVALID_HANDLE_VALUE) {
                throw std::runtime_error("Failed to create pipe.");
            }

            log_message(L"Pipe created. Waiting for connections...");
            BOOL connected = ConnectNamedPipe(pipe, nullptr);
            if (connected) {
                log_message(L"Client connected. Assigning to thread pool.");
                std::thread(handle_client, pipe).detach();
            }
            else {
                CloseHandle(pipe);
                log_message(L"Error connecting to pipe.");
            }
        }
    }
    catch (const std::exception& e) {
        std::wstring error_message = L"Pipe creation error: " + std::wstring(e.what(), e.what() + strlen(e.what()));
        log_message(error_message);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void override_vgc_pipe(const std::wstring& pipe_name) {
    std::wstring pipe_path = L"\\\\.\\pipe\\" + pipe_name;

    try {
        HANDLE pipeHandle = CreateFileW(
            pipe_path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );

        if (pipeHandle == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Failed to connect to original pipe.");
        }

        log_message(L"Connected to the original vgc.exe pipe at " + pipe_path);
        CloseHandle(pipeHandle);
        log_message(L"Original vgc.exe pipe closed and replaced by emulated pipe.");

        create_named_pipe(pipe_name);
    }
    catch (const std::exception& e) {
        std::wstring error_message = L"Error connecting to the original pipe: " + std::wstring(e.what(), e.what() + strlen(e.what()));
        log_message(error_message);
    }
}

void start_vgc_service() {
    SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scManager == nullptr) {
        log_message(L"Failed to open Service Control Manager.");
        return;
    }

    SC_HANDLE vgcService = OpenServiceW(scManager, L"vgc", SERVICE_START);
    if (vgcService == nullptr) {
        log_message(L"Failed to open vgc service.");
        CloseServiceHandle(scManager);
        return;
    }

    if (StartServiceW(vgcService, 0, nullptr)) {
        log_message(L"Successfully started the vgc service.");
    }
    else {
        log_message(L"Failed to start vgc service.");
    }

    CloseServiceHandle(vgcService);
    CloseServiceHandle(scManager);
}

int main() {
    std::wstring pipe_name = L"933823D3-C77B-4BAE-89D7-A92B567236BC";

    system("sc stop vgk");
    system("sc stop vgc");
    Sleep(200);
    system("sc start vgk");
    system("sc start vgc");
    system("cls");
    Sleep(500);
    override_vgc_pipe(pipe_name);
    create_named_pipe(pipe_name);

    return 0;
}