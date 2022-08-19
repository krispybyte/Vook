#include <Windows.h>
#include <thread>
#include "Vook.hpp"

namespace Hooks
{
    namespace GetCurrentProcessId
    {
        using FnGetCurrentProcessId = DWORD(__stdcall*)();
        void* Address;
        FnGetCurrentProcessId Original;
        DWORD __stdcall Hook()
        {
            std::printf("Hi from hook :)\n");
            return Original();
        }
    }
}

void Attach(const HMODULE Instance)
{
    auto Shutdown = [Instance]() -> void
    {
        FreeLibraryAndExitThread(Instance, EXIT_FAILURE);
    };

    // Ensure the library overlay library is loaded
    [[unlikely]]
#ifdef _WIN64
    while (!GetModuleHandleA("gameoverlayrenderer64.dll"))
#else
    while (!GetModuleHandleA("gameoverlayrenderer.dll"))
#endif
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    // Allocate a new console and attach to it
    AllocConsole();

    // Set the title for the new console
    SetConsoleTitleA("Vook Example");

    // Set permissions for the new console stream
    FILE* NewConsoleStream;
    freopen_s(&NewConsoleStream, "CONIN$", "r", stdin);
    freopen_s(&NewConsoleStream, "CONOUT$", "w", stdout);
    freopen_s(&NewConsoleStream, "CONOUT$", "w", stderr);

    // Initialize Vook
    [[unlikely]]
    if (!Vook::Initialize())
    {
        std::printf("Failed initializing Vook...\n");
        Shutdown();
    }

    // Hook with Vook
    const HMODULE Kernel32Lib = GetModuleHandleA("kernel32.dll");

    [[unlikely]]
    if (!Kernel32Lib)
    {
        std::printf("Failed finding kernel32.dll...\n");
        Shutdown();
    }

    Hooks::GetCurrentProcessId::Address = GetProcAddress(Kernel32Lib, "GetCurrentProcessId");

    [[unlikely]]
    if (!Hooks::GetCurrentProcessId::Address)
    {
        std::printf("Failed finding GetCurrentProcessId...\n");
        Shutdown();
    }

    Vook::Hook(Hooks::GetCurrentProcessId::Address, &Hooks::GetCurrentProcessId::Hook, &Hooks::GetCurrentProcessId::Original);

    [[likely]]
    while (!GetAsyncKeyState(VK_DELETE))
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::printf("Unloading Vook Example...\n");

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    FreeLibraryAndExitThread(Instance, EXIT_SUCCESS);
}

void Detach()
{
    Beep(125, 150);

    // Close all file streams
    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    // Free the allocated console
    FreeConsole();

    // Unhook all Vook hooks
    Vook::UnhookAll();

    // Example of unhooking a specific hook
    // Vook::Unhook(Hooks::GetCurrentProcessId::Address);
}

bool WINAPI DllMain(HINSTANCE Instance, DWORD Reason, LPVOID Reserved)
{
    HANDLE MainThread;

    switch (Reason)
    {
        case DLL_PROCESS_ATTACH:
            MainThread = CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&Attach), Instance, 0, 0);
            [[unlikely]]
            if (MainThread == INVALID_HANDLE_VALUE)
                throw std::exception("Error creating a thread.");
            else
                CloseHandle(MainThread);
            break;
        case DLL_PROCESS_DETACH:
            Detach();
            break;
    }

    return true;
}