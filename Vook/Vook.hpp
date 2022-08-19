#pragma once
#include <Windows.h>
#include <cstddef>
#include <vector>

namespace Vook
{
    std::uint8_t* PatternScan(const HMODULE Module, const char* Signature)
    {
        [[unlikely]]
        if (!Module)
            return {};

        static auto PatternToBytes = [](const char* Pattern)
        {
            auto Bytes = std::vector<int>{};
            char* StartPos = const_cast<char*>(Pattern);
            char* EndPos = const_cast<char*>(Pattern) + std::strlen(Pattern);

            for (auto CurrentChar = StartPos; CurrentChar < EndPos; ++CurrentChar)
            {
                if (*CurrentChar == '?')
                {
                    ++CurrentChar;

                    if (*CurrentChar == '?')
                        ++CurrentChar;

                    Bytes.push_back(-1);
                }
                else
                    Bytes.push_back(std::strtoul(CurrentChar, &CurrentChar, 16));
            }

            return Bytes;
        };

        const IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(Module);
        const IMAGE_NT_HEADERS* NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<std::uint8_t*>(Module) + DosHeader->e_lfanew);

        auto PatternBytes = PatternToBytes(Signature);
        const std::size_t PatternBytesSize = PatternBytes.size();
        const int* PatternBytesData = PatternBytes.data();

        const auto ImageSize = NtHeaders->OptionalHeader.SizeOfImage;
        std::uint8_t* ScanBytes = reinterpret_cast<std::uint8_t*>(Module);

        for (unsigned long i = 0; i < ImageSize - PatternBytesSize; ++i)
        {
            bool Found = true;

            for (unsigned long j = 0; j < PatternBytesSize; ++j)
            {
                if (ScanBytes[i + j] != PatternBytesData[j] && PatternBytesData[j] != -1)
                {
                    Found = false;
                    break;
                }
            }

            [[unlikely]]
            if (Found)
                return &ScanBytes[i];
        }
    
        return {};
    }

#ifdef _WIN64
    // char __fastcall ValveHookWrapper(void *FnAddr, __int64 HkAddr, _QWORD *OgAddr, int PreserveLogs)
    using FnValveHook = char(__fastcall*)(void*, void*, void*, int);
#else
    // char __cdecl ValveHook(LPVOID FnAddr, int HkAddr, int OgAddr, int PreserveLogs)
    using FnValveHook = char(__cdecl*)(void*, void*, void*, int);
#endif
    FnValveHook ValveHook;

#ifdef _WIN64
    // void __fastcall ValveUnhook(unsigned __int64 FnAddr, char a2)
    using FnValveUnhook = void(__fastcall*)(void*, char);
#else
    // void __cdecl ValveUnhook(unsigned int FnAddr, char a2)
    using FnValveUnhook = void(__cdecl*)(unsigned int, char);
#endif
    FnValveUnhook ValveUnhook;

    // Store all hooks
    std::vector<void*> EnabledHooks;

    bool Initialize()
    {
#ifdef _WIN64
        const HMODULE GameOverlayRenderer = GetModuleHandleA("gameoverlayrenderer64.dll");
#else
        const HMODULE GameOverlayRenderer = GetModuleHandleA("gameoverlayrenderer.dll");
#endif

        [[unlikely]]
        if (!GameOverlayRenderer)
            return false;

#ifdef _WIN64
        ValveHook = reinterpret_cast<FnValveHook>(PatternScan(GameOverlayRenderer, "48 89 5C 24 ? 57 48 83 EC 30 33 C0"));
#else
        ValveHook = reinterpret_cast<FnValveHook>(PatternScan(GameOverlayRenderer, "55 8B EC 51 8B 45 10 C7"));
#endif

        [[unlikely]]
        if (!ValveHook)
            return false;

#ifdef _WIN64
		const std::uint8_t* JmpAddress = PatternScan(GameOverlayRenderer, "E8 ? ? ? ? FF 15 ? ? ? ? 48 89 45 E8");
#else
        const std::uint8_t* JmpAddress = PatternScan(GameOverlayRenderer, "E8 ? ? ? ? 83 C4 08 FF 15 ? ? ? ?");
#endif

        ValveUnhook = reinterpret_cast<FnValveUnhook>(JmpAddress + 5 + *(DWORD*)(JmpAddress + 1));

		[[unlikely]]
		if (!ValveUnhook)
			return false;

        return true;
    }

    bool Hook(void* FunctionAddress, void* HookAddress, void* OriginalAddress)
    {
        const bool SuccessfullyHooked = static_cast<bool>(ValveHook(FunctionAddress, HookAddress, OriginalAddress, 0));

        [[likely]]
        if (SuccessfullyHooked)
            EnabledHooks.push_back(FunctionAddress);

        return SuccessfullyHooked;
    }

	void Unhook(void* FunctionAddress)
	{
#ifdef _WIN64
		ValveUnhook(FunctionAddress, 0);
#else
		ValveUnhook(reinterpret_cast<unsigned int>(FunctionAddress), 0);
#endif
	}

    void UnhookAll()
    {
        for (void* EnabledHook : EnabledHooks)
            Unhook(EnabledHook);
    }
}