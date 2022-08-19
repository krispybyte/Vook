# :video_game: Vook - Valve Hook
The `Vook` is a **single-header** library that allows you to call **Valve's hooking functions** in their **GameOverlayRenderer.dll** & **GameOverlayRenderer64.dll** libraries.
While making the project I found out it was already done by others previously, however they did not include support for Valve's 64-bit overlay library and so I decided to add support for games using it.
**As always, PR's are welcome!**

### :game_die: Usage Example
A `Vook` hook example can be found [here](Vook/Example.cpp).

### :gear: Library Functions
```cpp
// Hooks a function.
bool Vook::Hook(
    void* FunctionAddress, // The initial function's address
    void* HookAddress, // The hook's address
    void* OriginalAddress // The original's address
)

// Unhooks a function.
void Vook::Unhook(
    void* FunctionAddress // The initial function's address
)

// Unhooks all functions.
void Vook::UnhookAll()
```

### :zap: Cloning Vook
```bash
$ git clone https://github.com/krispybyte/Vook.git
```

### :balance_scale: License
This project is licensed under the **MIT** license.

### :trollface: Sick of Valve's hooking library?
Use the **[Trampy](https://github.com/AdamOron/Trampy/)** library today! (this is definitely not an ad).