#include <Windows.h>
#include <iostream>

#include "detours.h"
#include "sigscan.h"

// this is the function that the program
// will jump to when sum() is called in the original program (testprogram.exe)

DWORD AddressOfSum = 0;
// template for the original function
typedef int(*sum)(int x, int y); 

int HookSum(int x, int y)
{
	// manipulate the arguments
	x += 500;
	y += 500;

	// we manipulate the arguments here and then
	// redirect the program to the original function

	std::cout << "your program has been hacked! " << std::endl;
	sum originalSum = (sum)AddressOfSum;
	return originalSum(x, y);
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	// store the address of sum() in testprogram.exe here.

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		// We will use signature scanning to find the function that we want to hook
		// we will find the function in IDA pro and create a signature from it:

		SigScan Scanner;

		// testprogram.exe is the name of the main module in our target process
		AddressOfSum = Scanner.FindPattern("testprogram.exe", "\x55\x8B\xEC\x8B\x45\x08\x03\x45\x0C", "xxxxxxxxx");

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// this will hook the function
		DetourAttach(&(LPVOID&)AddressOfSum, &HookSum);

		DetourTransactionCommit();
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		// unhook
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// this will hook the function
		DetourDetach(&(LPVOID&)AddressOfSum, &HookSum);

		DetourTransactionCommit();
	}
	return TRUE;
}