#include <iostream>
#include <Windows.h>

#define IOCTL_PROTECT_PID    CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main(int argc, const char* argv[]) {
    DWORD bytes;

    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <pid>" << std::endl;
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    HANDLE device = CreateFile(L"\\\\.\\Protector", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (device == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to open device" << std::endl;
        return 1;
    }

    bool success = DeviceIoControl(device, IOCTL_PROTECT_PID, &pid, sizeof(pid), nullptr, 0, &bytes, nullptr);
    CloseHandle(device);

    if (!success) {
        std::cout << "Failed in DeviceIoControl: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "Protected process with pid: " << pid << std::endl;
    return 0;
}