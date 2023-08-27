#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;

DRIVER_UNLOAD ProtectorUnload;
DRIVER_DISPATCH ProtectorCreateClose, ProtectorDeviceControl;

OB_PREOP_CALLBACK_STATUS PreOpenProcessOperation(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);

// Definitions
#define IOCTL_PROTECT_PID    CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PROCESS_TERMINATE	  0x1
#define PROCESS_CREATE_THREAD 0x2
#define PROCESS_VM_READ		  0x10
#define PROCESS_VM_OPERATION  0x8

PVOID regHandle;
ULONG protectedPid = 0;

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING registry) {
    UNREFERENCED_PARAMETER(registry);

    NTSTATUS status = STATUS_SUCCESS;

    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\Protector");
    UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\Protector");
    PDEVICE_OBJECT DeviceObject = NULL;

    OB_OPERATION_REGISTRATION operations[] = {
        {
            PsProcessType,
            OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
            PreOpenProcessOperation, NULL
        }
    };

    OB_CALLBACK_REGISTRATION reg = {
        OB_FLT_REGISTRATION_VERSION,
        1,
        RTL_CONSTANT_STRING(L"12345.6879"),
        NULL,
        operations
    };

    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&symName, &deviceName);

    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(DeviceObject);
        return status;
    }

    status = ObRegisterCallbacks(&reg, &regHandle);

    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&symName);
        IoDeleteDevice(DeviceObject);
        return status;
    }

    DriverObject->DriverUnload = ProtectorUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = ProtectorCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ProtectorDeviceControl;

    return status;
}

NTSTATUS ProtectorCreateClose(PDEVICE_OBJECT pob, PIRP Irp) {
    UNREFERENCED_PARAMETER(pob);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS ProtectorDeviceControl(PDEVICE_OBJECT pob, PIRP Irp) {
    UNREFERENCED_PARAMETER(pob);

    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_PROTECT_PID:
    {
        ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

        if (size != sizeof(ULONG)) {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        ULONG* data = (ULONG*)Irp->AssociatedIrp.SystemBuffer;
        protectedPid = *data;
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

OB_PREOP_CALLBACK_STATUS PreOpenProcessOperation(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (Info->KernelHandle)
        return OB_PREOP_SUCCESS;

    PEPROCESS process = (PEPROCESS)Info->Object;
    HANDLE processId = PsGetProcessId(process);

    // Convert the HANDLE to ULONG (PID)
    ULONG pid = HandleToULong(processId);

    // Protecting our pid by removing terminate, dump and write process memory access.
    if (pid == protectedPid) {
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;

        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
        //Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
    }

    return OB_PREOP_SUCCESS;
}

void ProtectorUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\Protector");

    // Unregister the callback
    ObUnRegisterCallbacks(regHandle);

    // Delete the symbolic link and device object
    IoDeleteSymbolicLink(&symName);
    if (DriverObject->DeviceObject)
        IoDeleteDevice(DriverObject->DeviceObject);

    KdPrint(("ProtectorUnload: Unloaded\n"));
}
