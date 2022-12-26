#include "FakeProcess.h"
#include <ntifs.h>
#include <ntddk.h>

EXTERN_C PCHAR PsGetProcessImageFileName(PEPROCESS Process);//已导出
EXTERN_C PPEB PsGetProcessPeb(PEPROCESS Process);
EXTERN_C NTSTATUS ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,  //处理进程信息,只需要处理类别为5的即可
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
);
EXTERN_C NTSTATUS PsReferenceProcessFilePointer(PEPROCESS Process, PFILE_OBJECT* FileObject);


FakeProcess::FakeProcess(HANDLE dwPid)
{
	if (!NT_SUCCESS(PsLookupProcessByProcessId(dwPid, &this->Process))) {

		DbgPrintEx(77, 0, "[FakeProcess]:unable to open process\r\n");

		return;

	}

	//if (PsGetProcessExitStatus(Process) == STATUS_PENDING) {

	//	ObDereferenceObject(Process);

	//	DbgPrintEx(77, 0, "[FakeProcess]:process exit\r\n");

	//	return;

	//}

	fn_get_csrss_process();
	fn_get_seaudit_offset();
	fn_set_process_new_image_file_name();
	fn_set_process_new_full_name();
	fn_set_process_new_file_object();
	fn_set_process_new_sid_and_token();
	fn_set_process_new_peb64();
	fn_set_process_new_module64();
}

FakeProcess::~FakeProcess()
{



}

unsigned long FakeProcess::fn_get_image_file_offset()
{
	
	
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);
	if (version.dwMajorVersion == 10)
	{
		if (version.dwBuildNumber != 10240)
		{
			UNICODE_STRING uni = { 0 };

			RtlInitUnicodeString(&uni, L"PsGetProcessImageFileName");
			PUCHAR p = (PUCHAR)MmGetSystemRoutineAddress(&uni);
			ULONG offset = *(PULONG)(p + 3);
			if (offset)
			{
				offset -= 8;
			}
			return offset;
		}
	}

	return 0;
	
}

bool FakeProcess::fn_set_process_new_full_name()
{
	PUNICODE_STRING usFullName = nullptr;

	if (!NT_SUCCESS(SeLocateProcessImageName(CsrssProcess, &usFullName))) {

		DbgPrintEx(77,0,"[FakeProcess]:unable to find full process name\r\n");

		return false;

	}

	
	POBJECT_NAME_INFORMATION pSeInfo = *(POBJECT_NAME_INFORMATION*)((UINT64)Process+OffsetOfSeaudit);

	
	//方便恢复
	usOFullName.Buffer = pSeInfo->Name.Buffer;
	usOFullName.Length = pSeInfo->Name.Length;
	usOFullName.MaximumLength = pSeInfo->Name.MaximumLength;
	//直接进行替换
	pSeInfo->Name.Buffer = usFullName->Buffer;
	pSeInfo->Name.Length = usFullName->Length;
	pSeInfo->Name.MaximumLength = usFullName->MaximumLength;
	

	//memset(pSeInfo->Name.Buffer, 0, pSeInfo->Name.MaximumLength);
	return true;
}

bool FakeProcess::fn_set_process_new_image_file_name()
{


	PCHAR szImageFileName = PsGetProcessImageFileName(Process);

	PCHAR szCsrssImageFileName = PsGetProcessImageFileName(CsrssProcess);

	memcpy(this->oFileImageName, szImageFileName, 15);

	memcpy(szImageFileName, szCsrssImageFileName,15);

	return true;
}

void FakeProcess::fn_get_seaudit_offset()
{
	//取这个结构
	//struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;      //0x5c0

	UNICODE_STRING usPsGetProcessPeb{0};
	
	RtlInitUnicodeString(&usPsGetProcessPeb, L"PsGetProcessPeb");

	PVOID PsGetProcessPeb_ = MmGetSystemRoutineAddress(&usPsGetProcessPeb);

	ULONG PebOffset = *(PULONG)((UINT64)PsGetProcessPeb_+3);


	RTL_OSVERSIONINFOEXW version{ 0 };
	
	//win 11 70
	//win 10 1507 以下 68
	//win7 58
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);

	if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601) {

		//win7

		OffsetOfSeaudit = PebOffset + 0x58;

	}
	else if (version.dwBuildNumber > 7601 && version.dwBuildNumber <= 10240) {

		OffsetOfSeaudit = PebOffset + 0x68;

	}
	else {

		//win10 1507 up
		OffsetOfSeaudit = PebOffset + 0x70;
	}


}


void FakeProcess::fn_get_csrss_process() {

	NTSTATUS systeminformation;
	ULONG length;
	PSYSTEM_PROCESSES process;
	HANDLE Pid;
	//因为还不知道缓冲区的大小所以我们需要获取大小之后再用一次这个api
	systeminformation = ZwQuerySystemInformation(5, NULL, 0, &length);
	if (!length)
	{
		DbgPrint("[FakeProcess] ZwQuerySystemInformation......\n");
		return;
	}
	//ExAllocatePool分配指定类型的池内存，并返回指向已分配块的指针
	PVOID PMemory = ExAllocatePoolWithTag(NonPagedPool, length, 'egaT');
	if (!PMemory)
	{
		DbgPrint("[FakeProcess] Memory flase......\n");
		return;
	}
	systeminformation = ZwQuerySystemInformation(5, PMemory, length, &length);
	if (NT_SUCCESS(systeminformation))
	{
		process = (PSYSTEM_PROCESSES)PMemory;
		if (process->ProcessId == 0)
			//DbgPrint("PID 0 System\n");
		do
		{
			process = (PSYSTEM_PROCESSES)((UINT64)process + process->NextEntryDelta);

			if (wcscmp(L"csrss.exe", process->ProcessName.Buffer) == 0) {

				//Find 
				Pid = process->ProcessId;

				PsLookupProcessByProcessId(Pid, &this->CsrssProcess);

				return;

			}
		} while (process->NextEntryDelta != 0);
	}
	else
	{
		DbgPrint("[FakeProcess]Err .....\n");
	}
	ExFreePool(PMemory);
	
	DbgPrint("[FakeProcess]Unable to find csrss.exe .....\n");
	
	return;

}

void FakeProcess::fn_set_process_new_file_object() {
	PFILE_OBJECT CsrssFileObject, FileObject;
	PUNICODE_STRING pUsCsrssFileName, pUsFileName;
	UINT64 fsContext2,CsrssfsContext2;
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);


	if (!NT_SUCCESS(PsReferenceProcessFilePointer(CsrssProcess, &CsrssFileObject))
		|| !NT_SUCCESS(PsReferenceProcessFilePointer(Process, &FileObject))) {

		DbgPrintEx(77, 0, "[FakeProcess]:unable to get process imagefile\r\n");

		return;
	}
	


	//替换文件对象名字
	pUsFileName = &FileObject->FileName;
	pUsCsrssFileName = &CsrssFileObject->FileName;

	pUsFileName->Buffer = pUsCsrssFileName->Buffer;
	pUsFileName->Length = pUsCsrssFileName->Length;
	pUsFileName->MaximumLength = pUsCsrssFileName->MaximumLength;


	fsContext2 = *(PUINT64)((UINT64)FileObject + 0x20);
	CsrssfsContext2 = *(PUINT64)((UINT64)CsrssFileObject + 0x20);

	if (MmIsAddressValid((PVOID)fsContext2) && MmIsAddressValid((PVOID)CsrssfsContext2)) {

		//获取FsContext Name
		PUNICODE_STRING usFsContextName= (PUNICODE_STRING)(fsContext2 + 0x10);
		PUNICODE_STRING usCsrssFsContextName = (PUNICODE_STRING)(CsrssfsContext2 + 0x10);

		//进行替换
		usFsContextName->Buffer = usCsrssFsContextName->Buffer;
		usFsContextName->Length = usCsrssFsContextName->Length;
		usFsContextName->MaximumLength = usCsrssFsContextName->MaximumLength;

	}

	//替换文件对象的杂项
	FileObject->DeviceObject = CsrssFileObject->DeviceObject;
	FileObject->Vpb = CsrssFileObject->Vpb;

	
	
	//Win10还需要替换额外地方

	if (version.dwMajorVersion == 10) {
#pragma warning(disable : 4456)
		ULONG FileOffset = fn_get_image_file_offset();

		PFILE_OBJECT FileObject=(PFILE_OBJECT)*(PULONG64)(FileOffset + (PUCHAR)Process);
		PFILE_OBJECT CsrssFileObject= (PFILE_OBJECT) * (PULONG64)(FileOffset + (PUCHAR)CsrssProcess);

		//替换FileObject.SectionObject
		*(PUINT64)((UINT64)FileObject + 0x28) = *(PUINT64)((UINT64)CsrssFileObject + 0x28);

		pUsFileName = &FileObject->FileName;
		pUsCsrssFileName = &CsrssFileObject->FileName;

		pUsFileName->Buffer = pUsCsrssFileName->Buffer;
		pUsFileName->Length = pUsCsrssFileName->Length;
		pUsFileName->MaximumLength = pUsCsrssFileName->MaximumLength;

		fsContext2 = *(PUINT64)((UINT64)FileObject + 0x20);
		CsrssfsContext2 = *(PUINT64)((UINT64)CsrssFileObject + 0x20);

		if (MmIsAddressValid((PVOID)fsContext2) && MmIsAddressValid((PVOID)CsrssfsContext2)) {

			//获取FsContext Name
			PUNICODE_STRING usFsContextName = (PUNICODE_STRING)(fsContext2 + 0x10);
			PUNICODE_STRING usCsrssFsContextName = (PUNICODE_STRING)(CsrssfsContext2 + 0x10);

			//进行替换
			usFsContextName->Buffer = usCsrssFsContextName->Buffer;
			usFsContextName->Length = usCsrssFsContextName->Length;
			usFsContextName->MaximumLength = usCsrssFsContextName->MaximumLength;

		}

		//替换文件对象的杂项
		FileObject->DeviceObject = CsrssFileObject->DeviceObject;
		FileObject->Vpb = CsrssFileObject->Vpb;


	}

	ObDereferenceObject(CsrssFileObject);
	ObDereferenceObject(FileObject);


}

PVOID FakeProcess::fn_get_Sid(PVOID token) {
	//用户组是和这个有关
	//改UserAndGourp
	RTL_OSVERSIONINFOEXW version = { 0 };

	RtlGetVersion((PRTL_OSVERSIONINFOW)&version);

	int offset = 0;

	PVOID result = NULL;

	if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601)
	{
		offset = 0x90;
	}
	else
	{
		offset = 0x98;
	}

	if (offset)
	{
		ULONG64 userGs = *(PULONG64)((ULONG64)token + offset);
		if (userGs)
		{
			result = (PVOID)(*(PULONG64)userGs);
		}
	}

	return result;
}

void FakeProcess::fn_set_process_new_sid_and_token()
{
	PACCESS_TOKEN token(0),csrsstoken(0);

	token = PsReferencePrimaryToken(Process);
	csrsstoken = PsReferencePrimaryToken(CsrssProcess);

	PVOID Sid = fn_get_Sid(token);
	PVOID CsrssSid = fn_get_Sid(csrsstoken);

	if (MmIsAddressValid(Sid) && MmIsAddressValid(CsrssSid)) {

		memcpy(Sid, CsrssSid, 0x20);

	}
	else {
		DbgPrintEx(77, 0, "[FakeProcess]:Sid Err\r\n");
		return;

	}

	ObDereferenceObject(token);
	ObDereferenceObject(csrsstoken);

}
#pragma warning(disable : 4701)
void FakeProcess::fn_set_process_new_peb64()
{

	PMPEB64 CsrssPeb = (PMPEB64)PsGetProcessPeb(CsrssProcess);
	PMPEB64 Peb = (PMPEB64)PsGetProcessPeb(Process);
	KAPC_STATE Apc{0};
	MPEB64 CsrssPebSaved;
	UNICODE_STRING ImagePathName, CommandLine;


	KeStackAttachProcess(CsrssProcess, &Apc);

	if (MmIsAddressValid(CsrssPeb)) {

		memcpy(&CsrssPebSaved, CsrssPeb, sizeof(MPEB64));
	}


	//需要修改 
	//CsrssPeb->ProcessParameters->ImagePathName;
	//CsrssPeb->ProcessParameters->CommandLine;
	//CsrssPeb->ProcessParameters->WindowTitle;
	//先附加到Csrss.exe,保存ImagePath那些参数
	if (CsrssPeb->ProcessParameters->ImagePathName.Length) {

		ImagePathName.Buffer = (PWCH)ExAllocatePool(NonPagedPool, CsrssPeb->ProcessParameters->ImagePathName.MaximumLength);
		
		memcpy(ImagePathName.Buffer, CsrssPeb->ProcessParameters->ImagePathName.Buffer, CsrssPeb->ProcessParameters->ImagePathName.MaximumLength);
	
		ImagePathName.MaximumLength = CsrssPeb->ProcessParameters->ImagePathName.MaximumLength;
		ImagePathName.Length = CsrssPeb->ProcessParameters->ImagePathName.Length;
	}
	if (CsrssPeb->ProcessParameters->CommandLine.Length) {

		CommandLine.Buffer = (PWCH)ExAllocatePool(NonPagedPool, CsrssPeb->ProcessParameters->CommandLine.MaximumLength);

		memcpy(CommandLine.Buffer, CsrssPeb->ProcessParameters->CommandLine.Buffer, CsrssPeb->ProcessParameters->CommandLine.MaximumLength);

		CommandLine.MaximumLength = CsrssPeb->ProcessParameters->CommandLine.MaximumLength;
		CommandLine.Length = CsrssPeb->ProcessParameters->CommandLine.Length;
	}
	
	KeUnstackDetachProcess(&Apc);


	//再附加要伪装的进程
	KeStackAttachProcess(Process, &Apc);

	//先申请一块内存,用于替换那三个值
	PVOID pAllocBase = 0;
	SIZE_T size = PAGE_SIZE*2;

	

	NTSTATUS status=ZwAllocateVirtualMemory(NtCurrentProcess(), &pAllocBase, 0, &size, MEM_COMMIT, PAGE_READWRITE);
	
	if (!NT_SUCCESS(status)) {

		DbgPrintEx(77, 0, "[FakeProcess]:unable to alloc mem\r\n");
		return;

	}

	UINT64 Temp = (UINT64)pAllocBase;

	memset(pAllocBase, 0, PAGE_SIZE);

	//开始复制
	if (ImagePathName.Length) {

		memcpy((PVOID)Temp, ImagePathName.Buffer, ImagePathName.MaximumLength);

		Peb->ProcessParameters->ImagePathName.Buffer = (PWCH)Temp;

		Peb->ProcessParameters->ImagePathName.Length = ImagePathName.Length;

		Peb->ProcessParameters->ImagePathName.MaximumLength = ImagePathName.MaximumLength;

		Temp += ImagePathName.MaximumLength;
	}

	if (CommandLine.Length) {

		memcpy((PVOID)Temp, CommandLine.Buffer, CommandLine.MaximumLength);


		Peb->ProcessParameters->CommandLine.Buffer = (PWCH)Temp;

		Peb->ProcessParameters->CommandLine.Length = CommandLine.Length;

		Peb->ProcessParameters->CommandLine.MaximumLength = CommandLine.MaximumLength;

		Temp += CommandLine.MaximumLength;
	}


	memset(Peb->ProcessParameters->WindowTitle.Buffer,0, Peb->ProcessParameters->WindowTitle.MaximumLength);


	KeUnstackDetachProcess(&Apc);

	if(ImagePathName.Length) ExFreePool(ImagePathName.Buffer);
	if(CommandLine.Length) ExFreePool(CommandLine.Buffer);

}

void FakeProcess::fn_set_process_new_module64()
{
	//修改PEB的Module

	PMPEB64 Peb = (PMPEB64)PsGetProcessPeb(Process);

	PMPEB64 CsrssPeb = (PMPEB64)PsGetProcessPeb(CsrssProcess);

	if (!Peb || !CsrssPeb) return;


	KAPC_STATE Apc{0};

	UNICODE_STRING FullDllName = { 0 };
	UINT64 baseLen = 0;

	KeStackAttachProcess(CsrssProcess, &Apc);

	//链表的第一个就是本模块
	PMLDR_DATA_TABLE_ENTRY list = (PMLDR_DATA_TABLE_ENTRY)CsrssPeb->Ldr->InLoadOrderModuleList.Flink;

	if (list->FullDllName.Length) {
		FullDllName.Buffer = (PWCH)ExAllocatePool(NonPagedPool, list->FullDllName.MaximumLength);
	
		memcpy(FullDllName.Buffer, list->FullDllName.Buffer, list->FullDllName.Length);
	
		FullDllName.Length = list->FullDllName.Length;

		FullDllName.MaximumLength = list->FullDllName.MaximumLength;

		baseLen = (PUCHAR)list->BaseDllName.Buffer - (PUCHAR)list->FullDllName.Buffer;

	}

	KeUnstackDetachProcess(&Apc);

	//附加到原进程
	KeStackAttachProcess(Process, &Apc);

	PVOID pAllocBase = 0;
	SIZE_T size = PAGE_SIZE;
	PMLDR_DATA_TABLE_ENTRY fakeList = (PMLDR_DATA_TABLE_ENTRY)Peb->Ldr->InLoadOrderModuleList.Flink;

	NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pAllocBase, 0, &size, MEM_COMMIT, PAGE_READWRITE);

	if (!NT_SUCCESS(status)) {

		DbgPrintEx(77, 0, "[FakeProcess]:unable to alloc mem\r\n");

		return;

	}


	memcpy(pAllocBase, FullDllName.Buffer, FullDllName.Length);
	
	fakeList->FullDllName.Buffer = (PWCH)pAllocBase;
	fakeList->FullDllName.Length = FullDllName.Length;
	fakeList->FullDllName.MaximumLength = (USHORT)(baseLen+2);

	KeUnstackDetachProcess(&Apc);

	if (FullDllName.Length) ExFreePool(FullDllName.Buffer);
}