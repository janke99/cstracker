#include <stdio.h>
#include <stdlib.h>
#include <ws2tcpip.h>
#include <Windows.h>
#pragma comment(lib,"WS2_32.lib")

//IO Control Code
#define StartMonitor	CTL_CODE(FILE_DEVICE_UNKNOWN,0x811,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define StopMonitor		CTL_CODE(FILE_DEVICE_UNKNOWN,0x812,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define SetMonitor		CTL_CODE(FILE_DEVICE_UNKNOWN,0x813,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define SetPid			CTL_CODE(FILE_DEVICE_UNKNOWN,0x814,METHOD_BUFFERED,FILE_ANY_ACCESS)

//int main()
//{
//	HANDLE hDevice = CreateFile(TEXT("\\\\.\\CsTracker"),GENERIC_ALL,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
//	if (hDevice==INVALID_HANDLE_VALUE)
//	{
//		printf("CreateFile Error!\n");
//	}
//
//	ULONG dwReturn = 0;
//	ULONG dwPid = 0;
//	printf("Input the PID:");
//	scanf("%d",&dwPid);
//	DeviceIoControl(hDevice,SetPid,&dwPid,sizeof(ULONG),NULL,NULL,&dwReturn,NULL);
//	//HANDLE hEvent = CreateEvent(NULL,FALSE,FALSE,NULL);
//	//DeviceIoControl(hDevice,SetMonitor,&hEvent,sizeof(HANDLE),NULL,NULL,&dwReturn,NULL);
//	//DeviceIoControl(hDevice,StartMonitor,NULL,NULL,NULL,NULL,&dwReturn,NULL);
//	//
//	//ULONG dwLength = 0;
//	//while (TRUE)
//	//{
//	//	WaitForSingleObject(hEvent,INFINITE);
//	//	ReadFile(hDevice,&dwLength,sizeof(ULONG),&dwReturn,NULL);
//	//	if (dwLength != 0)
//	//	{
//	//		PCHAR pBuffer = (PCHAR)malloc(dwLength+1);
//	//		ReadFile(hDevice,pBuffer,dwLength,&dwReturn,NULL);
//	//		for (int i=0;i<dwLength;i++)
//	//		{
//	//			if (i%10==0)
//	//			{
//	//				printf("\n");
//	//			}
//
//	//			printf("%02x ",pBuffer[i]);
//	//		}
//	//		printf("\n");
//	//		pBuffer[dwLength] = '\0';
//	//		printf("%s",pBuffer);
//	//		free(pBuffer);
//	//	}
//	//	SetEvent(hEvent);
//	//}
//
//	return 0;
//}

int main()
{
	char temp[] = "192.168.0.125";

	ULONG dw = inet_addr(temp);

	ULONG dwa = sizeof(unsigned short);

	printf("%10x\t%d\n",dw,dwa);

	return 0;
}