//////////////////////////////////////////////////////////////////////////
//Author:    0xQo
//Date:      2009-11-01  
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
//ͷ�ļ�����
//////////////////////////////////////////////////////////////////////////
#include "Header.h"
#include <vector>


//////////////////////////////////////////////////////////////////////////
//ȫ�ֱ���
//////////////////////////////////////////////////////////////////////////
HANDLE	hDevice = INVALID_HANDLE_VALUE;
BOOL	bFlag	= TRUE;
Filter	filter;
HANDLE	hEvent = NULL;
std::vector<Filter> Packets;
HWND hList;


//////////////////////////////////////////////////////////////////////////
//��������
//////////////////////////////////////////////////////////////////////////
//�����ڹ���
LRESULT CALLBACK MainDlgProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
//���ù���
LRESULT CALLBACK SetDlgProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
//��ʼ��List Control
BOOL InitListControl(HWND hListControl);
//�򿪼��
BOOL CreateMonitor();
//�رռ��
BOOL CloseMonitor();
//���ü��
BOOL SetMonitor();
//�̺߳���
void ThreadFunc();
//����һ�����ݰ���List Control
BOOL InsertPacket(Filter& p);



//////////////////////////////////////////////////////////////////////////
//������
//////////////////////////////////////////////////////////////////////////
int APIENTRY WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nShowCmd )
{
	//��ʼ��ͨ�ÿؼ���
	InitCommonControls();

	HANDLE hDevice = CreateFile(TEXT("\\\\.\\CsTracker"),GENERIC_ALL,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if (hDevice==INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL,TEXT("�޷��������豸��"),NULL,MB_OK);
		exit(0);
	}
	hEvent = CreateEvent(NULL,FALSE,FALSE,NULL);
	DWORD dwTemp;
	DeviceIoControl(hDevice,SetEvent,&hEvent,sizeof(ULONG),NULL,NULL,&dwTemp,NULL);

	CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)ThreadFunc,NULL,NULL,NULL);

	//�����ڹ���
	return DialogBox(hInstance,MAKEINTRESOURCE(IDD_DIALOG1),NULL,(DLGPROC)MainDlgProc);
}


//////////////////////////////////////////////////////////////////////////
//�����ڹ���
//////////////////////////////////////////////////////////////////////////
LRESULT CALLBACK MainDlgProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	LPNMITEMACTIVATE lpnmitem;
	LPNMHDR lpnmhdr;
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			hList = GetDlgItem(hDlg,IDC_LIST1);
			InitListControl(hList);
		}
		break;
	case WM_COMMAND:
		{
			switch(LOWORD(wParam))
			{
			case IDCSET:
				{
					DialogBox(GetModuleHandle(NULL),MAKEINTRESOURCE(IDD_DIALOG2),NULL,(DLGPROC)SetDlgProc);
					//SetMonitor();
				}
				break;
			case IDCST:
				{
					if (bFlag)
					{
						ListView_DeleteAllItems(hList);
						CreateMonitor();
					}
					else
					{
						CloseMonitor();
					}
					
					bFlag = !bFlag;
				}
				break;
			}
		}
		break;
	case WM_NOTIFY:
		{
			lpnmhdr = (LPNMHDR)lParam;
			if(lpnmhdr->hwndFrom == hList)
			{
				if(lpnmhdr->code == NM_CLICK)
				{
					lpnmitem = (LPNMITEMACTIVATE)lParam;
					UINT iSelect = ListView_GetSelectionMark(hList);
					if (iSelect>Packets.size())
					{
						break;
					}
					Filter p = Packets[iSelect];
					char* pTemp = (PCHAR)malloc(p.Length);
					memset(pTemp,0,sizeof(pTemp));

					for (unsigned int i=0;i<p.Length;i++)
					{
						//�����ַ���ָ��
						char *ptr = (PCHAR)p.pBuffer;
						//ÿ����ʾ16���ַ�
						if (i%16==0&&i!=0)
						{
							strcat(pTemp,"\r\n");
						}
						if (ptr[i]=='\0')
						{
							strcat(pTemp,"00 ");
						}
						else
						{
							char temp[10] = {0};
							sprintf(temp,"%02x ",ptr[i]);
							if (strstr(temp,"ffffff")!=NULL)
							{
								strcpy(temp,temp+6);
							}
							strcat(pTemp,temp);
						}
					}
					HWND hEdit1 = GetDlgItem(hDlg,IDC_EDIT1);
					SetWindowText(hEdit1,pTemp);
					//��ʾ�ַ�
					memset(pTemp,0,sizeof(pTemp));
					for (unsigned int i=0;i<p.Length;i++)
					{
						char *ptr = (PCHAR)p.pBuffer;
						if (i%16==0&&i!=0)
						{
							strcat(pTemp,"\r\n");
						}
						char ch = ptr[i];
						char temp[10] = {0};
						sprintf(temp,"%c",ch);
						strcat(pTemp,temp);
					}
					HWND hEdit2 = GetDlgItem(hDlg,IDC_EDIT2);
					SetWindowText(hEdit2,pTemp);
				}
			}
		}
		break;
	case WM_CLOSE:
		{
			CloseMonitor();
			EndDialog(hDlg,NULL);
		}
		break;
	}

	return FALSE;
}


//////////////////////////////////////////////////////////////////////////
//���ù���
//////////////////////////////////////////////////////////////////////////
LRESULT CALLBACK SetDlgProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	ULONG	dwTemp;
	static Filter filter;
	switch(uMsg)
	{
	case WM_COMMAND:
		{
			switch(LOWORD(wParam))
			{
			case IDOK:
				{
					filter.Pid		= GetDlgItemInt(hDlg,IDC_EDIT1,NULL,NULL);
					filter.Length	= GetDlgItemInt(hDlg,IDC_EDIT5,NULL,NULL);
					filter.Behavior = GetDlgItemInt(hDlg,IDC_EDIT5,NULL,NULL);
					filter.Port		= ntohs(u_short(GetDlgItemInt(hDlg,IDC_EDIT3,NULL,NULL)));
					SendDlgItemMessage(hDlg,IDC_IPADDRESS1,IPM_GETADDRESS,NULL,(LPARAM)(&(filter.Ip)));
					DeviceIoControl(hDlg,SetFilter,&filter,sizeof(Filter),NULL,NULL,&dwTemp,NULL);
					EndDialog(hDlg,NULL);
				}
				break;
			}
		}
		break;
	case WM_CLOSE:
		{
			EndDialog(hDlg,NULL);
		}
		break;
	default:
		break;
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////////
//��ʼ��ListControl�ؼ�
//////////////////////////////////////////////////////////////////////////
BOOL InitListControl(HWND hListControl)
{
	LVCOLUMN lvCol;
	char *szColumn[]= {"Pid", "Behavior","IP","Port","Length","Address"};
	int i, width[]= {50,100,149,50,100,100};

	ZeroMemory(&lvCol, sizeof(LVCOLUMN));

	lvCol.mask= LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH | LVCF_FMT;
	lvCol.fmt= LVCFMT_LEFT;
	ListView_SetExtendedListViewStyleEx(hListControl,0 , LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP);

	for( i=0; i<6; i++ )
	{
		lvCol.iSubItem= i;
		lvCol.cx= width[i];
		lvCol.pszText= szColumn[i];

		ListView_InsertColumn(hListControl, i, &lvCol);
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////
//�򿪼��
//////////////////////////////////////////////////////////////////////////
BOOL CreateMonitor()
{
	ULONG dwTemp = 0;
	DeviceIoControl(hDevice,StartMonitor,NULL,NULL,NULL,NULL,&dwTemp,NULL);

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////
//�رռ��
//////////////////////////////////////////////////////////////////////////
BOOL CloseMonitor()
{
	ULONG dwTemp = 0;
	DeviceIoControl(hDevice,StopMonitor,NULL,NULL,NULL,NULL,&dwTemp,NULL);

	for (int i=0;i<Packets.size();i++)
	{
		free(Packets[i].pBuffer);
	}
	Packets.clear();

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////
//���ü��
//////////////////////////////////////////////////////////////////////////
BOOL SetMonitor()
{
	ULONG dwTemp = 0;
	DeviceIoControl(hDevice,SetFilter,&filter,sizeof(Filter),NULL,NULL,&dwTemp,NULL);

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////
//�̺߳���
//////////////////////////////////////////////////////////////////////////
void ThreadFunc()
{
	while (true)
	{
		WaitForSingleObject(hEvent,INFINITE);
		Filter p;DWORD dwRet;
		ReadFile(hDevice,&p,sizeof(Filter),&dwRet,NULL);
		InsertPacket(p);
		PCHAR pTemp = (PCHAR)malloc(p.Length);
		ReadFile(hDevice,pTemp,p.Length,&dwRet,NULL);
		p.pBuffer = pTemp;
		Packets.push_back(p);
	}
}


//////////////////////////////////////////////////////////////////////////
//��һ�����ݰ���List Control
//////////////////////////////////////////////////////////////////////////
BOOL InsertPacket(Filter& p)
{
	char Buf[1024];
	LVITEM LvItem;
	LvItem.mask= LVIF_TEXT;
	LvItem.iItem= ListView_GetItemCount(hList);
	LvItem.iSubItem= 0;
	memset(Buf,0,sizeof(Buf));
	sprintf(Buf,"%d",p.Pid);
	LvItem.pszText= Buf;
	SendMessage(hList, LVM_INSERTITEM, (WPARAM)0, (LPARAM)&LvItem);
	LvItem.iSubItem = 1;
	memset(Buf,0,sizeof(Buf));
	if (p.Behavior == AFD_SENDTO)
	{
		sprintf(Buf,"%s","Sendto()");
	}
	else
	{
		sprintf(Buf,"%s","Recvfrom()");
	}
	LvItem.pszText = Buf;
	SendMessage(hList,LVM_SETITEM,(WPARAM)0,(LPARAM)&LvItem);
	LvItem.iSubItem = 2;
	memset(Buf,0,sizeof(Buf));
	sprintf(Buf,"%d",p.Ip);
	LvItem.pszText= Buf;
	SendMessage(hList,LVM_SETITEM,(WPARAM)0,(LPARAM)&LvItem);
	LvItem.iSubItem = 3;
	memset(Buf,0,sizeof(Buf));
	sprintf(Buf,"%d",ntohs(p.Port));
	LvItem.pszText= Buf;
	SendMessage(hList,LVM_SETITEM,(WPARAM)0,(LPARAM)&LvItem);
	LvItem.iSubItem = 4;
	memset(Buf,0,sizeof(Buf));
	sprintf(Buf,"%d",p.Length);
	LvItem.pszText= Buf;
	SendMessage(hList,LVM_SETITEM,(WPARAM)0,(LPARAM)&LvItem);
	LvItem.iSubItem = 5;
	memset(Buf,0,sizeof(Buf));
	sprintf(Buf,"0x%08x",p.pBuffer);
	LvItem.pszText= strupr(Buf);
	SendMessage(hList,LVM_SETITEM,(WPARAM)0,(LPARAM)&LvItem);

	return TRUE;
}