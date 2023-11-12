#include <stdio.h>
#include "pcap.h"
#include <string>
#include <vector>
#include <iostream>
#include <WinSock2.h>
using namespace std;
#pragma pack(1)	//Ϊ�˷��㸳ֵ���ýṹ����ڲ���Ա���ܰ���
#pragma comment(lib,"ws2_32.lib")
#pragma warning( disable : 4996 )
struct IpHeader
{
	BYTE VersionAndHeadlength;
	BYTE ServiceType;
	WORD TotalLength;
	WORD Identification;
	WORD FlagAndOffset;//��־λ������ԭʼ�����е�ƫ����
	BYTE TTL;//��ʶ���Ծ�����·������
	BYTE Protocol;
	WORD CheckSum;
	u_int Ip_Sorce;
	u_int Ip_Destination;
};
struct EtherFrame {
	BYTE Destination[6];
	BYTE Source[6];
	WORD type;
};
struct DataFrame {
	struct EtherFrame header;
	struct IpHeader body;
};
struct dev
{
	char* Name;
	string Descrip;
	string Addr;
	string Netmask;
	string Broadaddr;

};
vector<dev> Devices;//�������ӵ�е������豸
#pragma pack()	
void GetAllDev()
{
	pcap_if_t* alldevs;
	pcap_if_t* device;
	pcap_addr_t* a;//�����ĵ�ַ��Ϣ
	char errbuf[PCAP_ERRBUF_SIZE]; // �궨���������
	struct in_addr net_mask_address;//�洢һ��32λ�޷�������
	struct in_addr net_ip_address;

	uint32_t net_ip;
	uint32_t net_mask;

	// ��ȡ�������豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, // Interface  
		NULL,	// ������֤
		&alldevs,	// �б��ײ�
		errbuf
	) == -1)
	{
		cout << "ERROR";
		pcap_freealldevs(alldevs);
		return;
	}
	for (device = alldevs; device != NULL; device = device->next)
	{
		dev cur;
		cur.Name = device->name;
		cur.Descrip = device->description;
		pcap_lookupnet(device->name, &net_ip, &net_mask, errbuf); // ��ȡ�����Լ�IP��ַ
		net_ip_address.s_addr = net_ip;
		net_mask_address.s_addr = net_mask;

		for (a = device->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET)  // �ж���ַ�Ƿ�ΪIP��ַ
			{

				cur.Addr = inet_ntoa(net_ip_address);
				cur.Netmask = inet_ntoa(net_mask_address);
				Devices.push_back(cur);
			}
		}
	}
	pcap_freealldevs(alldevs);
}
void output()
{
	for (vector<dev>::iterator it = Devices.begin(); it != Devices.end(); it++)
	{
		cout << it->Name << endl
			<< "description:" << it->Descrip << endl
			<< "IPaddr:" << it->Addr << endl
			<< "netmask:" << it->Netmask <<endl;
		//	<< "broadaddr:" << it->broadaddr << std::endl
		//<< "dstaddr:" << it->dstaddr << std::endl;
		cout << endl;
	}
	cout << "The numbers of NIC: " << Devices.size() << endl;
}
string transIp(DWORD in)//��Ӧ��IP��ַ
{
	string ans;
	DWORD mask[] = { 0xFF000000,0x00FF0000,0x0000FF00,0x000000FF };
	DWORD num[4];

	num[0] = in & mask[0];
	num[0] = num[0] >> 24;
	num[1] = in & mask[1];
	num[1] = num[1] >> 16;
	num[2] = in & mask[2];
	num[2] = num[2] >> 8;
	num[3] = in & mask[3];

	char temp[100];
	sprintf_s(temp, "%d.%d.%d.%d", num[0], num[1], num[2], num[3]);
	ans = temp;
	return ans;
}
string transMac(BYTE* MAC)//Ŀ�ĵ�ַ��Դ��ַ
{
	string ans;
	char temp[100];
	sprintf_s(temp, "%02X-%02X-%02X-%02X-%02X-%02X", int(MAC[0]), int(MAC[1]), int(MAC[2]), int(MAC[3]), int(MAC[4]), int(MAC[5]));
	ans = temp;
	return ans;
}
void capturePacket()
{
	char errbuf[PCAP_ERRBUF_SIZE]; // �궨���������
	int nicId;
	int res;
	pcap_t* adapter; // pcap_open����ֵ
	pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	struct DataFrame* IPPacket;
	ULONG		SourceIP, DestinationIP;

	if (Devices.empty())
	{
		cout << "Can not find devices!" << endl;
		return;
	}
	output();
	cout << "Please choose the NIC:" << endl;
	while (1) {
		cin >> nicId;
		if (nicId >= Devices.size() || nicId < 0)
		{
			cout << "NIC not exsits.Choose again!" << endl;
			continue;
		}
		if ((adapter = pcap_open(Devices[nicId].Name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 3000, NULL, errbuf)) == NULL) //snaplen��ʾ���ĳ���
		{
			cout << "Open failed!" << endl;
			continue;
		}//����ģʽ
		else
		{
			std::cout << "Monitor NIC:" << endl << Devices[nicId].Name << std::endl << Devices[nicId].Descrip << std::endl;
		}
		if ((res = pcap_next_ex(adapter, &pkt_header, &pkt_data)) != 1) // �������ж˿ڶ���ʹ�ã�2��3����
		{
			if (res != 0)
				cout << "Cpature fialed��try another NIC! Error code: " << res << endl;
			else
				cout << "Out of time, try again!";
			continue;

		}

		IPPacket = (DataFrame*)pkt_data;
		SourceIP = ntohl(IPPacket->body.Ip_Sorce);
		DestinationIP = ntohl(IPPacket->body.Ip_Destination);

		cout << "Source IP: " << transIp(ntohl(SourceIP)) << endl;
		cout << "Dst IP: " << transIp(ntohl(DestinationIP)) << endl;
		std::cout << "Source MAC: " << transMac(IPPacket->header.Source) << std::endl;
		std::cout << "Dst MAC: " << transMac(IPPacket->header.Destination) << std::endl;
		printf("Checksum:%x\n", IPPacket->body.CheckSum);
		printf("ID:%x\n", IPPacket->body.Identification);
		printf("Len:%d\n", IPPacket->body.VersionAndHeadlength);
	}
}
int main()
{
	GetAllDev();
	//output();
	capturePacket();
	return 0;
}