#include <Winsock2.h>
#include<Windows.h>
#include<iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <string>
#include<cstring>
#include<iomanip>
#include<vector>
#include<set>

#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//��ʾ���ӵ�ʱ����ws2_32.lib
#pragma warning( disable : 4996 )//Ҫʹ�þɺ���
#define _WINSOCK_DEPRECATED_NO_WARNINGS
using namespace std;
#pragma pack(1)
struct FrameHeader_t //֡�ײ�
{
	BYTE DesMAC[6];  //Ŀ�ĵ�ַ
	BYTE SrcMAC[6];  //Դ��ַ
	WORD FrameType;  //֡����
};
struct ARPFrame_t               //ARP֡
{
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
};
#pragma pack()
void printIP(DWORD IP)
{
	BYTE* p = (BYTE*)&IP;
	for (int i = 0; i < 3; i++)
	{
		cout << dec << (int)*p << ".";
		p++;
	}
	cout << dec << (int)*p;
};
void printMAC(BYTE MAC[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (i < 5)
			printf("%02x:", MAC[i]);
		else
			printf("%02x", MAC[i]);
	}

};
void printFrameHeader(const FrameHeader_t& frameHeader) {
	std::cout << "Frame Header:" << std::endl;
	std::cout << "  Destination MAC: ";
	for (int i = 0; i < 6; ++i) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(frameHeader.DesMAC[i]);
		if (i < 5) std::cout << ":";
	}
	std::cout << std::endl;

	std::cout << "  Source MAC: ";
	for (int i = 0; i < 6; ++i) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(frameHeader.SrcMAC[i]);
		if (i < 5) std::cout << ":";
	}
	std::cout << std::endl;

	std::cout << "  Frame Type: " << std::hex << frameHeader.FrameType << std::dec << std::endl;
}

// ��� ARPFrame_t �ĺ���
void printARPFrame(const ARPFrame_t& arpFrame) {
	printFrameHeader(arpFrame.FrameHeader);

	std::cout << "ARP Frame:" << std::endl;
	std::cout << "  Hardware Type: " << std::hex << arpFrame.HardwareType << std::dec << std::endl;
	std::cout << "  Protocol Type: " << std::hex << arpFrame.ProtocolType << std::dec << std::endl;
	std::cout << "  Hardware Address Length: " << std::dec << static_cast<int>(arpFrame.HLen) << std::endl;
	std::cout << "  Protocol Address Length: " << std::dec << static_cast<int>(arpFrame.PLen) << std::endl;
	std::cout << "  Operation: " << std::hex << arpFrame.Operation << std::dec << std::endl;

	std::cout << "  Sender Hardware Address: ";
	for (int i = 0; i < 6; ++i) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(arpFrame.SendHa[i]);
		if (i < 5) std::cout << ":";
	}
	std::cout << std::endl;

	std::cout << "  Sender Protocol Address: " << std::dec << arpFrame.SendIP << std::endl;

	std::cout << "  Target Hardware Address: ";
	for (int i = 0; i < 6; ++i) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(arpFrame.RecvHa[i]);
		if (i < 5) std::cout << ":";
	}
	std::cout << std::endl;

	std::cout << "  Target Protocol Address: " << std::dec << arpFrame.RecvIP << std::endl;
}
int main() {
	pcap_if_t* alldevs;//ָ���豸�б��ײ���ָ��
	pcap_if_t* ptr;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];//������Ϣ������
	ARPFrame_t ARPFrame;
	ARPFrame_t* IPPacket;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	DWORD SendIP;
	DWORD RevIP;
	int index = 0;
	char PCAP_SRC_IF_STRING_CONS[9] = "rpcap://";
	pcap_findalldevs_ex(PCAP_SRC_IF_STRING_CONS, NULL, &alldevs, errbuf);
	for (ptr = alldevs; ptr != NULL; ptr = ptr->next)
	{
		cout << "����" << index + 1 << "\t" << ptr->name << endl;
		cout << "������Ϣ��" << ptr->description << endl;

		for (a = ptr->addresses; a != NULL; a = a->next)
		{
			if (a->addr->sa_family == AF_INET)
			{
				cout << "  IP��ַ��" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
				cout << "  �������룺" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;
			}
		}
		index++;
	}

	int num;
	cout << "��ѡҪ�򿪵������ţ�";
	cin >> num;
	ptr = alldevs;
	for (int i = 1; i < num; i++)
	{
		ptr = ptr->next;
	}

	pcap_t* pcap_handle = pcap_open(ptr->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);//������
	if (pcap_handle == NULL)
	{
		cout << "������ʱ��������" << errbuf << endl;
		return 0;
	}
	else
	{
		cout << "�ɹ��򿪸�����" << endl;
	}
	//ȷ��NPcapֻ������̫��֡����ΪARP�����ݰ�
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xFF;//����Ϊ�����㲥��ַ255.255.255.255.255.255
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;//����Ϊ�����MAC��ַ66-66-66-66-66-66-66
		ARPFrame.RecvHa[i] = 0;//����Ϊ0
		ARPFrame.SendHa[i] = 0x66;
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4; // Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����
	SendIP = ARPFrame.SendIP = htonl(0x80707070);//ԴIP��ַ����Ϊ�����IP��ַ 128.112.112.112

	//����ѡ���������IP����Ϊ�����IP��ַ
	for (a = ptr->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			cout << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
			RevIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
	}
	printARPFrame(ARPFrame);
	pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	cout << "ARP�����ͳɹ�" << endl;
	while (true)
	{
		int rtn = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
		if (rtn == -1)
		{
			cout << "  �������ݰ�ʱ��������" << errbuf << endl;
			return 0;
		}
		else
		{
			if (rtn == 0)
			{
				cout << "  û�в������ݱ�" << endl;
			}
			else
			{
				IPPacket = (ARPFrame_t*)pkt_data;
				if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)//�ж��ǲ���һ��ʼ���İ�
				{

					cout << " ���񵽻ظ������ݱ�,����IP����MAC��ַ��Ӧ��ϵ���£�" << endl;
					printIP(IPPacket->SendIP);
					cout << "	-----	";
					printMAC(IPPacket->SendHa);
					cout << endl;
					break;
				}
			}
		}
	}
	//�����緢�����ݰ�
	cout << "\n" << endl;
	cout << "�����緢��һ�����ݰ�" << endl;
	cout << "�����������IP��ַ:";
	char str[15];
	cin >> str;
	RevIP = ARPFrame.RecvIP = inet_addr(str);
	SendIP = ARPFrame.SendIP = IPPacket->SendIP;//������IP��ֵ�����ݱ���ԴIP
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i];
	}

	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "ARP������ʧ��" << endl;
	}
	else
	{
		cout << "ARP�����ͳɹ�" << endl;

		while (true)
		{
			int n = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
			if (n == -1)
			{
				cout << "  �������ݰ�ʱ��������" << errbuf << endl;
				return 0;
			}
			else
			{
				if (n == 0)
				{
					cout << "  û�в������ݱ�" << endl;
				}
				else
				{
					IPPacket = (ARPFrame_t*)pkt_data;
					if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)
					{
						cout << "  ���񵽻ظ������ݱ�,����IP����MAC��ַ��Ӧ��ϵ���£�" << endl;
						printIP(IPPacket->SendIP);
						cout << "	-----	";
						printMAC(IPPacket->SendHa);
						cout << endl;
						break;
					}
				}
			}
		}
	}

}