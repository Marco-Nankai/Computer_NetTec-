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
#pragma comment(lib,"ws2_32.lib")//表示链接的时侯找ws2_32.lib
#pragma warning( disable : 4996 )//要使用旧函数
#define _WINSOCK_DEPRECATED_NO_WARNINGS
using namespace std;
#pragma pack(1)
struct FrameHeader_t //帧首部
{
	BYTE DesMAC[6];  //目的地址
	BYTE SrcMAC[6];  //源地址
	WORD FrameType;  //帧类型
};
struct ARPFrame_t               //ARP帧
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

// 输出 ARPFrame_t 的函数
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
	pcap_if_t* alldevs;//指向设备列表首部的指针
	pcap_if_t* ptr;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区
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
		cout << "网卡" << index + 1 << "\t" << ptr->name << endl;
		cout << "描述信息：" << ptr->description << endl;

		for (a = ptr->addresses; a != NULL; a = a->next)
		{
			if (a->addr->sa_family == AF_INET)
			{
				cout << "  IP地址：" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
				cout << "  子网掩码：" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;
			}
		}
		index++;
	}

	int num;
	cout << "请选要打开的网卡号：";
	cin >> num;
	ptr = alldevs;
	for (int i = 1; i < num; i++)
	{
		ptr = ptr->next;
	}

	pcap_t* pcap_handle = pcap_open(ptr->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);//打开网卡
	if (pcap_handle == NULL)
	{
		cout << "打开网卡时发生错误：" << errbuf << endl;
		return 0;
	}
	else
	{
		cout << "成功打开该网卡" << endl;
	}
	//确保NPcap只捕获以太网帧类型为ARP的数据包
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xFF;//设置为本机广播地址255.255.255.255.255.255
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;//设置为虚拟的MAC地址66-66-66-66-66-66-66
		ARPFrame.RecvHa[i] = 0;//设置为0
		ARPFrame.SendHa[i] = 0x66;
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4; // 协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求
	SendIP = ARPFrame.SendIP = htonl(0x80707070);//源IP地址设置为虚拟的IP地址 128.112.112.112

	//将所选择的网卡的IP设置为请求的IP地址
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
	cout << "ARP请求发送成功" << endl;
	while (true)
	{
		int rtn = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
		if (rtn == -1)
		{
			cout << "  捕获数据包时发生错误：" << errbuf << endl;
			return 0;
		}
		else
		{
			if (rtn == 0)
			{
				cout << "  没有捕获到数据报" << endl;
			}
			else
			{
				IPPacket = (ARPFrame_t*)pkt_data;
				if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)//判断是不是一开始发的包
				{

					cout << " 捕获到回复的数据报,请求IP与其MAC地址对应关系如下：" << endl;
					printIP(IPPacket->SendIP);
					cout << "	-----	";
					printMAC(IPPacket->SendHa);
					cout << endl;
					break;
				}
			}
		}
	}
	//向网络发送数据包
	cout << "\n" << endl;
	cout << "向网络发送一个数据包" << endl;
	cout << "请输入请求的IP地址:";
	char str[15];
	cin >> str;
	RevIP = ARPFrame.RecvIP = inet_addr(str);
	SendIP = ARPFrame.SendIP = IPPacket->SendIP;//将本机IP赋值给数据报的源IP
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i];
	}

	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "ARP请求发送失败" << endl;
	}
	else
	{
		cout << "ARP请求发送成功" << endl;

		while (true)
		{
			int n = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
			if (n == -1)
			{
				cout << "  捕获数据包时发生错误：" << errbuf << endl;
				return 0;
			}
			else
			{
				if (n == 0)
				{
					cout << "  没有捕获到数据报" << endl;
				}
				else
				{
					IPPacket = (ARPFrame_t*)pkt_data;
					if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)
					{
						cout << "  捕获到回复的数据报,请求IP与其MAC地址对应关系如下：" << endl;
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