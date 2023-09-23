//PCAP API를 사용하여 TCP Packet Header 정보를 출력하는 프로그램

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>// libpcap(PCAP API)를 사용하기 위한 헤더파일
#include <arpa/inet.h>
#include <string.h> //문자열 처리를 위한 헤더파일,메시지 관련 기능수행

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; /* destination host address */
    u_char  ether_shost[6]; /* source host address */
    //송,수신 측의 mac주소에 대한 변수가 선언, 이를 활용
    u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
    //protocol type 을 구분, 우리는 tcp 에 관한 기능 수행
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)

    //메시지의 길이는 iph_ihl,iph_len을 이용하여 구할 수 있다.

    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
//myheader.h 에서 가져온 헤더 정보이다. 
//구조체 내에 포트 변수가 선언되어 있고 , 이를 이용하여 출력가능
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
//#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    
    //우리가 사용할 구조체의 포인터 변수를 선언하고 내부의 데이터에 접근하여 원하는 
    //결과를 도출해낼 수 있다.

    struct ethheader *eth = (struct ethheader *)packet;
    //mac주소를 출력하기 위한 코드로 mac주소는 6비트로 이루어져 있어 
    //index가 0~5까지 존재한다.
    printf("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
       eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
       eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

    printf("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
       eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
       eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type,IPv4를 나타낸다
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) { // Check if it's a TCP packet
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
            
            // "->" : 참조 연산자로 구조체 포인터를 사용하여 구조체 내부의 변수에 접근하는데 사용된다.
            //따라서 원하는 정보를 얻을 수 있다.

            printf("From: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("To: %s\n", inet_ntoa(ip->iph_destip));
            //i

            printf("TCP Source Port: %d\n", ntohs(tcp->tcp_sport));
            printf("TCP Destination Port: %d\n", ntohs(tcp->tcp_dport));
            
            printf("This is Assignment!!!\n");// 이거 과제임...
            printf("Message length: %d\n", ntohs(ip->iph_len) - (ip->iph_ihl << 2));
            //문자 및 기호까지 19개, 문자열의 마지막 null까지 총 길이 20 출력
            

            /* determine protocol */
            switch(ip->iph_protocol) {
                case IPPROTO_TCP:
                    printf("Protocol: TCP\n");
                    return;
                case IPPROTO_UDP:
                    printf("   Protocol: UDP\n");
                    return;
                case IPPROTO_ICMP:
                    printf("   Protocol: ICMP\n");
                    return;
                default:
                    printf("   Protocol: others\n");
                    return;
            }
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";// 수업에서는 icmp 프로토콜을 실습하였지만 tcp로 수정
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 2;
    }

    // Step 2: Compile filter_exp into BPF pseudo-code
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // Step 3: Set the filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter: %s\n", pcap_geterr(handle));
        return 2;
    }

    // Step 4: Capture packets
    pcap_loop(handle, 100, got_packet, NULL);

    // Step 5: Close the handle
    pcap_close(handle);   // Close the handle
    return 0;
}


