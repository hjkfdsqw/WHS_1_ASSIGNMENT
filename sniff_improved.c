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

void got_packet(정
            

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


