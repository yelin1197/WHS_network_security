#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
    u_char ether_dhost[6];    // destination host address
    u_char ether_shost[6];    // source host address
    u_short ether_type;       // protocol type
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr    iph_sourceip;
    struct  in_addr    iph_destip;
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

/* MAC 주소 출력 함수 */
void print_mac(u_char *mac) {
    for(int i = 0; i < 6; i++) {
        printf("%02X", mac[i]);
        if(i != 5) printf(":");
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if(ntohs(eth->ether_type) == 0x0800) { // IP 패킷인지 확인
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if(ip->iph_protocol == IPPROTO_TCP) { // TCP 프로토콜인지 확인
            int ip_header_len = ip->iph_ihl * 4;
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

            printf("===== TCP Packet Captured =====\n");

            // Ethernet Header 정보 출력
            printf("Ethernet Header:\n");
            printf("   Src MAC: ");
            print_mac(eth->ether_shost);
            printf("\n");
            printf("   Dst MAC: ");
            print_mac(eth->ether_dhost);
            printf("\n");

            // IP Header 정보 출력
            printf("IP Header:\n");
            printf("   Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("   Dst IP: %s\n", inet_ntoa(ip->iph_destip));

            // TCP Header 정보 출력
            printf("TCP Header:\n");
            printf("   Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("   Dst Port: %d\n", ntohs(tcp->tcp_dport));

            // 메시지 출력
            printf("Message: [WHS][PCAP Programming] 19반 장예린(5103) 실습 완료!!!\n");

            printf("================================\n\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // TCP만 필터링
    bpf_u_int32 net;

    // 네트워크 디바이스 열기 (필요에 따라 "enp0s3"을 다른 NIC 이름으로 변경)
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    // 필터 설정
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // 패킷 캡처 시작
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // 핸들 닫기
    return 0;
}
