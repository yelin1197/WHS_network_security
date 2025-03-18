#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include "myheader.h"

void print_mac(u_char *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i != 5) printf(":");
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // Ethernet Type: 0x0800 → IP
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        // Protocol: TCP (6)
        if (ip->iph_protocol == IPPROTO_TCP) {
            int ip_header_len = ip->iph_ihl * 4;

            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

            int tcp_header_len = ((tcp->tcp_offx2 & 0xF0) >> 4) * 4;

            // Message 부분 계산
            int total_ip_len = ntohs(ip->iph_len);
            int payload_offset = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_len = total_ip_len - ip_header_len - tcp_header_len;

            printf("\n--- TCP Packet ---\n");

            // Ethernet
            printf("Ethernet Src MAC: ");
            print_mac(eth->ether_shost);
            printf("\nEthernet Dst MAC: ");
            print_mac(eth->ether_dhost);
            printf("\n");

            // IP
            printf("IP Src: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("IP Dst: %s\n", inet_ntoa(ip->iph_destip));

            // TCP
            printf("TCP Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("TCP Dst Port: %d\n", ntohs(tcp->tcp_dport));

            // Message 출력 (적당히 50바이트까지 제한)
            printf("Message: ");
            const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            for (int i = 0; i < payload_len && i < 50; i++) {
                if (isprint(payload[i]))
                    printf("%c", payload[i]);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // 네트워크 인터페이스 열기
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    // 필터 설정 (TCP만 캡처)
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // 패킷 루프
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
