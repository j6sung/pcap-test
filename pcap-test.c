#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <stdlib.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int i = 0;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr* ethernet = (struct libnet_ethernet_hdr*)(packet);
        struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)(packet + SIZE_ETHERNET);
        struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)(packet + SIZE_ETHERNET + ip->ip_hl*4);
        
        if (ip->ip_p != IPPROTO_TCP) continue;

        printf("Src MAC: ");
        for (int i = 0; i < ETHER_ADDR_LEN; i++){
            printf("%02x", ethernet->ether_shost[i]);
            if (i == 5) break;

            printf(":");
        }
        printf("\nDst MAC: ");
        for (int i = 0; i < ETHER_ADDR_LEN; i++){
            printf("%02x", ethernet->ether_dhost[i]);
            if (i == 5) break;
            printf(":");
        }
        printf("\n");

        printf("IP Src: %s\n", inet_ntoa(ip->ip_src));
        printf("IP Dst: %s\n", inet_ntoa(ip->ip_dst));

        printf("TCP Src Port: %d\n", ntohs(tcp->th_sport));
        printf("TCP Dst Port: %d\n", ntohs(tcp->th_dport));
        u_int8_t* payload;
        payload = (u_int8_t *)(packet + SIZE_ETHERNET + ip->ip_hl*4 + tcp->th_off*4 );

        printf("Payload: ");
        for (int i =0; i < 20; i++){
            printf("0x%02x ", payload[i]);
        }
        printf("\n");


        printf("--------------------------\n");
    }

    pcap_close(pcap);
    return 0;
}

