#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <ctype.h>
#include <string.h>
#include <time.h>

struct ethernet_header {
    u_char dest_mac[6];
    u_char src_mac[6];
    u_short type;
};

void print_tcp_packet(const u_char *packet) {
    struct ethernet_header *eth = (struct ethernet_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethernet_header));
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethernet_header) + ip_header->ip_hl * 4);

    time_t now = time(NULL);
    struct tm *lt = localtime(&now);
    printf("\n[%04d-%02d-%02d %02d:%02d:%02d] TCP Packet Detected.\n",
           lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
           lt->tm_hour, lt->tm_min, lt->tm_sec);

    printf("[Ethernet Header]\n");
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
           eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->dest_mac[0], eth->dest_mac[1], eth->dest_mac[2],
           eth->dest_mac[3], eth->dest_mac[4], eth->dest_mac[5]);

    printf("\n[IP Header]\n");
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

    printf("\n[TCP Header]\n");
    printf("Source Port: %d\n", ntohs(tcp_header->source));
    printf("Destination Port: %d\n", ntohs(tcp_header->dest));

    const u_char *payload = packet + sizeof(struct ethernet_header) + ip_header->ip_hl * 4 + tcp_header->th_off * 4;
    int payload_length = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4 + tcp_header->th_off * 4);

    printf("\n[Message]\n");
    if (payload_length > 0) {
        // HTTP 메시지인지 확인
        if (strstr((char *)payload, "HTTP") != NULL || strstr((char *)payload, "GET") != NULL || strstr((char *)payload, "POST") != NULL) {
            printf("HTTP Message Detected:\n");
            for (int i = 0; i < payload_length && i < 200; i++) {
                printf("%c", isprint(payload[i]) ? payload[i] : '.');
            }
        } else {
            printf("No HTTP Message Detected.\n");
        }
    } else {
        printf("No payload data in this packet.\n");
    }

    printf("\n------------------------------------------------------------\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    printf("사용 가능한 네트워크 인터페이스:\n");
    int index = 0;
    for (device = alldevs; device; device = device->next) {
        printf("%d. %s\n", index++, device->name);
    }

    printf("사용할 인터페이스 번호를 선택하세요: ");
    int dev_index;
    scanf("%d", &dev_index);

    device = alldevs;
    for (int i = 0; i < dev_index; i++) {
        if (device->next) {
            device = device->next;
        } else {
            fprintf(stderr, "Invalid device index.\n");
            return 1;
        }
    }

    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }

    printf("선택된 인터페이스: %s\n", device->name);
    printf("패킷을 수신 중입니다...\n");

    struct pcap_pkthdr header;
    const u_char *packet;

    while ((packet = pcap_next(handle, &header)) != NULL) {
        struct ethernet_header *eth = (struct ethernet_header *)packet;
        if (ntohs(eth->type) == 0x0800) { // IP 패킷인지 확인
            struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethernet_header));
            if (ip_header->ip_p == IPPROTO_TCP) { // TCP 패킷인지 확인
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethernet_header) + ip_header->ip_hl * 4);
                if (ntohs(tcp_header->source) == 80 || ntohs(tcp_header->dest) == 80) { // HTTP 트래픽 필터링
                    print_tcp_packet(packet);
                }
            }
        }
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
