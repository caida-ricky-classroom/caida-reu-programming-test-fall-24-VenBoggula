#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>  // Used this for inet_ntoa()
#include <string.h>

#define MAX_LAST_OCTET 256   
// IP last octet range is 0-255

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct iphdr *ip_header;
    int packet_count = 0;
    int last_octet_count[MAX_LAST_OCTET] = {0};  // Array to hold last octet counts

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        // Mkes sure that it is large enough to contain both Ethernet and IP headers
        if (header.len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
            fprintf(stderr, "Packet too short to contain Ethernet and IP headers. Skipping.
");
            continue;
        }
        // Extract the IP header, assuming Ethernet header first
        ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));

        // Prints the destination IP address using inet_ntoa
        struct in_addr dest_ip;
        dest_ip.s_addr = ip_header->daddr;  // Corrected daddr handling

        // Get the last octet of the destination IP address
        unsigned char *ip_bytes = (unsigned char *)&dest_ip.s_addr;
        int last_octet = ip_bytes[3];  // Last octet is the 4th byte in the address
        // Increment the count for the last octet
        last_octet_count[last_octet]++;
        printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(dest_ip));
    }
    // Print the summary of last octet occurrences
    printf("\nSummary of last octet occurrences:\n");
    for (int i = 0; i < MAX_LAST_OCTET; i++) {
        if (last_octet_count[i] > 0) {
            printf("Last octet %d: %d occurrence(s)\n", i, last_octet_count[i]);
        }
    }
    pcap_close(handle);
    return 0;
