#pragma once
// #pragma comment(lib, "Ws2_32.lib") // For ntohs and ntohl
// #pragma comment(lib, "wpcap.lib")  // For pcap_open_offline, pcap_close, pcap_loop

#include <iostream>
#include <fstream>
#include <pcap.h>
#include <unordered_map>
#include <vector>

#define SIZE_ETHERNET 14 // Ethernet headers are always 14 bytes
#define ETHER_ADDR_LEN 6 // Ethernet addresses consist of 6 bytes

using namespace std;

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; // Destination address
    u_char ether_shost[ETHER_ADDR_LEN]; // Source address
    u_short ether_type;
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl; // Version 4
    u_char ip_tos; // Service type
    u_short ip_len; // Total length
    u_short ip_id; // Identifier
    u_short ip_off; // Offset fragment field
    u_char ip_ttl; // Lifetime
    u_char ip_p; // Protocol
    u_short ip_sum; // Check sum
    struct in_addr ip_src, ip_dst; // Source address and destination address
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport; // Source port
    u_short th_dport; // Port of destination
    tcp_seq th_seq; // Sequence number
    tcp_seq th_ack; // Confirmation number
    u_char th_offx2; // Data offset, rsvd
    u_char th_flags;
    u_short th_win; // Window
    u_short th_sum; // Check sum
    u_short th_urp; // Emergency pointer
};

/* UDP header */
struct sniff_udp {
    u_short uh_sport; // Source port
    u_short uh_dport; // Port of destination
    u_short uh_ulen; // Header length + data
    u_short uh_sum; // Check sum
};

/* Key for unordered_map */
struct ThreadKey {
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;

    bool operator==(const ThreadKey& other) const {
        return (src_ip == other.src_ip && dest_ip == other.dest_ip &&
            src_port == other.src_port && dest_port == other.dest_port);
    }
};

/* Hash for unordered_map */
struct ThreadKeyHash {
    size_t operator()(const ThreadKey& key) const {
        return hash<uint32_t>()(key.src_ip) ^ hash<uint32_t>()(key.dest_ip) ^
            hash<uint16_t>()(key.src_port) ^ hash<uint16_t>()(key.dest_port);
    }
};

/* Stats for packs thread */
struct ThreadStatistics {
    size_t packet_count;
    size_t total_bytes;

    ThreadStatistics() : packet_count(0), total_bytes(0) {}
};


struct Thread {
    vector<const u_char*> packets;
    ThreadStatistics statistics;
};

class PcapHandler {
private:
    static void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);

    static unordered_map<ThreadKey, Thread, ThreadKeyHash> thread;

public:
    PcapHandler();
    ~PcapHandler();

    void process_packets(const char* pcap_filame, const char* csv_filename);
    void write_to_csv(const unordered_map<ThreadKey, Thread, ThreadKeyHash>& threads, const string& filename);
};