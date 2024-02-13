#include "pcap_handle.h"

PacketPcapProcessor::PacketPcapProcessor() {}
PacketPcapProcessor::~PacketPcapProcessor() {}

FilePcapHandler::FilePcapHandler() {}
FilePcapHandler::~FilePcapHandler() {}

InterfacePcapHandler::InterfacePcapHandler() {}
InterfacePcapHandler::~InterfacePcapHandler() {}


CsvPcapHandler::CsvPcapHandler() {}
CsvPcapHandler::~CsvPcapHandler() {}

unordered_map<ThreadKey, Thread, ThreadKeyHash> PacketPcapProcessor::thread;

void PacketPcapProcessor::packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    const struct sniff_ethernet* ethernet;
    const struct sniff_ip* ip;
    const struct sniff_tcp* tcp;
    const struct sniff_udp* udp;

    // Variables will contain information about the protocols
    int size_ip;
    int size_tcp;
    int size_udp;
    int size_payload;

    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;

    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = sizeof(struct sniff_ip);

    // Assignment of values 
    if (ip->ip_p == IPPROTO_TCP) {
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = sizeof(struct sniff_tcp);

        // Functions are used to convert numbers from network byte order to host byte order 
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
        src_ip = ntohl(ip->ip_src.s_addr);
        dest_ip = ntohl(ip->ip_dst.s_addr);
        src_port = ntohs(tcp->th_sport);
        dest_port = ntohs(tcp->th_dport);
    }
    else if (ip->ip_p == IPPROTO_UDP) {
        udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
        size_udp = sizeof(struct sniff_udp);

        size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
        src_ip = ntohl(ip->ip_src.s_addr);
        dest_ip = ntohl(ip->ip_dst.s_addr);
        src_port = ntohs(udp->uh_sport);
        dest_port = ntohs(udp->uh_dport);
    }

    ThreadKey key = { src_ip, dest_ip, src_port, dest_port };

    // Checking for the existence of a thread with a given key (IPs, ports)
    auto it = thread.find(key);
    if (it == thread.end()) {
        Thread new_thread;
        new_thread.packets.push_back(packet);
        new_thread.statistics.packet_count = 1;
        new_thread.statistics.total_bytes = size_payload;

        thread[key] = new_thread;
    }
    else {
        it->second.packets.push_back(packet);
        it->second.statistics.packet_count++;
        it->second.statistics.total_bytes += size_payload;
    }
}

// The opening of the file and extraction of packets from it occur here.
void PacketPcapProcessor::packet_capture(pcap_t* handle, const char* filter_exp, int max_packets) {
    struct bpf_program fp;

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << endl;
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << endl;
        pcap_freecode(&fp);
        return;
    }

    pcap_loop(handle, max_packets, packet_handler, nullptr);

    pcap_freecode(&fp);
}

void PacketPcapProcessor::set_file_handler(IFileHandler* file_handler) { this->file_handler = file_handler; }

void PacketPcapProcessor::set_interface_handler(IInterfaceHandler* interface_handler) { this->interface_handler = interface_handler; }

unordered_map<ThreadKey, Thread, ThreadKeyHash> PacketPcapProcessor::get_threads() { return thread; }

pcap_t* FilePcapHandler::open_file(const char* pcap_filename, char* errbuf) {
    pcap_t* handle = pcap_open_offline(pcap_filename, errbuf);
    return handle;
}

void FilePcapHandler::close_file(pcap_t* handle) { pcap_close(handle); }

pcap_t* InterfacePcapHandler::open_interface(const char* dev, char* errbuf) {
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        cerr << "Couldn't open interface: " << errbuf << endl;
        const char* another_dev = pcap_lookupdev(errbuf);
        if (another_dev != nullptr) {
            cerr << "Trying default interface: " << another_dev << endl;
            handle = pcap_open_live(another_dev, BUFSIZ, 1, 1000, errbuf);
        }
        return handle;         
    }
    return handle;
}

void InterfacePcapHandler::close_interface(pcap_t* handle) { pcap_close(handle); }

// The writing to the file takes plase in the format <Source IP> <Destination IP> <Source Port> <Destination Port> <Packet Count> <Total Bytes>
void CsvPcapHandler::write_to_csv(const unordered_map<ThreadKey, Thread, ThreadKeyHash>& threads, const string& filename) {
    ofstream csv_file(filename);

    if (!csv_file.is_open()) {
        cerr << "CSV file is not creating" << endl;
        return;
    }

    csv_file << "Source IP,Destination IP,Source Port,Destination Port,Packet Count,Total Bytes" << endl;

    for (const auto& entry : threads) {
        const ThreadKey& key = entry.first;
        const Thread& thread = entry.second;
        csv_file << key.to_string() << "," << thread.statistics.packet_count << "," << thread.statistics.total_bytes << endl;
    }

    csv_file.close();
}
