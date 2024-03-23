#include "pcap_handler.h"

PcapHandler::PcapHandler() {}

PcapHandler::~PcapHandler() {}

unordered_map<ThreadKey, Thread, ThreadKeyHash> PcapHandler::thread;

void PcapHandler::packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    try {
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
    catch (const exception& e) {
        cerr << "Packet handling error: " << e.what() << endl;
    }
}

void PcapHandler::process_file(const char* pcap_filename, const char* csv_filename, const char* max_packets) {
    try {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_offline(pcap_filename, errbuf);

        if (handle == nullptr) {
            throw runtime_error(string("Couldn't open file: ") + errbuf);
        }

        process_packets_internal(handle, csv_filename, max_packets);
        pcap_close(handle);
    }
    catch (const exception& e) {
        cerr << "File processing error: " << e.what() << endl;
    }
}
void PcapHandler::process_interface(const char* dev, const char* csv_filename, const char* max_packets) {
    try {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

        if (handle == nullptr) {
            throw runtime_error(string("Couldn't open interface: ") + errbuf);
        }

        process_packets_internal(handle, csv_filename, max_packets);
        pcap_close(handle);
    }
    catch (const exception& e) {
        cerr << "Interface processing error: " << e.what() << endl;
    }
}

void PcapHandler::process_packets(const char* source, const char* csv_filename, const char* max_packets) {
    try {
        if (source_is_file(source)) {
            process_file(source, csv_filename, max_packets);
        }
        else if (source_is_interface(source)) {
            process_interface(source, csv_filename, max_packets);
        }
        else {
            throw invalid_argument("Invalid source specified: " + string(source));
        }
    }
    catch (const exception& e) {
        cerr << "Packet processing error: " << e.what() << endl;
    }
}

// The opening of the file and extraction of packets from it occur here.
void PcapHandler::process_packets_internal(pcap_t* handle, const char* csv_filename, const char* max_packets) {
    try {
        const char* filter_exp = "ip and (tcp or udp)";
        struct bpf_program fp;

        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            throw runtime_error(string("Couldn't parse filter ") + filter_exp + ": " + pcap_geterr(handle));
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            throw runtime_error(string("Couldn't install filter ") + filter_exp + ": " + pcap_geterr(handle));
        }

        int cnt_of_packets = stoi(max_packets);
        pcap_loop(handle, cnt_of_packets, packet_handler, nullptr);

        pcap_freecode(&fp);

        write_to_csv(thread, csv_filename);
    }
    catch (const exception& e) {
        cerr << "Internal packet processing error: " << e.what() << endl;
    }
}

bool PcapHandler::source_is_file(const char* file_name) {
    return (strstr(file_name, ".pcap") != nullptr);
}

bool PcapHandler::source_is_interface(const char* dev) {
    return (strstr(dev, ".") == nullptr && strstr(dev, "/") == nullptr);
}

// The writing to the file takes plase in the format <Source IP> <Destination IP> <Source Port> <Destination Port> <Packet Count> <Total Bytes>
void PcapHandler::write_to_csv(const unordered_map<ThreadKey, Thread, ThreadKeyHash>& threads, const string& filename) {
    try {
        ofstream csv_file (filename);

        if (!csv_file.is_open()) {
            throw runtime_error("CSV file is not creating");
        }

        csv_file << "Source IP,Destination IP,Source Port,Destination Port,Packet Count,Total Bytes" << endl;

        for (const auto& entry : threads) {
            const ThreadKey& key = entry.first;
            const Thread& thread = entry.second;
            csv_file << key.to_string() << "," << thread.statistics.packet_count << "," << thread.statistics.total_bytes << endl;
        }

        csv_file.close();
    }
    catch (const exception& e) {
        cerr << "CSV writing error: " << e.what() << endl;
    }
}