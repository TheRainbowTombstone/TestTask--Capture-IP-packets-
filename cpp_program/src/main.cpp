#include "pcap_handler.h"

int main(int argc, char* argv[]) {

    PcapHandler pcapHandler;
    const char* max_packets = "0";

    if (argc == 3) {
        pcapHandler.process_packets(argv[1], argv[2], max_packets);
    }
    else if (argc == 4) {
        pcapHandler.process_packets(argv[1], argv[2], argv[3]);
    }
    else {
        cerr << "Usage: " << argv[0] << " <source> <output_file.csv> <max_packets>(optional)" << endl;
        return 1;
    }
    return 0;
}