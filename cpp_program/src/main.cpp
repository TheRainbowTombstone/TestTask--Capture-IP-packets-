#include "pcap_handler.h"

int main(int argc, char* argv[]) {
    try {
        PcapHandler pcapHandler;
        const char* max_packets = "0";

        try {
            if (argc == 3) {
                pcapHandler.process_packets(argv[1], argv[2], max_packets);
            }
            else if (argc == 4) {
                pcapHandler.process_packets(argv[1], argv[2], argv[3]);
            }
            else {
                throw invalid_argument("Usage: <source> <output_file.csv> <max_packets>(optional)");
            }
        }
        catch(const exception& e) {
            cerr << "Error: " << e.what() << endl;
            return 1;
        }
        return 0;
    }
    catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
}