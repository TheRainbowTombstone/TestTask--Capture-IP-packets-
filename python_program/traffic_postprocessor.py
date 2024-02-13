import pandas as pd
import argparse

# Function to calculate statistics for a given IP address
def get_stats_for_ip(ip, df):
    # Filter data based on source or destination IP
    filtered_data = df[(df['Source IP'] == ip) | (df['Destination IP'] == ip)]

    # Calculate transmitted and received packets and bytes
    transmitted_packets = filtered_data[filtered_data['Source IP'] == ip]['Packet Count'].sum()
    received_packets = filtered_data[filtered_data['Destination IP'] == ip]['Packet Count'].sum()
    transmitted_bytes = filtered_data[filtered_data['Source IP'] == ip]['Total Bytes'].sum()
    received_bytes = filtered_data[filtered_data['Destination IP'] == ip]['Total Bytes'].sum()

    # Return a dictionary with IP statistics
    return {
        'IP Address': ip,
        'Received Packets': received_packets,
        'Received Bytes': received_bytes,
        'Send Packets': transmitted_packets,
        'Send Bytes': transmitted_bytes
    }

def main():
    # Set up command-line argument parser
    parser = argparse.ArgumentParser(description='Process CSV file and generate IP statistics.')
    
    # Define input and output file paths as command-line arguments
    parser.add_argument('input_file', default='../cpp_programm/csv_files/csv.csv', help='Path to the input CSV file')
    parser.add_argument('output_file', default='../csv.csv', help='Path to the output CSV file')

    # Parse command-line arguments
    args = parser.parse_args()

    # Get input and output file paths from command-line arguments
    input_filename = args.input_file
    output_filename = args.output_file

    # Read CSV file into a pandas DataFrame
    df = pd.read_csv(input_filename, sep=',')

    # Get unique IP addresses from both 'Source IP' and 'Destination IP' columns
    unique_ips = list(set(df['Source IP'].unique()) | set(df['Destination IP'].unique()))

    # Calculate statistics for each unique IP address
    stats_list = [get_stats_for_ip(ip, df) for ip in unique_ips]

    output_df = pd.DataFrame(stats_list)

    output_df.to_csv(output_filename, index=False)

if __name__ == "__main__":
    main()