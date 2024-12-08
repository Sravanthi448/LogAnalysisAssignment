import re
import csv
from collections import Counter, defaultdict

def analyze_log(file_path, threshold=10):
    try:

        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        endpoint_pattern = re.compile(r'\"[A-Z]+\s(/[\w/.\-]*)\sHTTP')
        failed_login_pattern = re.compile(r'(401|Invalid credentials|Illd cred|Invalid redes|malli redh)')


        ip_counts = Counter()
        endpoint_counts = Counter()
        failed_logins = defaultdict(int)


        with open(file_path, 'r') as file:
            for line in file:

                ips = ip_pattern.findall(line)
                if ips:
                    ip_counts.update(ips)

                endpoints = endpoint_pattern.findall(line)
                if endpoints:
                    endpoint_counts.update(endpoints)


                if failed_login_pattern.search(line):
                    if ips:
                        failed_logins[ips[0]] += 1


        most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1], default=("None", 0))


        suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}


        print("\nRequests per IP:")
        print(f"{'IP Address':<15}{'Request Count'}")
        for ip, count in ip_counts.most_common():
            print(f"{ip:<15}{count}")

        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

        print("\nSuspicious Activity Detected:")
        if suspicious_ips:
            print(f"{'IP Address':<15}{'Failed Login Attempts'}")
            for ip, count in suspicious_ips.items():
                print(f"{ip:<15}{count}")
        else:
            print("No suspicious activity detected.")


        with open("analysis_results.csv", "w", newline="") as csvfile:
            writer = csv.writer(csvfile)


            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in ip_counts.most_common():
                writer.writerow([ip, count])


            writer.writerow([])
            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])


            writer.writerow([])
            writer.writerow(["Suspicious Activity"])
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, count in suspicious_ips.items():
                writer.writerow([ip, count])

        print("\nResults saved to 'analysis_results.csv'.")

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")



log_file_path = "sample.log"
analyze_log(log_file_path)