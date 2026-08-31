import re
from collections import Counter
from pathlib import Path


SUSPICIOUS_THRESHOLD = 3


def run_full_analyzer(file_path):
    path_obj = Path(file_path)
    if not path_obj.is_file():
        print(f"\033[91m[-] Error: File not found at '{file_path}'\033[0m")
        return


    LOG_REGEX = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
    r"\[(?P<level>[A-Za-z]+)\]\s+"
    r"(?P<message>.*)$"
    )

    IP_REGEX = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    level_counter = Counter()
    error_messages = Counter()
    ip_error_tracker = Counter()

    print(f"\033[93m[~] Analyzing target log stream:\033[0m {file_path}...\n")

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            for line in file:
                match = LOG_REGEX.match(line.rstrip())
                if match:
                    data = match.groupdict()
                    level = data["level"]
                    msg = data["message"]

                    level_counter[level] += 1

                    ip_match = IP_REGEX.search(msg)
                    ip_address = ip_match.group(0) if ip_match else None

                    if level in ("ERROR", "CRITICAL","INFO","WARNING"):
                        clean_error_msg = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<IP>", msg)
                        error_messages[clean_error_msg] += 1

                        if ip_address:
                            ip_error_tracker[ip_address] += 1
    except (OSError, IOError) as e:
        print(f"\033[91m[-] Error reading file: {e}\033[0m")
        return

    
    print("\033[92m" + "─" * 50)
    print(" 📊 METRICS & SECURITY INTELLIGENCE REPORT")
    print("─" * 50 + "\033[0m")

    # Part A: Log Level Occurrences
    print("\033[93m[+] LOG LEVEL BREAKDOWN:\033[0m")
    if level_counter:
        for lvl, count in sorted(level_counter.items(), key=lambda x: x[1], reverse=True):
            print(f"   └── {lvl:<12} : {count} times")
    else:
        print("   └── No matching log lines found.")

    print("\n\033[91m[+] TOP 10 MOST COMMON APPLICATION ERRORS:\033[0m")
    if error_messages:
        for rank, (err, count) in enumerate(error_messages.most_common(10), 1):
            print(f"   {rank:2d}. [Count: {count}] {err}")
    else:
        print("   └── No application errors recorded.")

  
    print("\n\033[96m[+] SECURITY ALERTS / SUSPICIOUS IP DETECTION:\033[0m")
    flagged_threats = False
    for ip, err_count in ip_error_tracker.items():
        if err_count >= SUSPICIOUS_THRESHOLD:
            print(
                f"   ⚠️  ALERT: IP \033[1m{ip:<15}\033[0m triggered "
                f"\033[91m{err_count}\033[0m error logs! (Threshold: {SUSPICIOUS_THRESHOLD})"
            )
            flagged_threats = True

    if not flagged_threats:
        print("   └── No IP addresses exceeded the security threshold.")


if __name__ == "__main__":
    print("=" * 35)
    print("       📊  LOG ANALYZER  📊       ")
    print("=" * 35)

    user_input = input("Pls Enter a valid file path: ")
    clean_path = user_input.strip().strip('"').strip("'")
    output = Path(clean_path)

    run_full_analyzer(output)
