import sys
import re
import pandas as pd
import json

# Regex patterns for PII
PII_PATTERNS = {
    "phone": re.compile(r"\b\d{10}\b"),
    "aadhar": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
    "passport": re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d{6}\b"), 
    "upi_id": re.compile(r"\b[\w.-]+@[a-zA-Z]{2,}\b")
}

def mask_value(key, value):
    """Mask/redact sensitive fields"""
    if key in ["phone", "contact"]:
        return value[:2] + "XXXXXX" + value[-2:]
    elif key == "aadhar":
        return value[:2] + " XXXX XXXX " + value[-2:]
    elif key == "passport":
        return value[0] + "XXXXXXX"
    elif key == "upi_id":
        parts = value.split("@")
        return parts[0][:2] + "XXXX@" + parts[1]
    elif key == "email":
        return value[0:2] + "XXX@" + value.split("@")[1]
    elif key == "name":
        return " ".join([w[0] + "XXX" for w in value.split()])
    elif key == "address":
        return "[REDACTED_PII]"
    elif key in ["ip_address", "device_id"]:
        return "[REDACTED_PII]"
    return value

def detect_pii(record):
    is_pii = False
    redacted_record = {}

    try:
        data = json.loads(record)
    except:
        return record, False 

    for key, value in data.items():
        if not value or not isinstance(value, str):
            redacted_record[key] = value
            continue

        redacted_value = value

        # Regex-based detection
        for pii_type, pattern in PII_PATTERNS.items():
            if pattern.search(value):
                is_pii = True
                redacted_value = mask_value(key, value)

        # Key-based detection (Name, Email, Address,)
        if key in ["name", "email", "address", "ip_address", "device_id", "contact"]:
            is_pii = True
            redacted_value = mask_value(key, value)

        redacted_record[key] = redacted_value

    return json.dumps(redacted_record), is_pii

def main(input_file):
    df = pd.read_csv(input_file)
    df.columns = df.columns.str.strip()  #to remove accidental spaces in column names

    output_rows = []

    for _, row in df.iterrows():
        record_id = row["record_id"]
        redacted_json, is_pii = detect_pii(row["Data_json"])
        output_rows.append([record_id, redacted_json, is_pii])

    out_df = pd.DataFrame(output_rows, columns=["record_id", "redacted_data_json", "is_pii"])
    out_file = "redacted_output_candidate_full_name.csv"
    out_df.to_csv(out_file, index=False)
    print(f"[+] Output written to {out_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv")
        sys.exit(1)
    main(sys.argv[1])

