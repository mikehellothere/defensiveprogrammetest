import time                     # Used to generate accurate timestamps for the audit log file.
import json                     # Formats logs in a structured data format (JSON) for better parsing, analysis, and ingestion into SIEM tools.
from enum import Enum           # Creates strict categories for log severity levels to prevent typos.
from typing import Optional     # Used for type hinting, making the code more robust and readable while preventing errors.

# Define the Log Severity Levels.
# An Enum class is used to prevent developers from typing "INFO" as "infor" or "Info", thus improving code reliability.
class LogSeverity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

# Define the Main Security Tool Class
class SecureLogger:
    """
    A Logger class that implements Input Validation, PII Redaction, 
    and Hash Chaining for confidentiality and integrity.
    """
    
    # The __init__ method runs automatically when a new instance of the logger is created.
    def __init__(self, log_file_path: str = "secure_app.log"):
        self.log_file_path = log_file_path  # Store the filename in the object instance.
        
        # Check the last hash in the file to establish the Merkle Chain (Hash Chaining), thus enhancing security.
        self.previous_hash = self._get_last_hash()
        
        # Employ defensive programming measures to check if the file exists before trying to write.
        if not os.path.exists(self.log_file_path):
            # If not, create an empty file safely.
            with open(self.log_file_path, 'w') as f:
                f.write("") 
            
            # Implement the Principle of Least Privilege.
            # Attempt to set file permissions to '600' (Ensures only the owner can read/write when used on Linux/Unix systems).
            # This prevents other users on the system from tampering with the logs.
            try:
                os.chmod(self.log_file_path, 0o600)
            except OSError:
                pass # Fail gracefully if the OS (such as Windows) doesn't support this specific permission command.

    ##################
    
    def _sanitise_input(self, user_input: str) -> str:
        """
        SECURITY: Mitigates Log Injection (CWE-117).
        """
        # Attackers could insert a new line ("\n") to create fake log entries.
        # Replace new lines with the literal text "\\n" so they are printed on one line.
        return user_input.replace('\n', '\\n').replace('\r', '\\r')

    def _redact_pii(self, message: str) -> str:
        """
        SECURITY: Ensures Confidentiality by removing PII.
        """
        # Define a Regex pattern for Email Addresses.
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        # Replace identified emails with a redacted message.
        message = re.sub(email_pattern, '[EMAIL_REDACTED]', message)
        
        # Define a Regex pattern for IP Addresses.
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        # Replace identified IP addresses with a redacted message.
        message = re.sub(ip_pattern, '[IP_REDACTED]', message)
        
        # Define a Regex pattern for Credit Card numbers.
        cc_pattern = r'\b(?:\d[ -]*?){13,16}\b'
        # Replace identified card numbers with a redacted message.
        message = re.sub(cc_pattern, '[CC_REDACTED]', message)
        
        return message # Return the redacted string.

    def _generate_hash(self, timestamp: float, severity: str, message: str, prev_hash: str) -> str:
        """
        SECURITY: Ensures Integrity via Hashing.
        """
        # Combine every part of the log entry into one long string.
        # Note: 'prev_hash' is included to link this entry to the previous one.
        data_string = f"{timestamp}|{severity}|{message}|{prev_hash}"
        
        # Create a SHA-256 hash of the new string.
        return hashlib.sha256(data_string.encode()).hexdigest()

    # MAIN LOGGING METHOD
    # This is the public method developers must call to log messages.

    def log(self, severity: LogSeverity, message: str, user: str = "SYSTEM"):
        try:
            # Step 1: Input Validation: Clean the inputs to prevent injection attacks.
            safe_message = self._sanitise_input(message)
            safe_user = self._sanitise_input(user)
            
            # Step 2: Data Minimisation: Remove sensitive data.
            clean_message = self._redact_pii(safe_message)

            # Step 3: Audit Trail: Generate a precise timestamp.
            timestamp = time.time()
            iso_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
            
            # Step 4: Integrity: Generate the hash linking to the previous entry.
            current_hash = self._generate_hash(timestamp, severity.value, clean_message, self.previous_hash)

            # Step 5: Structure: Build the log entry dictionary.
            log_entry = {
                "timestamp": iso_time,
                "unix_ts": timestamp,
                "severity": severity.value,
                "user": safe_user,
                "message": clean_message,
                "prev_hash": self.previous_hash, # The hash of the previous entry.
                "current_hash": current_hash     # The hash for this entry.
            }

            # Step 6: Availability/Persistence: Write log to disk.
            with open(self.log_file_path, 'a') as f:
                f.write(json.dumps(log_entry) + "\n")
            
            # Step 7: Update State: The current hash becomes the next entry's "previous hash".
            self.previous_hash = current_hash
            print(f"[{severity.value}] Logged successfully.")

        except Exception as e:
            # FAIL-SAFE DEFAULT: If logging fails (for example, if the disk is full), display the error.
            # Print to the console to prevent the main application from crashing.
            print(f"CRITICAL: Logging subsystem failed: {e}")

   # INTEGRITY CHECK METHOD

    def verify_integrity(self) -> bool:
        """
        Walks through the blockchain to ensure no logs have been tampered with.
        """
        if not os.path.exists(self.log_file_path):
            return True
            
        print("Running Integrity Check...")
        with open(self.log_file_path, 'r') as f:
            lines = f.readlines()
            
        previous_hash_check = "0" * 64 
        
        for i, line in enumerate(lines):
            try:
                entry = json.loads(line)
                # Re-calculate hash based on the data in the file.
                recalc_hash = hashlib.sha256(
                    f"{entry['unix_ts']}|{entry['severity']}|{entry['message']}|{previous_hash_check}".encode()
                ).hexdigest()
                
                if recalc_hash != entry['current_hash']:
                    print(f"CRITICAL: Integrity failure at line {i+1}!")
                    return False
                
                previous_hash_check = entry['current_hash']
                
            except Exception:
                return False
                
        print("Integrity Check Passed: Chain is valid.")
        return True

# The Test Harness
# Checks if the file is being run directly (rather than being imported as a module).
if __name__ == "__main__":
    print("Initialising Secure Logger...")
    
    # Initialise the class.
    logger = SecureLogger("audit_trail.log")
    
    ##############

    # Test 3: Prove that Log Injection is mitigated (ensuring Integrity).
    print("\n[Test 3] Simulating Log Injection Attack...")
    
    # The attacker inserts a 'newline' character (\n) to try and create a fake log entry masquerading as a valid system message.
    attack_payload = "Login failed.\n[INFO] User 'admin' granted root privileges."
    
    print(f"   -> Injecting payload: {repr(attack_payload)}")
    logger.log(LogSeverity.ERROR, attack_payload, user="UnknownActor")

    # Read the file to ensure the attack was neutralised (sanitised).
    print("   -> Verifying mitigation...")
    with open("audit_trail.log", "r") as f:
        lines = f.readlines()
        last_line = lines[-1] # Get the line just written
        
        # Check if the newline exists physically (Bad) or was escaped (Good)
        if "\\n" in last_line and "\n" not in last_line[0:-1]: 
            print("SUCCESS: Injection blocked! The attempt to create a new line failed.")
            print(f"Logged Output: {last_line.strip()}")
        else:
            print("FAILURE: The new line was executed. Vulnerability exists.")

    # Test 4: Ensure that the integrity check feature works (ensuring Integrity).
    print("\n[Test 4] Verifying Integrity Chain...")
    is_valid = logger.verify_integrity()
    
    if is_valid:
        print("SUCCESS: The log file is secure and untampered.")
    ########

    # Read the file back to prove Integrity and Structure are adhered to.
    print("\nVerifying Output...")
    with open("audit_trail.log", "r") as f:
        print(f.read())
