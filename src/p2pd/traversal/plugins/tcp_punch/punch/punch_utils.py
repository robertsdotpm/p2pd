
import time
import socket
import struct

# --- NTP Constants ---
NTP_SERVER = "pool.ntp.org"
NTP_PORT = 123
NTP_DELTA = 2208988800 # 70-year offset between NTP epoch (1900) and Unix epoch (1970)
NTP_PACKET_SIZE = 48
MAX_NTP_RETRIES = 5
NTP_TIMEOUT = 1.0



def get_ntp_time(server=NTP_SERVER, port=NTP_PORT, retries=MAX_NTP_RETRIES, timeout=NTP_TIMEOUT):
    """
    Fetches the Unix timestamp from an NTP server using UDP sockets, 
    with built-in retry logic for reliability.
    """
    # NTP request message: 48 bytes, setting mode=3 (client), version=4
    # The first byte is 0b00100011 (0x23)
    request_data = b'\x23' + 47 * b'\0' 

    for attempt in range(retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                # Send the request
                s.sendto(request_data, (server, port))
                # Receive the response
                response_data, _ = s.recvfrom(NTP_PACKET_SIZE)
                
                if len(response_data) < NTP_PACKET_SIZE:
                    raise RuntimeError("NTP response too short")

                # The Transmit Timestamp is the last 8 bytes (offset 40)
                # It is a 64-bit unsigned fixed-point number (seconds + fraction)
                # We unpack the first 4 bytes (seconds part)
                ntp_time_seconds = struct.unpack('!I', response_data[40:44])[0]
                
                # Convert from NTP epoch (1900) to Unix epoch (1970)
                unix_time = ntp_time_seconds - NTP_DELTA
                
                return int(unix_time)

        except socket.timeout:
            print(f"NTP request timed out. Retrying ({attempt + 1}/{retries})...")
            time.sleep(0.1)
        except Exception as e:
            # Handle other socket errors or unpacking issues
            print(f"NTP error on attempt {attempt + 1}: {e}")
            time.sleep(0.1)

    raise RuntimeError(f"Failed to get reliable network time from {server} after {retries} attempts.")


