# Simulating-a-Local-Network-Attack
This repository showcases a controlled Wi-Fi penetration-test scenario on a home network. The demonstration walks through an attacker’s workflow: discovering the wireless network, authenticating to it, enumerating connected hosts, and ultimately performing ARP spoofing to intercept a victim’s outbound traffic (Man-in-the-Middle).

##
### 1. Setup
<img width="797" alt="Screenshot 2025-06-25 at 9 00 11 AM" src="https://github.com/user-attachments/assets/2a52d144-2b43-4d1d-b399-bc0e0df1028f" />

Legal note: All testing occurred on equipment and networks owned by me and with full permission.
Do not replicate these steps on networks you do not own or lack written consent to assess.

#
### 2. Reconnaissance

Begin the reconnaissance phase by placing your wireless adapter into monitor mode, which detaches it from any access-point association and allows it to passively capture all frames on the air. With the interface listening in this mode, launch airodump-ng to survey the radio spectrum; the utility displays every WLAN beacon it detects, listing each access point’s BSSID, signal strength, security parameters, and—crucially—the operating channel. Once the target network appears, note its BSSID and lock the capture to that specific channel so that only traffic to and from the chosen access point is collected. Keeping airodump-ng running against the locked channel lets you observe the “Stations” table, where the MAC addresses of connected clients are enumerated in real time. By specifying a dump file prefix (with the --write option), you ensure that every captured management, control, and data frame—along with any ensuing WPA/WPA2 handshakes—is recorded to disk for later analysis. This focused capture gives you both the access point’s identifiers and each client’s MAC address while continuously logging raw 802.11 traffic, providing the intelligence needed for subsequent credential attacks or man-in-the-middle positioning.

#
<img width="937" alt="Screenshot 2025-06-25 at 9 08 31 AM" src="https://github.com/user-attachments/assets/f1474ff1-0daa-45d6-8746-0ce1865f4d69" />
<img width="937" alt="Screenshot 2025-06-25 at 9 07 05 AM" src="https://github.com/user-attachments/assets/84dc8b90-324e-4b34-b8f2-c7e79933dc38" />
<img width="937" alt="Screenshot 2025-06-25 at 9 08 31 AM" src="https://github.com/user-attachments/assets/c0c2b322-50ce-43d6-bd87-f925bf68a6f7" />


  #
### 3. De-authentication Attack

In the de-authentication attack phase, the goal is to forcibly disconnect a legitimate client from its access point by exploiting the lack of authentication for management frames in the Wi-Fi protocol. Using aireplay-ng, you can craft and transmit deauthentication packets that impersonate either the access point or the client device. Once you've identified both the BSSID of the target AP and the MAC address of a connected client (from the previous reconnaissance step), you can launch the attack by specifying these addresses in the command. When executed, aireplay-ng rapidly sends a series of forged deauth frames, effectively convincing the client that it has been disconnected from the network. As a result, the client is knocked offline and typically attempts to reconnect automatically. This process not only causes a temporary denial of service but also creates an opportunity to capture the WPA/WPA2 4-way handshake if the reconnection is successful while airodump-ng is still running in the background. The captured handshake is a critical piece of encrypted data needed for password cracking in offline attacks, making deauthentication a common technique in wireless penetration testing.

#
<img width="937" alt="Screenshot 2025-06-25 at 9 12 16 AM" src="https://github.com/user-attachments/assets/81c0cc5d-21b5-4f4e-bdcd-f66ef98f5701" />

  #
### 4. Capture EAPOL Handshake

Once the targeted client is disconnected via the deauthentication attack, it will typically attempt to reconnect automatically to the trusted access point. During this reconnection process, the WPA/WPA2 4-way handshake is initiated between the client and the AP to establish a secure communication channel. This handshake is based on the EAPOL (Extensible Authentication Protocol over LAN) protocol and consists of four distinct message exchanges. If airodump-ng is still running and focused on the correct channel and BSSID, it will detect and capture this handshake in real time. The captured packets are saved in the specified .cap file and can be later examined in detail using Wireshark. In Wireshark, you can apply the filter eapol to isolate the handshake frames and ensure all four parts are present: Message 1 (AP → Client), Message 2 (Client → AP), Message 3 (AP → Client), and Message 4 (Client → AP). Capturing all four ensures the handshake is complete and suitable for offline password cracking using tools like aircrack-ng or hashcat. This step is crucial in wireless security assessments, as it provides the encrypted key exchange necessary for attempting brute-force or dictionary attacks against the network’s pre-shared key (PSK).

  #
  
<img width="946" alt="Screenshot 2025-06-25 at 9 20 02 AM" src="https://github.com/user-attachments/assets/6cd53e6c-a0cb-460f-89c4-f79ed174ab7a" />
<img width="946" alt="Screenshot 2025-06-25 at 9 21 25 AM" src="https://github.com/user-attachments/assets/f11ca181-9e40-4c76-822c-1e510cc02d64" />

 #
### 5. Hashcat Password Attack
After successfully capturing the full WPA handshake, the next step is to perform an **offline password cracking attack** using **Hashcat**, one of the fastest and most powerful GPU-accelerated password recovery tools available. First, the `.cap` file containing the handshake must be converted into a format compatible with Hashcat. This is typically done using the **`hcxpcapngtool`** or **`cap2hccapx`** utility, which extracts the essential handshake information and outputs a `.hccapx` file. Once converted, Hashcat can be launched in **mode 22000**, which is specifically designed for WPA/WPA2 handshakes. To increase the chances of a successful crack, a **dictionary attack** is used, leveraging the widely known **`rockyou.txt`** wordlist—an extensive collection of real-world leaked passwords. To further enhance the effectiveness of the wordlist, a **ruleset** called **`best64.rule`** is applied, which systematically modifies the base words (e.g., capitalizations, appending numbers, reversing strings) to simulate common password variations. Hashcat then hashes each candidate word using the captured handshake parameters and compares it to the original key exchange data. If a match is found, the cracked password is printed along with its corresponding hash, indicating a successful breach. This approach highlights the danger of weak or reused passwords in wireless networks, especially those susceptible to simple dictionary and rules-based attacks.
#
<img width="1337" alt="Screenshot 2025-06-25 at 9 25 20 AM" src="https://github.com/user-attachments/assets/9a657235-a572-46b7-85ec-3bac947019e9" />
<img width="1337" alt="Screenshot 2025-06-25 at 9 25 20 AM" src="https://github.com/user-attachments/assets/a7afc248-ca61-42da-85ab-a3d35ff53e2b" />
  
  #
### 6. Reconnaissance

With the WPA2 password successfully cracked, you can now **authenticate to the target wireless network as a legitimate client**, effectively gaining access to the internal LAN. After connecting, begin by running **`ifconfig`** (or `ip a`) to identify your assigned **local IP address** and the corresponding subnet—this provides context on the local network’s addressing scheme and helps define the scan scope. The next step is to use **`nmap`**, a powerful network scanning and enumeration tool, to **probe the network for active hosts**, open ports, running services, and potential vulnerabilities. A simple ping sweep or ARP scan (e.g., `nmap -sn 192.168.1.0/24`) reveals live systems, while more advanced service version detection (`nmap -sV`) and OS fingerprinting (`nmap -O`) help identify the nature and configuration of each device. You can also leverage scripts from the **Nmap Scripting Engine (NSE)** to detect known vulnerabilities (e.g., `nmap --script vuln`). This reconnaissance phase is essential for **mapping the internal topology**, identifying exposed services like SMB, HTTP, or SSH, and ultimately selecting a **weaker target device**—such as an unpatched printer, IoT device, or legacy Windows host—for further exploitation or man-in-the-middle attacks.

#
<img width="937" alt="Screenshot 2025-06-25 at 9 28 43 AM" src="https://github.com/user-attachments/assets/bedb01fe-58fb-42c8-beae-25865cb43b89" />

  #
### 7. Arp Poisoning, MiTM

With network access established and a target client identified, you can now initiate a **Man-in-the-Middle (MITM) attack** using **Ettercap**, a comprehensive suite for network sniffing and traffic manipulation. The goal of this phase is to **silently position your machine between the router (gateway) and the victim device**, allowing you to intercept, monitor, and even alter communications in real time. Begin by launching Ettercap in graphical or text mode (`ettercap -G` or `ettercap -T -q -i wlan0`), and set the scan range to detect hosts on the local subnet. Once both the client and gateway are identified, select them as targets—typically **Target 1 as the victim** and **Target 2 as the router**. Enable **ARP poisoning** to forge ARP replies that associate your MAC address with both IPs, tricking each party into believing your machine is the other. This deception results in **all traffic between the client and router being transparently routed through your system**, enabling passive traffic capture. By enabling **packet forwarding** on your machine (e.g., `echo 1 > /proc/sys/net/ipv4/ip_forward`), the connection remains stable, making the attack stealthy and persistent. All intercepted packets can be logged or inspected in real time using tools like **Wireshark**, revealing sensitive information such as HTTP credentials, DNS queries, or unencrypted application data—all without the victim’s awareness.

#
<img width="937" alt="Screenshot 2025-06-25 at 9 30 47 AM" src="https://github.com/user-attachments/assets/1a63fa66-e1a0-461f-8e56-206fa162638c" />

  #
### 8. Packet Analysis

After successfully executing the Man-in-the-Middle attack, the captured network traffic can be analyzed in-depth using **Wireshark**, a powerful and widely-used network protocol analyzer. Wireshark allows you to **inspect individual packets**, filter specific protocols (e.g., `http`, `ftp`, `dns`, or `tcp.port==80`), and **follow full TCP/UDP streams**, making it ideal for dissecting application-layer interactions and uncovering potential leaks of sensitive information. By loading the `.pcap` file generated during the sniffing session, you can view the exact contents of intercepted data flows, reconstruct conversations, detect anomalies, and identify unencrypted credentials or session tokens transmitted in plaintext. For those who prefer a more accessible or lightweight option, there are also several **online tools** such as *CloudShark*, *PacketTotal*, and *PCAP Analyzer* that allow you to upload `.pcap` files for browser-based exploration. These platforms provide visual summaries, host-based communication graphs, and basic threat intelligence indicators, which can simplify the process of understanding packet flows for beginners or quick assessments. Whether using Wireshark or online platforms, packet analysis is a critical final step that turns raw captured traffic into actionable insights about how data flows through the network, and what vulnerabilities or misconfigurations may have been exploited during the attack.
#
<img width="1407" alt="Screenshot 2025-06-25 at 9 33 14 AM" src="https://github.com/user-attachments/assets/073f4a68-551d-46a6-a42a-70cd3a5ae6b3" />

<img width="1407" alt="Screenshot 2025-06-25 at 9 33 41 AM" src="https://github.com/user-attachments/assets/434aedc6-ab0d-42dd-af51-40182383ff65" />

![screentshot](https://github.com/user-attachments/assets/b47103f4-b2be-4e38-a71b-27c42aff80c4)

