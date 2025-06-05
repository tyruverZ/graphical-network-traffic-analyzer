This program is a graphical network traffic analyzer that allows the user to monitor and analyze network packets passing through the computer in real time.

**What the program can do:**

1. Capture network packets  
   The program starts a process to listen to the network interface and automatically intercepts all passing packets. This allows analyzing the data being transmitted over the network.

2. Display a list of packets  
   All captured packets are displayed in a convenient table with basic parameters:  
   - Packet number in the sequence  
   - Capture time  
   - Source IP or MAC address  
   - Destination IP or MAC address  
   - Protocol (e.g., TCP, UDP, ICMP)  
   - Packet size in bytes  

3. View detailed packet information  
   When selecting any packet from the list, the program displays its full structure and content in a separate text window. This helps understand what is being transmitted within each packet.

4. Control the capture process  
   The user can:  
   - Start traffic capture with the "Start" button  
   - Stop the capture with the "Stop" button  
   - Clear the list of already captured packets with the "Clear" button  

5. Customize the appearance  
   The interface supports switching between light and dark themes, improving usability in different lighting conditions.

6. Intuitive and responsive interface  
   The application is built using Tkinter with modern controls (tables, buttons, scrollable text fields). Packet capture is performed in a separate thread, ensuring the interface is not blocked and runs smoothly.

---

**What is it for?**

- Network traffic analysis is useful for system administrators and security specialists to monitor the data being transmitted over the network.  
- Education and research — students and developers can use the program to understand how network protocols work and study the structure of packets.  
- Debugging network applications — developers can see how their programs exchange data over the network.

---

**Brief technical implementation details**

- The Scapy library is used for low-level packet capture and parsing.  
- The graphical interface is built using Tkinter with widgets from ttk and a scrollable text window.  
- Thread-based operations ensure simultaneous packet capture and user interaction.  
- The program is neatly designed, supports themes, and is user-friendly.

---

Thus, this program is a simple and intuitive tool for monitoring and analyzing network traffic with a convenient user interface and basic functionality for working with packets.
