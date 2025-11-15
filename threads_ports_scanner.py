import threading
import time
import socket
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

class ThreadedPortScanner:
 def __init__(self):
    self.open_ports = []
    self.lock = threading.Lock()
    pass
 def check_port(self, host, port, timeout=1):
   try:
     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     sock.settimeout(timeout)
     result = sock.connect_ex((host,port))
     if result == 0:
       return True
     else:
       return False
   except:
     return False
   finally:
     sock.close()

 def check_port_thread(self, host, port):
   is_open = self.check_port(host, port)
   if is_open:
     with self.lock:
       self.open_ports.append(port)
     print(f"the openning ports are: {port}")

 def scan_port_range(self, host, start_port = 1, end_port = 1000):
   self.open_ports = []
   ports = list(range(start_port, end_port + 1))
   print(f"the range of ports: ports {start_port} - {end_port} (sum of the ports are {len(ports)})")
   return self.scan_ports(host, ports)

 def scan_ports(self, host, ports):
   threads = []
   print(f"operating threads scanning {host}")
   for port in ports:
     thread = threading.Thread(
       target = self.check_port_thread,
       args = (host, port)
     )
     threads.append(thread)
     thread.start()
   for thread in threads:
     thread.join()
  
   return self.open_ports
 

class PortScannerGUI:
  def __init__(self, root):
    self.root = root
    self.root.title("OiOi's Port Scanner")
    self.root.geometry("700x500")
    self.scanner = ThreadedPortScanner()
    self.setup_gui()
 
  def setup_gui(self):
   main_frame = ttk.Frame(self.root, padding="10")
   main_frame.pack(fill=tk.BOTH, expand=True)
   title_label = ttk.Label(main_frame,
                            text= "OiOi's Port Scanner", 
                           font=("Arial", 16, "bold"))
   title_label.pack(pady=(0,20))
   input_frame = ttk.Frame(main_frame)
   input_frame.pack(fill=tk.X, pady=10)
   ttk.Label(input_frame, text="Target IP: ").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
   self.host_entry = ttk.Entry(input_frame, width=20)
   self.host_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
   self.host_entry.insert(0,"8.8.8.8")
   ttk.Label(input_frame, text="Port Range: ").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
   port_range_frame = ttk.Frame(input_frame)
   port_range_frame.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
   self.start_port_entry = ttk.Entry(port_range_frame, width=8)
   self.start_port_entry.pack(side=tk.LEFT)
   self.start_port_entry.insert(0,"1")
   ttk.Label(port_range_frame, text=" to ").pack(side=tk.LEFT)
   self.end_port_entry = ttk.Entry(port_range_frame, width=8)
   self.end_port_entry.pack(side=tk.LEFT)
   self.end_port_entry.insert(0, "100")
   button_frame = ttk.Frame(main_frame)
   button_frame.pack(pady=20)
   self.scan_button = ttk.Button(button_frame,
                                 text="Start Scan",
                                 command=self.start_scan)
   self.scan_button.pack(side=tk.LEFT, padx=10)
   self.stop_button = ttk.Button(button_frame,
                                 text="Stop",
                                 command=self.stop_scan,
                                 state="disabled")
   self.stop_button.pack(side=tk.LEFT, padx=10)
   self.clear_button = ttk.Button(button_frame,
                                  text="Clear",
                                  command=self.clear_results)
   self.clear_button.pack(side=tk.LEFT, padx=10)
   self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
   self.progress.pack(fill=tk.X, pady=10)
   self.status_label = ttk.Label(main_frame, text="Ready to scan....")
   self.status_label.pack(pady=5)
   results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding = "5")
   results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
   self.results_text = scrolledtext.ScrolledText(results_frame, height=15)
   self.results_text.pack(fill=tk.BOTH, expand=True)
   self.results_text.insert(tk.END, "Scan results will appear here...\n")
   self.results_text.config(state=tk.DISABLED)
  

  def start_scan(self):
    try:
      host = self.host_entry.get().strip()
      start_port = int(self.start_port_entry.get())
      end_port = int(self.end_port_entry.get())
      if not host:
        messagebox.showerror("Error", "Please enter a target IP")
        return
      self.scan_button.config(state="disabled")
      self.stop_button.config(state="normal")
      self.progress.start()
      self.status_label.config(text="Scanning...")
      self.results_text.config(state= tk.NORMAL)
      self.results_text.delete(1.0, tk.END)
      self.results_text.insert(tk.END, f"Starting scan on {host}...\n")
      self.results_text.insert(tk.END, f"Port range: {start_port}-{end_port}\n")
      self.results_text.insert(tk.END, "=" * 50 + "\n")
      self.results_text.config(state=tk.DISABLED)
      self.scan_thread = threading.Thread(
                target=self.run_scan,
                args=(host, start_port, end_port)
            )
      self.scan_thread.daemon = True
      self.scan_thread.start()
    except ValueError as e:
            messagebox.showerror("Error", "Please enter valid port numbers")
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.progress.stop()
  
  def run_scan(self, host, start_port, end_port):
  
        try:
            open_ports = self.scanner.scan_port_range(host, start_port, end_port)
            
          
            self.root.after(0, self.scan_completed, open_ports, host, start_port, end_port)
            
        except Exception as e:
            self.root.after(0, self.scan_failed, str(e))


  def scan_completed(self, open_ports, host, start_port, end_port):
        
        self.progress.stop()
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_label.config(text="Scan completed!")
        
      
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, f"\nScan completed!\n")
        self.results_text.insert(tk.END, f"Target: {host}\n")
        self.results_text.insert(tk.END, f"Ports scanned: {start_port}-{end_port}\n")
        self.results_text.insert(tk.END, f"Total ports: {end_port - start_port + 1}\n")
        self.results_text.insert(tk.END, "=" * 50 + "\n")
        
        if open_ports:
            self.results_text.insert(tk.END, f"Open ports found: {len(open_ports)}\n")
            for port in sorted(open_ports):
                self.results_text.insert(tk.END, f"Port {port} is open\n")
        else:
            self.results_text.insert(tk.END, "No open ports found\n")
        
        self.results_text.config(state=tk.DISABLED)
        self.results_text.see(tk.END)



  def scan_failed(self, error_msg):
        self.progress.stop()
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_label.config(text="Scan failed!")
        
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, f"\nScan failed: {error_msg}\n")
        self.results_text.config(state=tk.DISABLED)
        self.results_text.see(tk.END)
        
        messagebox.showerror("Scan Error", f"Scan failed: {error_msg}")
  

  def stop_scan(self):
        self.progress.stop()
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_label.config(text="Scan stopped")
        
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, "\nScan stopped by user\n")
        self.results_text.config(state=tk.DISABLED)
        self.results_text.see(tk.END)
  


  def clear_results(self):
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Scan results will appear here...\n")
        self.results_text.config(state=tk.DISABLED)
        self.status_label.config(text="Ready to scan...")
    
  
      


 
def get_user_input():
    print(f"oioi's scanning machine configuration")
    print("=" * 60)
    host = input("please enter the target IP (now is 8.8.8.8): ").strip()
    if not host:
        host = "8.8.8.8"
    start_port_input = input("please enter the start port (now is 1): ").strip()
    if start_port_input:
        start_port = int(start_port_input)
    else:
        start_port = 1
    end_port_input = input("please enter the end port (now is 100): ").strip()
    if end_port_input:
        end_port = int(end_port_input)
    else:
        end_port = 100
    return host, start_port, end_port
 
if __name__ == "__main__":
  choice = input("Choose interface: (1) GUI (2) Console [default: 1]: ").strip()
    
  if choice == "2":
        scanner = ThreadedPortScanner()
        host, start_port, end_port = get_user_input()
        print(f"\n start scanning... ")
        print(f"target: {host}")
        print(f"ports range: {start_port} - {end_port}")
        print(f"sum of the ports: {end_port - start_port + 1}")
        print("=" * 60)
        open_ports = scanner.scan_port_range(host, start_port, end_port)
        print(f"\n finished scanning")
        if open_ports:
            print(f"opening ports: {sorted(open_ports)}")
            print(f"sum of the opening ports: {len(open_ports)}")
        else:
            print("no ports are opening")
  else:
        root = tk.Tk()
        app = PortScannerGUI(root)
        root.mainloop()


