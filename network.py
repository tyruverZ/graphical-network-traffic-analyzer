import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import sniff, Packet

class TrafficAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("network")
        self.root.geometry('1100x600')
        self.packets = []
        self.sniffing = False

        
        self.current_theme = 'light'

        self.create_menu()
        self.setup_style()
        self.create_widgets()

    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Настройки", menu=settings_menu)
        settings_menu.add_command(label="Светлая тема", command=lambda: self.set_theme('light'))
        settings_menu.add_command(label="Тёмная тема", command=lambda: self.set_theme('dark'))

    def setup_style(self):
    
        self.style = ttk.Style(self.root)
        self.style.theme_use('clam')

     
        self.style.configure('TButton', font=('Segoe UI', 12), padding=6)
        self.style.configure('Treeview.Heading', font=('Segoe UI', 11, 'bold'))
        self.style.configure('Treeview', font=('Segoe UI', 10), rowheight=28)
        self.style.configure('Status.TLabel', font=('Segoe UI', 10), foreground='gray')
        self.style.map('TButton', background=[('active', '#4a90e2')])

        
        self.apply_theme()

    def apply_theme(self):
        if self.current_theme == 'light':
            bg_color = '#f8f8fa'
            fg_color = '#222244'
            tree_bg = 'white'
            tree_fg = 'black'
            tree_sel_bg = '#cce6ff'
            detail_bg = '#f8f8fa'
            detail_fg = '#222244'
            status_fg = 'gray'
            btn_bg_active = '#4a90e2'
        else:
          
            bg_color = '#2e2e2e'
            fg_color = '#dddddd'
            tree_bg = '#3c3f41'
            tree_fg = '#dddddd'
            tree_sel_bg = '#5a5f61'
            detail_bg = '#2e2e2e'
            detail_fg = '#dddddd'
            status_fg = '#aaaaaa'
            btn_bg_active = '#5a9bd5'

       
        self.root.configure(bg=bg_color)
        
        
        self.style.configure('Treeview',
                             background=tree_bg,
                             foreground=tree_fg,
                             fieldbackground=tree_bg,
                             highlightthickness=0,
                             bordercolor=bg_color)
        self.style.map('Treeview',
                       background=[('selected', tree_sel_bg)],
                       foreground=[('selected', 'white')])

        
        self.style.configure('Status.TLabel', foreground=status_fg, background=bg_color)

       
        self.style.map('TButton',
                       background=[('active', btn_bg_active)],
                       foreground=[('!disabled', fg_color)])

       
        if hasattr(self, 'detail_text'):
            self.detail_text.config(bg=detail_bg, fg=detail_fg, insertbackground=fg_color)

      
        if hasattr(self, 'tree'):
            self.tree.tag_configure('oddrow', background=tree_bg)
            self.tree.tag_configure('evenrow', background=tree_bg)

        
        if hasattr(self, 'status_lbl'):
            self.status_lbl.configure(background=bg_color)

    def set_theme(self, theme_name):
        if theme_name not in ('light', 'dark'):
            return
        self.current_theme = theme_name
        self.apply_theme()

    def create_widgets(self):
        
        top_frame = ttk.Frame(self.root, padding=(10, 10, 10, 0))
        top_frame.pack(fill=tk.X)

        self.start_btn = ttk.Button(top_frame, text="▶ Старт захвата", command=self.start_sniffing)
        self.start_btn.pack(side=tk.LEFT, padx=4)

        self.stop_btn = ttk.Button(top_frame, text="■ Стоп", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)

        self.clear_btn = ttk.Button(top_frame, text="🧹 Очистить", command=self.clear_packets)
        self.clear_btn.pack(side=tk.LEFT, padx=4)

        self.status_var = tk.StringVar(value="Ожидание...")
        self.status_lbl = ttk.Label(top_frame, textvariable=self.status_var, style='Status.TLabel')
        self.status_lbl.pack(side=tk.RIGHT, padx=8)

        
        main_frame = ttk.Frame(self.root, padding=(10, 5, 10, 10))
        main_frame.pack(fill=tk.BOTH, expand=True)

        
        columns = ('#', 'Время', 'Источник', 'Назначение', 'Протокол', 'Длина')
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=20)
        for col, width in zip(columns, (45, 110, 200, 200, 120, 65)):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor='center')
        self.tree.bind('<<TreeviewSelect>>', self.on_packet_select)

        tree_scroll_y = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        tree_scroll_x = ttk.Scrollbar(main_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscroll=tree_scroll_y.set, xscroll=tree_scroll_x.set)

        self.tree.grid(row=0, column=0, sticky='nsew')
        tree_scroll_y.grid(row=0, column=1, sticky='ns')
        tree_scroll_x.grid(row=1, column=0, sticky='ew')

        
        detail_frame = ttk.LabelFrame(main_frame, text=" Подробности пакета ", padding=(10, 5, 10, 5))
        detail_frame.grid(row=0, column=2, rowspan=2, sticky='nsew', padx=(15, 0))

        self.detail_text = scrolledtext.ScrolledText(
            detail_frame, width=50, height=30, font=('Consolas', 11), wrap=tk.WORD
        )
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        
        self.apply_theme()

        
        main_frame.columnconfigure(0, weight=3)
        main_frame.columnconfigure(2, weight=2)
        main_frame.rowconfigure(0, weight=1)

  

    def start_sniffing(self):
        self.sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set("Захват трафика: выполняется...")
        self.packets.clear()
        self.tree.delete(*self.tree.get_children())
        self.detail_text.delete('1.0', tk.END)
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Захват остановлен.")

    def clear_packets(self):
        self.packets.clear()
        self.tree.delete(*self.tree.get_children())
        self.detail_text.delete('1.0', tk.END)
        self.status_var.set("Очищено.")

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=False, stop_filter=lambda x: not self.sniffing)

    def process_packet(self, packet: Packet):
        info = self.extract_packet_info(packet)
        self.packets.append(packet)
        self.tree.insert('', tk.END, values=info)

    def extract_packet_info(self, packet):
        time = f"{packet.time:.2f}"
        src = packet[0].src if hasattr(packet[0], 'src') else '-'
        dst = packet[0].dst if hasattr(packet[0], 'dst') else '-'
        proto = packet.name
        length = len(packet)
        return (len(self.packets), time, src, dst, proto, length)

    def on_packet_select(self, event):
        selected = self.tree.selection()
        if selected:
            idx = int(self.tree.item(selected[0])['values'][0]) - 1
            packet = self.packets[idx]
            self.detail_text.delete('1.0', tk.END)
            self.detail_text.insert(tk.END, packet.show(dump=True))

if __name__ == '__main__':
    root = tk.Tk()
    app = TrafficAnalyzer(root)
    root.mainloop()
