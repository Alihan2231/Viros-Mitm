#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ARP Spoofing Tespit Aracı
Bu araç, ağda olası ARP spoofing saldırılarını tespit etmek için bir arayüz sunar.
"""

import tkinter as tk
import arp_gui

if __name__ == "__main__":
    root = tk.Tk()
    app = arp_gui.ARP_GUI(root)
    root.mainloop()
