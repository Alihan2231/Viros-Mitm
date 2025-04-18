#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ARP Spoofing Tespit Aracı - Grafik Arayüz
Bu araç, ağda olası ARP spoofing saldırılarını tespit etmek için tkinter tabanlı bir grafik arayüz sunar.
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import threading
import time
import arp_detector
import sys

class ARP_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ARP Spoofing Tespit Aracı")
        self.root.geometry("700x600")
        self.root.resizable(True, True)
        
        # Renk şeması
        self.bg_color = "#2E3440"
        self.text_color = "#ECEFF4"
        self.button_color = "#5E81AC"
        self.warning_color = "#BF616A"
        self.success_color = "#A3BE8C"
        
        # Uygulama simgesi
        try:
            self.root.iconbitmap("arp_icon.ico")
        except:
            pass  # Simge dosyası yoksa devam et
        
        # Ana çerçeveyi oluştur
        self.main_frame = tk.Frame(root, bg=self.bg_color)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Başlık ve açıklama
        title_label = tk.Label(self.main_frame, 
                              text="ARP Spoofing Tespit Aracı", 
                              font=("Arial", 18, "bold"),
                              bg=self.bg_color, 
                              fg=self.text_color)
        title_label.pack(pady=10)
        
        description_label = tk.Label(self.main_frame, 
                                    text="Bu araç, ağınızda olası ARP Spoofing saldırılarını tespit eder.\n"
                                         "ARP Spoofing, bir saldırganın ağ trafiğinizi izlemesine olanak tanır.",
                                    font=("Arial", 10),
                                    bg=self.bg_color, 
                                    fg=self.text_color, 
                                    justify="center")
        description_label.pack(pady=5)
        
        # Seçenekler çerçevesi
        options_frame = tk.Frame(self.main_frame, bg=self.bg_color)
        options_frame.pack(fill=tk.X, pady=10)
        
        # Demo modu onay kutusu
        self.demo_var = tk.BooleanVar()
        demo_check = tk.Checkbutton(options_frame, 
                                   text="Demo modu (Örnek veriler kullan)", 
                                   variable=self.demo_var,
                                   bg=self.bg_color, 
                                   fg=self.text_color,
                                   selectcolor=self.bg_color,
                                   activebackground=self.bg_color,
                                   activeforeground=self.text_color)
        demo_check.pack(side=tk.LEFT, padx=10)
        
        # Periyodik kontrol onay kutusu
        self.periodic_var = tk.BooleanVar()
        self.periodic_check = tk.Checkbutton(options_frame, 
                                          text="Periyodik kontrol (24 saatte bir)", 
                                          variable=self.periodic_var,
                                          bg=self.bg_color, 
                                          fg=self.text_color,
                                          selectcolor=self.bg_color,
                                          activebackground=self.bg_color,
                                          activeforeground=self.text_color)
        self.periodic_check.pack(side=tk.LEFT, padx=10)
        
        # Sonuçlar için metin alanı
        self.results_text = scrolledtext.ScrolledText(self.main_frame, 
                                                    wrap=tk.WORD, 
                                                    height=20,
                                                    bg="#3B4252", 
                                                    fg=self.text_color,
                                                    font=("Consolas", 10))
        self.results_text.pack(fill=tk.BOTH, expand=True, pady=10)
        self.results_text.insert(tk.END, "Program başlatıldı. ARP taraması için 'Tara' butonuna tıklayın.\n")
        self.results_text.config(state=tk.DISABLED)
        
        # İlerleme çubuğu
        self.progress = ttk.Progressbar(self.main_frame, 
                                       orient=tk.HORIZONTAL, 
                                       length=100, 
                                       mode='indeterminate')
        
        # Butonlar çerçevesi
        button_frame = tk.Frame(self.main_frame, bg=self.bg_color)
        button_frame.pack(fill=tk.X, pady=10)
        
        # Tarama butonu
        self.scan_button = tk.Button(button_frame, 
                                   text="Tara", 
                                   command=self.start_scan,
                                   bg=self.button_color, 
                                   fg=self.text_color,
                                   width=15,
                                   font=("Arial", 10, "bold"))
        self.scan_button.pack(side=tk.LEFT, padx=10)
        
        # Durdur butonu (periyodik tarama için)
        self.stop_button = tk.Button(button_frame, 
                                   text="Durdur", 
                                   command=self.stop_periodic_scan,
                                   bg=self.warning_color, 
                                   fg=self.text_color,
                                   width=15,
                                   font=("Arial", 10, "bold"),
                                   state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=10)
        
        # Çıkış butonu
        exit_button = tk.Button(button_frame, 
                              text="Çıkış", 
                              command=self.exit_program,
                              bg="#4C566A", 
                              fg=self.text_color,
                              width=15,
                              font=("Arial", 10, "bold"))
        exit_button.pack(side=tk.RIGHT, padx=10)
        
        # Periyodik tarama için durum değişkenleri
        self.periodic_running = False
        self.periodic_thread = None
        
        # Durum çubuğu
        self.status_var = tk.StringVar()
        self.status_var.set("Hazır")
        status_bar = tk.Label(self.main_frame, 
                            textvariable=self.status_var, 
                            bd=1, 
                            relief=tk.SUNKEN, 
                            anchor=tk.W,
                            bg="#4C566A", 
                            fg=self.text_color)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Kapanış sırasında periyodik taramayı düzgün şekilde sonlandır
        self.root.protocol("WM_DELETE_WINDOW", self.exit_program)
    
    def update_text(self, text, clear=False, is_warning=False, is_success=False):
        """
        Sonuç metin alanını günceller.
        
        Args:
            text (str): Eklenecek metin
            clear (bool): Mevcut metni temizleyip temizlememe
            is_warning (bool): Uyarı olarak renklendirme
            is_success (bool): Başarı olarak renklendirme
        """
        self.results_text.config(state=tk.NORMAL)
        
        if clear:
            self.results_text.delete(1.0, tk.END)
        
        # Renge göre metin ekle
        if is_warning:
            self.results_text.insert(tk.END, text, "warning")
            # Etiket tanımlanmamışsa oluştur
            if not "warning" in self.results_text.tag_names():
                self.results_text.tag_configure("warning", foreground=self.warning_color)
        elif is_success:
            self.results_text.insert(tk.END, text, "success")
            # Etiket tanımlanmamışsa oluştur
            if not "success" in self.results_text.tag_names():
                self.results_text.tag_configure("success", foreground=self.success_color)
        else:
            self.results_text.insert(tk.END, text)
        
        self.results_text.see(tk.END)  # Otomatik olarak aşağı kaydır
        self.results_text.config(state=tk.DISABLED)
    
    def capture_output(self, func, *args, **kwargs):
        """
        Bir fonksiyonun print çıktılarını yakalar ve GUI'de gösterir.
        
        Args:
            func: Çıktısı yakalanacak fonksiyon
            *args, **kwargs: Fonksiyona geçirilecek argümanlar
            
        Returns:
            Fonksiyonun geri dönüş değeri
        """
        import io
        import sys
        from contextlib import redirect_stdout
        
        f = io.StringIO()
        with redirect_stdout(f):
            result = func(*args, **kwargs)
        
        output = f.getvalue()
        
        # Okunurluğu artırmak için renklendir
        lines = output.split('\n')
        for line in lines:
            if "⚠️" in line or "❌" in line:
                self.update_text(line + "\n", is_warning=True)
            elif "✅" in line:
                self.update_text(line + "\n", is_success=True)
            elif "📌 Broadcast" in line or "📌 Multicast" in line:
                # Broadcast ve multicast bilgilerini mavi renkle göster
                self.results_text.config(state=tk.NORMAL)
                self.results_text.insert(tk.END, line + "\n", "info")
                if not "info" in self.results_text.tag_names():
                    self.results_text.tag_configure("info", foreground="#88C0D0")
                self.results_text.see(tk.END)
                self.results_text.config(state=tk.DISABLED)
            else:
                self.update_text(line + "\n")
        
        return result
    
    def start_scan(self):
        """
        ARP taramasını başlatır.
        """
        # Demo modu argümanını ayarla
        if self.demo_var.get():
            sys.argv = [sys.argv[0], "--demo"] if len(sys.argv) <= 1 else sys.argv
            if "--demo" not in sys.argv:
                sys.argv.append("--demo")
        else:
            # Demo modu kapalıysa, argüman listesinden "--demo" çıkar
            if "--demo" in sys.argv:
                sys.argv.remove("--demo")
        
        # Arayüzü hazırla
        self.status_var.set("Taranıyor...")
        self.scan_button.config(state=tk.DISABLED)
        self.progress.pack(fill=tk.X, pady=5)
        self.progress.start()
        self.update_text("=" * 60 + "\n", clear=True)
        self.update_text("🛡️  ARP SPOOFING TESPİT ARACI  🛡️\n")
        self.update_text("=" * 60 + "\n")
        self.update_text("📌 Bu araç, ağınızda olası ARP Spoofing saldırılarını tespit eder.\n")
        self.update_text("📌 ARP Spoofing, bir saldırganın ağ trafiğinizi izlemesine olanak tanır.\n")
        self.update_text("=" * 60 + "\n")
        
        # Ayrı bir iş parçacığında tarama yap
        threading.Thread(target=self._run_scan, daemon=True).start()
    
    def _run_scan(self):
        """
        ARP taramasını arka planda çalıştırır.
        """
        try:
            # ARP taramasını yap
            self.capture_output(arp_detector.arp_kontrol_et)
            
            # Periyodik tarama istendi mi?
            if self.periodic_var.get() and not self.periodic_running:
                self.start_periodic_scan()
            else:
                # İlerleme çubuğunu durdur
                self.root.after(0, self.progress.stop)
                self.root.after(0, self.progress.pack_forget)
                self.root.after(0, lambda: self.scan_button.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.status_var.set("Tarama tamamlandı"))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Hata", f"Tarama sırasında bir hata oluştu: {str(e)}"))
            self.root.after(0, self.progress.stop)
            self.root.after(0, self.progress.pack_forget)
            self.root.after(0, lambda: self.scan_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.status_var.set("Hata oluştu"))
    
    def start_periodic_scan(self):
        """
        Periyodik taramayı başlatır.
        """
        self.periodic_running = True
        self.stop_button.config(state=tk.NORMAL)
        self.scan_button.config(state=tk.DISABLED)
        self.periodic_check.config(state=tk.DISABLED)
        
        self.update_text("\n🕒 Periyodik kontrol aktifleştirildi. 24 saatte bir ARP tablosu kontrol edilecek.\n")
        self.update_text("ℹ️  Durdurmak için 'Durdur' butonuna tıklayabilirsiniz.\n")
        
        # Periyodik tarama iş parçacığını başlat
        self.periodic_thread = threading.Thread(target=self._periodic_scan_thread, daemon=True)
        self.periodic_thread.start()
    
    def _periodic_scan_thread(self):
        """
        Periyodik tarama için arka plan iş parçacığı.
        """
        # Her 24 saatte bir tarama yap (86400 saniye)
        interval_seconds = 86400
        
        # 🚩 DEV TEST: Kısa interval ile test etmek için 
        # (Yorumları kaldırarak test edebilirsiniz)
        #interval_seconds = 30  # Test için 30 saniye
        
        while self.periodic_running:
            # İlk taramayı hemen yap
            self.root.after(0, lambda: self.status_var.set("Periyodik tarama başlatılıyor..."))
            
            try:
                # Ana threadde güvenli bir şekilde UI güncelle
                self.root.after(0, lambda: self.update_text("\n" + "=" * 60 + "\n"))
                self.root.after(0, lambda: self.update_text(f"🕒 Periyodik tarama başlatılıyor - {time.strftime('%Y-%m-%d %H:%M:%S')}\n"))
                
                # Taramayı yap
                self.capture_output(arp_detector.arp_kontrol_et)
                
                # Ana threadde güvenli bir şekilde UI güncelle
                self.root.after(0, lambda: self.update_text(f"✅ Periyodik tarama tamamlandı - {time.strftime('%Y-%m-%d %H:%M:%S')}\n"))
                self.root.after(0, lambda: self.update_text(f"🕒 Bir sonraki tarama: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + interval_seconds))}\n"))
                self.root.after(0, lambda: self.update_text("=" * 60 + "\n"))
                self.root.after(0, lambda: self.status_var.set("Bir sonraki periyodik tarama bekleniyor..."))
            except Exception as e:
                # Hata durumunda güvenli bir şekilde UI güncelle
                error_message = f"❌ Periyodik tarama sırasında hata oluştu: {str(e)}\n"
                self.root.after(0, lambda msg=error_message: self.update_text(msg, is_warning=True))
            
            # 24 saat bekle veya durdurulana kadar
            for _ in range(interval_seconds):
                if not self.periodic_running:
                    break
                time.sleep(1)
    
    def stop_periodic_scan(self):
        """
        Periyodik taramayı durdurur.
        """
        if self.periodic_running:
            self.periodic_running = False
            # Thread'in sonlanmasını beklemeye gerek yok, daemon=True
            
            self.stop_button.config(state=tk.DISABLED)
            self.scan_button.config(state=tk.NORMAL)
            self.periodic_check.config(state=tk.NORMAL)
            self.periodic_var.set(False)
            
            self.update_text("\n🛑 Periyodik kontrol durduruldu.\n", is_warning=True)
            self.status_var.set("Hazır")
    
    def exit_program(self):
        """
        Programı düzgün bir şekilde kapatır.
        """
        if self.periodic_running:
            self.periodic_running = False
            # Thread'in sonlanmasını beklemeye gerek yok, daemon=True
        
        if messagebox.askokcancel("Çıkış", "Programdan çıkmak istediğinize emin misiniz?"):
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ARP_GUI(root)
    root.mainloop()
