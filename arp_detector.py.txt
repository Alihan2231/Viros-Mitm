#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ARP Spoofing Tespit Aracı
Bu araç, ağda olası ARP spoofing saldırılarını tespit etmek için kullanılır.
"""

import subprocess
import re
import time
import platform
import sys
from collections import defaultdict
import os

def temizle_ekran():
    """İşletim sistemine göre terminal ekranını temizler."""
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def arp_tablosunu_al():
    """
    İşletim sistemine bağlı olarak ARP tablosunu alır ve döndürür.
    
    Windows, Linux ve macOS için farklı komutlar çalıştırılır.
    Eğer 'arp' komutu bulunamazsa, alternatif komutlar denenir.
    Demo modu ile örnek veriler sunulur.
    
    Returns:
        str: ARP tablosunun çıktısı
    """
    # Demo modu için basit bir argüman kontrolü
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        print("✅ Demo modu aktif! Örnek ARP tablosu kullanılıyor.")
        
        # Demo için örnek ARP tablosu (ARP saldırısı simülasyonu)
        ornek_tablo = """
192.168.1.1 dev eth0 lladdr aa:bb:cc:11:22:33 REACHABLE
192.168.1.5 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE
192.168.1.105 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE
192.168.1.23 dev eth0 lladdr cc:dd:ee:ff:00:11 REACHABLE
192.168.1.28 dev eth0 lladdr aa:bb:cc:11:22:33 REACHABLE
192.168.1.44 dev eth0 lladdr 33:44:55:66:77:88 REACHABLE
        """
        return ornek_tablo
    
    komutlar = []
    
    if platform.system() == "Windows":
        komutlar = ["arp -a"]
    else:  # Linux ve macOS
        komutlar = ["arp -a", "ip neigh", "ip neighbour"]
    
    for komut in komutlar:
        try:
            sonuc = subprocess.check_output(komut, shell=True, universal_newlines=True)
            print(f"✅ ARP tablosu '{komut}' komutu ile alındı.")
            return sonuc
        except subprocess.CalledProcessError:
            continue
        except FileNotFoundError:
            continue
    
    print("❌ ARP tablosu alınamadı. Hiçbir komut çalıştırılamadı.")
    print("📌 Bu araç için 'arp' veya 'ip neigh' komutlarından birinin yüklü olması gerekiyor.")
    print("📌 Demo modu için '--demo' parametresi ile çalıştırabilirsiniz: python arp_detector.py --demo")
    return ""

def arp_tablosunu_isle(arp_ciktisi):
    """
    ARP tablosunu işler ve MAC adreslerine göre IP'leri gruplar.
    Farklı işletim sistemleri ve komutlar için uyumlu regex'ler içerir.
    
    Args:
        arp_ciktisi (str): ARP komutunun çıktısı
    
    Returns:
        dict: MAC adreslerine göre gruplandırılmış IP'ler
    """
    mac_to_ips = defaultdict(list)
    
    # Farklı format desenlerini tanımlayalım
    desenler = [
        # Windows ARP çıktısı örnek: "192.168.1.1           aa-bb-cc-dd-ee-ff     dinamik"
        r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})",
        
        # Linux/macOS ARP çıktısı örnek: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on wlan0"
        r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2})",
        
        # ip neigh çıktısı örnek: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        r"(\d+\.\d+\.\d+\.\d+).*lladdr ([0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2})"
    ]
    
    for satir in arp_ciktisi.splitlines():
        for desen in desenler:
            eslesme = re.search(desen, satir)
            if eslesme:
                ip_adresi = eslesme.group(1)
                mac_adresi = eslesme.group(2).lower()  # MAC adreslerini küçük harfe çevir
                
                # Incomplete veya <incomplete> gibi geçersiz MAC adreslerini kontrol et
                if "incomplete" not in mac_adresi and len(mac_adresi) >= 17:
                    mac_to_ips[mac_adresi].append(ip_adresi)
                break  # Eşleşme bulundu, sonraki desene geçmeye gerek yok
    
    return mac_to_ips

def arp_spoofing_kontrol(mac_to_ips):
    """
    Aynı MAC adresine sahip birden fazla IP olup olmadığını kontrol eder.
    
    Args:
        mac_to_ips (dict): MAC adreslerine göre gruplandırılmış IP'ler
    
    Returns:
        list: Şüpheli MAC adresleri ve bunlara ait IP'ler listesi
    """
    supheli_macler = []
    
    for mac, ips in mac_to_ips.items():
        if len(ips) >= 2:
            supheli_macler.append((mac, ips))
    
    return supheli_macler

def sonuclari_yazdir(supheli_macler):
    """
    Sonuçları ekrana yazdırır.
    
    Args:
        supheli_macler (list): Şüpheli MAC adresleri ve bunlara ait IP'ler listesi
    """
    if supheli_macler:
        print("\n⚠️  ARP SPOOFING UYARISI  ⚠️")
        print("🔍 Aynı MAC adresine sahip birden fazla IP adresi tespit edildi!")
        print("\nTespit edilen şüpheli MAC adresleri:")
        print("-" * 60)
        
        for mac, ips in supheli_macler:
            print(f"🔹 MAC: {mac}")
            print(f"   Bağlı IP'ler: {', '.join(ips)}")
            print("-" * 60)
        
        print("\n⚠️  GÜVENLİK BİLGİSİ  ⚠️")
        print("📌 Bu durum, ağınızda bir ARP Spoofing saldırısı olabileceğini gösterir.")
        print("📌 ARP Spoofing, saldırganın ağdaki trafiği izlemesine olanak tanır.")
        print("📌 Saldırı sırasında şu risklere maruz kalabilirsiniz:")
        print("   - Giriş bilgileriniz çalınabilir")
        print("   - Web trafiğiniz izlenebilir")
        print("   - Ağ üzerinden iletilen verileriniz ele geçirilebilir")
        print("\n📋 Tavsiyeler:")
        print("   - Güvenilir olmayan ağlara bağlanmaktan kaçının")
        print("   - Önemli işlemlerinizi VPN kullanarak yapın")
        print("   - Ağ yöneticinizle iletişime geçin")
        print("   - HTTPS kullanan web siteleri tercih edin")
    else:
        print("\n✅ ARP Spoofing tespit edilmedi.")
        print("🔍 Ağınızda şüpheli bir aktivite görünmüyor.")
        print("📌 Yine de güvenliğiniz için düzenli kontroller yapmanızı öneririz.")

def periyodik_kontrol():
    """
    Kullanıcıdan periyodik kontrol yapılıp yapılmayacağını sorar ve gerekirse zamanlanmış kontrol başlatır.
    Demo modunda ise otomatik olarak hayır cevabı verir.
    """
    # Demo modu kontrolü
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        print("\n🔄 Demo modunda periyodik kontrol atlanıyor.")
        print("👋 Program sonlandırıldı. İyi günler!")
        return
        
    while True:
        cevap = input("\n🔄 Periyodik kontrol yapmak istiyor musunuz? (24 saatte bir) [E/h]: ").lower()
        
        if cevap == "" or cevap == "e":
            print("\n🕒 Periyodik kontrol aktifleştirildi. 24 saatte bir ARP tablosu kontrol edilecek.")
            print("ℹ️  Programı sonlandırmak için Ctrl+C tuşlarına basabilirsiniz.")
            
            try:
                while True:
                    # İlk kontrol hemen yapılır
                    arp_kontrol_et()
                    
                    # 24 saat (86400 saniye) bekle
                    print(f"\n⏱️  Bir sonraki kontrol {time.strftime('%d.%m.%Y %H:%M:%S', time.localtime(time.time() + 86400))} tarihinde yapılacak.")
                    time.sleep(86400)
                    temizle_ekran()
            except KeyboardInterrupt:
                print("\n\n👋 Program sonlandırıldı. İyi günler!")
                break
        elif cevap == "h":
            print("\n👋 Program sonlandırıldı. İyi günler!")
            break
        else:
            print("❓ Lütfen 'e' (evet) veya 'h' (hayır) olarak cevap verin.")

def arp_kontrol_et():
    """
    ARP tablosunu alıp kontrol eder ve sonuçları yazdırır.
    """
    print("\n🔍 ARP tablosu kontrol ediliyor...")
    arp_ciktisi = arp_tablosunu_al()
    
    if not arp_ciktisi:
        return
    
    print(f"✅ {len(arp_ciktisi.splitlines())} ARP kaydı bulundu.")
    
    mac_to_ips = arp_tablosunu_isle(arp_ciktisi)
    supheli_macler = arp_spoofing_kontrol(mac_to_ips)
    
    sonuclari_yazdir(supheli_macler)

def main():
    """
    Ana program akışı.
    """
    temizle_ekran()
    print("=" * 60)
    print("🛡️  ARP SPOOFING TESPİT ARACI  🛡️")
    print("=" * 60)
    print("📌 Bu araç, ağınızda olası ARP Spoofing saldırılarını tespit eder.")
    print("📌 ARP Spoofing, bir saldırganın ağ trafiğinizi izlemesine olanak tanır.")
    print("=" * 60)
    
    arp_kontrol_et()
    periyodik_kontrol()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Program sonlandırıldı. İyi günler!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Beklenmedik bir hata oluştu: {str(e)}")
        sys.exit(1)
