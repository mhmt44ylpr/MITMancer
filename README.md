# MITMancer 🕵️‍♂️

MITMancer, Python ve Scapy kullanılarak geliştirilmiş, terminal tabanlı bir **Man-in-the-Middle (MITM)** saldırı aracıdır. Hedef cihazlar ve gateway arasında ARP poisoning yaparak veri trafiğini izleyebilir, yönlendirebilir ve analiz edebilirsiniz.

## 🚀 Özellikler

- Otomatik ARP spoofing
- Hedef ve gateway MAC adreslerinin alınması
- `iptables` ile yönlendirme ve NAT yapılandırması
- `sslstrip` desteğiyle HTTP trafiğini şifre çözmeden izleme
- Paralel terminalde listener script çalıştırma
- Renkli ve estetik terminal çıktısı (`colorama`, `rich`, `pyfiglet` desteği)

## 🧰 Gereksinimler

- Python 3.6+
- Linux ortamı (Kali önerilir)
- `xfce4-terminal`

### Python Kütüphaneleri

```bash
pip install -r requirements.txt
```

## 📂 Klasör Yapısı

```bash
.
├── mitmancer.py
├── requirements.txt
└── tools/
    ├── sslstrip/
    └── listener.py
```

## ⚙️ Kurulum

1. `sslstrip` kurun:
```bash
sudo apt update
sudo apt install sslstrip
```

2. Dosyaları yerleştirin:
```bash
mkdir -p tools/sslstrip
cp listener.py tools/
```

## ▶️ Kullanım

```bash
sudo python3 mitmancer.py -t <hedef_ip> -g <gateway_ip> -i <interface>
```

### Örnek:
```bash
sudo python3 mitmancer.py -t 192.168.1.10 -g 192.168.1.1 -i wlan0
```

## 📌 Notlar

- `sudo` ile çalıştırmalısınız.
- iptables kuralları işlem sonunda temizlenir.
- Bu araç yalnızca **eğitim amaçlıdır.**

## ⚠️ Yasal Uyarı

Yasal izin olmadan ağlara yapılan saldırılar **yasadışıdır**. Bu yazılım yalnızca **etik hacking ve siber güvenlik eğitimi** için geliştirilmiştir.
