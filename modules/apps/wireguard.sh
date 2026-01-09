#!/bin/bash

install_wireguard() {
    print_message "\n🛡️  WIREGUARD VPN SERVER KURULUMU" "$CYAN"
    print_message "─────────────────────────────────" "$BLUE"

    if [[ -f "/etc/wireguard/wg0.conf" ]]; then
        print_message "✅ WireGuard zaten kurulu görünüyor (/etc/wireguard/wg0.conf mevcut)." "$YELLOW"
        print_message "Yine de kurulum scriptini çalıştırmak (yeni kullanıcı eklemek/kaldırmak için) ister misiniz?" "$CYAN"
        read -p "Seçiminiz (E/h): " wg_reinstall
        if [[ ! "$wg_reinstall" =~ ^[Ee]$ ]]; then
             return
        fi
    fi

    # Angristan WireGuard Installer kullan
    print_message "📥 Kurulum scripti indiriliyor (Angristan)..." "$YELLOW"
    curl -O https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh
    chmod +x wireguard-install.sh

    print_message "⚙️  Kurulum başlıyor... (Lütfen soruları cevaplayın)" "$YELLOW"
    ./wireguard-install.sh

    # Kurulum sonrası optimizasyonlar
    if [[ -f "/etc/wireguard/wg0.conf" ]]; then
        print_message "\n🚀 WIREGUARD OPTİMİZASYONLARI" "$PURPLE"
        print_message "─────────────────────────────" "$PURPLE"
        
        echo ""
        print_message "Performans Optimizasyonu İçin Donanım Seçin:" "$CYAN"
        echo "1) ☁️  Standart VPS / x86 Sunucu (DigitalOcean, AWS, vb.)"
        echo "2) 🍓 Raspberry Pi 4/5 veya ARM Kartlar"
        echo "3) ⏭️  Atla (Optimizasyon yapma)"
        echo ""
        read -p "Seçiminiz: " hardware_choice

        # 1. IP Forwarding (Kernel seviyesinde zaten script yapmış olabilir ama garantiye alalım)
        echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.d/99-wireguard-opt.conf > /dev/null
        echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee -a /etc/sysctl.d/99-wireguard-opt.conf > /dev/null

        # 2. Sysctl Optimizasyonları (Hardware Bazlı)
        case $hardware_choice in
            1|2)
                print_message "🛠️  Genel optimizasyonlar uygulanıyor (BBR, UDP Buffer)..." "$YELLOW"
                cat <<EOF | sudo tee -a /etc/sysctl.d/99-wireguard-opt.conf > /dev/null
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
EOF
                # Sysctl uygula (Hata verirse devam et - Fail-safe)
                sudo sysctl -p /etc/sysctl.d/99-wireguard-opt.conf >> "$LOG_FILE" 2>&1 || print_message "⚠️  Uyarı: BBR/Buffer ayarları uygulanamadı." "$YELLOW"
                
                # Raspberry Pi Özel (UDP GRO)
                if [[ "$hardware_choice" == "2" ]]; then
                    if command -v ethtool &> /dev/null; then
                        NET_IFACE=$(ip route sh | grep default | awk '{print $5}')
                        print_message "Rx-UDP-GRO aktif ediliyor ($NET_IFACE)..." "$YELLOW"
                        sudo ethtool -K "$NET_IFACE" rx-udp-gro-forwarding on >> "$LOG_FILE" 2>&1 || true
                        
                        # Kalıcılık (rc.local)
                        if [[ ! -f /etc/rc.local ]]; then
                             echo '#!/bin/bash' | sudo tee /etc/rc.local > /dev/null
                             echo 'exit 0' | sudo tee -a /etc/rc.local > /dev/null
                             sudo chmod +x /etc/rc.local
                        fi
                        if ! grep -q "ethtool -K $NET_IFACE rx-udp-gro-forwarding on" /etc/rc.local 2>/dev/null; then
                             sudo sed -i -e '$i \ethtool -K '"$NET_IFACE"' rx-udp-gro-forwarding on\n' /etc/rc.local
                        fi
                    fi
                fi
                ;;
            *)
                print_message "ℹ️  Donanım optimizasyonu atlandı." "$YELLOW"
                ;;
        esac

        # 3. MSS Clamping & MTU Fix (Kritik Hız Ayarı)
        print_message "📡 Ağ Optimizasyonları (MTU & MSS Clamping) ayarlanıyor..." "$YELLOW"
        
        # MTU (wg0 arayüzü)
        if ip link show wg0 > /dev/null 2>&1; then
             # Genelde 1420 veya 1280 (Safe)
             sudo ip link set dev wg0 mtu 1280 || true
             print_message "✅ WireGuard MTU: 1280 olarak ayarlandı." "$GREEN"
        fi

        # MSS Clamping via Iptables
        if command -v iptables > /dev/null; then
             if ! sudo iptables -t mangle -C FORWARD -i wg0 -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
                 sudo iptables -t mangle -A FORWARD -i wg0 -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true
                 print_message "✅ TCP MSS Clamping kuralı eklendi." "$GREEN"
                 
                 # Kalıcılık (rc.local - basit yöntem)
                 CMD="iptables -t mangle -A FORWARD -i wg0 -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
                 if [[ ! -f /etc/rc.local ]]; then
                     echo '#!/bin/bash' | sudo tee /etc/rc.local > /dev/null
                     echo 'exit 0' | sudo tee -a /etc/rc.local > /dev/null
                     sudo chmod +x /etc/rc.local
                 fi
                 if ! grep -q "TCPMSS --clamp-mss-to-pmtu" /etc/rc.local; then
                      sudo sed -i -e '$i '"$CMD"'\n' /etc/rc.local
                 fi
             fi
        fi

        print_message "✅ WireGuard kurulumu ve optimizasyonu tamamlandı." "$GREEN"
        print_message "Konfigürasyon dosyaları /home/$NEW_USER dizini altında (veya root) oluşturulmuş olabilir." "$YELLOW"
        
    else
        print_message "❌ Kurulum tamamlanamadı (wg0.conf bulunamadı)." "$RED"
    fi

    # Temizlik
    rm -f wireguard-install.sh
}
