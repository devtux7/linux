#!/bin/bash

install_wireguard() {
    print_message "\n🛡️  WIREGUARD VPN SERVER KURULUMU" "$CYAN"
    print_message "─────────────────────────────────" "$BLUE"
    
    print_message "⚠️  DİKKAT: Bu modül için sunucunuzun PUBLIC IP (Statik) adresi olmalıdır." "$RED"
    print_message "Ev interneti (CGNAT) veya modemin arkasındaki cihazlarda çalışmayabilir." "$YELLOW"
    print_message "Eğer ev sunucusu kullanıyorsanız 'Tailscale' modülünü tercih ediniz." "$YELLOW"
    echo ""
    read -p "Devam etmek istiyor musunuz? (E/h): " wg_confirm
    if [[ ! "$wg_confirm" =~ ^[Ee]$ ]]; then
         return
    fi

    if sudo test -f "/etc/wireguard/wg0.conf"; then
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

    # PATCH: LXC/Container kontrolünü devre dışı bırak (OrbStack desteği için)
    print_message "🔧 Sanallaştırma kontrolleri yamalanıyor (OrbStack/LXC Fix)..." "$YELLOW"
    
    # checkVirt fonksiyonunun çağrıldığı satırı yorum satırı yap
    # Bu, LXC/OpenVZ kontrolünü tamamen devre dışı bırakır
    sed -i 's/^\tcheckVirt/#\tcheckVirt/' wireguard-install.sh

    print_message "⚙️  Kurulum başlıyor... (Lütfen soruları cevaplayın)" "$YELLOW"
    sudo bash wireguard-install.sh

    # Kurulum sonrası optimizasyonlar
    if sudo test -f "/etc/wireguard/wg0.conf"; then
        print_message "\n🚀 WIREGUARD OPTİMİZASYONLARI" "$PURPLE"
        print_message "─────────────────────────────" "$PURPLE"
        
        echo ""
        print_message "Performans Optimizasyonu:" "$CYAN"
        echo "1) ☁️  Standart VPS / Sunucu (DigitalOcean, AWS, vb.)"
        echo "2) ⏭️  Atla (Optimizasyon yapma)"
        echo ""
        read -p "Seçiminiz: " hardware_choice

        # 1. IP Forwarding (Kernel seviyesinde zaten script yapmış olabilir ama garantiye alalım)
        echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.d/99-wireguard-opt.conf > /dev/null
        echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee -a /etc/sysctl.d/99-wireguard-opt.conf > /dev/null

        # 2. Sysctl Optimizasyonları (Hardware Bazlı)
        case $hardware_choice in
            1)
                print_message "🛠️  VPS optimizasyonları uygulanıyor (BBR, UDP Buffer)..." "$YELLOW"
                cat <<EOF | sudo tee -a /etc/sysctl.d/99-wireguard-opt.conf > /dev/null
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
EOF
                # Sysctl uygula (Hata verirse devam et - Fail-safe)
                sudo sysctl -p /etc/sysctl.d/99-wireguard-opt.conf >> "$LOG_FILE" 2>&1 || print_message "⚠️  Uyarı: BBR/Buffer ayarları uygulanamadı." "$YELLOW"
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
