#!/bin/bash

install_tailscale() {
    print_message "\n🕸️  TAILSCALE VPN KURULUMU" "$CYAN"
    print_message "────────────────────────" "$BLUE"

    if command -v tailscale &> /dev/null; then
        print_message "✅ Tailscale zaten kurulu" "$GREEN"
    else
        print_message "📥 Tailscale GPG key ve repo ekleniyor..." "$YELLOW"
        curl -fsSL https://tailscale.com/install.sh | sh >> "$LOG_FILE" 2>&1
        
        if command -v tailscale &> /dev/null; then
            print_message "✅ Tailscale kuruldu" "$GREEN"
            sudo systemctl enable tailscaled >> "$LOG_FILE" 2>&1
            sudo systemctl start tailscaled
            log_message "Tailscale kuruldu"
        else
            print_message "❌ Tailscale kurulumu başarısız oldu" "$RED"
            return 1
        fi
    fi

    # Exit Node Yapılandırma Sorusu
    echo ""
    print_message "🔄 Bu sunucuyu Exit Node (VPN İnternet Çıkış Noktası) olarak kullanacak mısınız?" "$CYAN"
    echo "Bu işlem trafiği yönlendirmek için IP Forwarding ayarlarını yapar ve sistem optimizasyonu sağlar."
    echo ""
    read -p "Seçiminiz (E/h): " exit_node_choice
    
    if [[ "$exit_node_choice" =~ ^[Ee]$ ]]; then
        print_message "⚙️  IP Forwarding (Yönlendirme) açılıyor..." "$YELLOW"
        
        # IP Forwarding aktif et
        echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.d/99-tailscale.conf
        echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee -a /etc/sysctl.d/99-tailscale.conf
        # sysctl hatası scripti durdurmasın (Sanal ortamlarda yazma izni olmayabilir)
        sudo sysctl -p /etc/sysctl.d/99-tailscale.conf >> "$LOG_FILE" 2>&1 || print_message "⚠️  Uyarı: sysctl ayarları uygulanamadı (Sanal ortam kısıtlaması olabilir)." "$YELLOW"
        
        print_message "🚀 Performans Optimizasyonu İçin Donanım Seçin:" "$CYAN"
        echo "1) ☁️  Standart VPS / x86 Sunucu (DigitalOcean, AWS, vb.)"
        echo "2) 🍓 Raspberry Pi 4/5 veya ARM Kartlar"
        echo "3) ⏭️  Atla (Optimizasyon yapma)"
        echo ""
        read -p "Seçiminiz: " hardware_choice
        
        case $hardware_choice in
            1)
                print_message "🛠️  VPS optimizasyonları uygulanıyor (BBR, UDP Buffer)..." "$YELLOW"
                
                # BBR Congestion Control & UDP Buffer
                cat <<EOF | sudo tee -a /etc/sysctl.d/99-tailscale.conf
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
EOF
                sudo sysctl -p /etc/sysctl.d/99-tailscale.conf >> "$LOG_FILE" 2>&1 || print_message "⚠️  Uyarı: BBR/Buffer ayarları uygulanamadı (Kernel desteği olmayabilir)." "$YELLOW"
                ;;
                
            2)
                print_message "🛠️  Raspberry Pi optimizasyonları uygulanıyor (UDP Offload, BBR)..." "$YELLOW"
                
                # BBR & UDP Buffer
                cat <<EOF | sudo tee -a /etc/sysctl.d/99-tailscale.conf
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
EOF
                sudo sysctl -p /etc/sysctl.d/99-tailscale.conf >> "$LOG_FILE" 2>&1
                
                # Raspberry Pi Eth0 UDP GRO (Generic Receive Offload) Optimization
                # Bu özellik CPU yükünü ciddi oranda düşürür
                if command -v ethtool &> /dev/null; then
                    NET_IFACE=$(ip route sh | grep default | awk '{print $5}')
                    print_message "Rx-UDP-GRO aktif ediliyor ($NET_IFACE)..." "$YELLOW"
                    sudo ethtool -K "$NET_IFACE" rx-udp-gro-forwarding on >> "$LOG_FILE" 2>&1 || true
                    
                    # Kalıcı yapmak için (network-manager dispatcher veya rc.local gerekebilir, şimdilik rc.local basit çözüm)
                    if ! grep -q "ethtool -K $NET_IFACE rx-udp-gro-forwarding on" /etc/rc.local 2>/dev/null; then
                         # rc.local yoksa oluştur
                         if [[ ! -f /etc/rc.local ]]; then
                             echo '#!/bin/bash' | sudo tee /etc/rc.local
                             echo 'exit 0' | sudo tee -a /etc/rc.local
                             sudo chmod +x /etc/rc.local
                         fi
                         # exit 0 satırından önceye ekle
                         sudo sed -i -e '$i \ethtool -K '"$NET_IFACE"' rx-udp-gro-forwarding on\n' /etc/rc.local
                    fi
                else
                    print_message "⚠️  ethtool bulunamadı, UDP offload atlanıyor." "$YELLOW"
                fi
                ;;
                
            *)
                print_message "ℹ️  Ekstra optimizasyon atlandı." "$YELLOW"
                ;;
        esac
        
        print_message "\n⚠️  ÖNEMLİ: Tailscale Exit Node modu ile başlatılıyor!" "$GREEN"
        print_message "Kurulum sonrası ekrana gelen linke tıklayın ve Admin Panel'den 'Edit Route Settings' -> 'Use as Exit Node' seçeneğini işaretleyin." "$YELLOW"
        
        # Exit node olarak başlatma komutu (kullanıcının linke basıp login olması gerekir)
        print_message "Aşağıdaki komutu kopyalayıp çalıştırın:\nsudo tailscale up --advertise-exit-node" "$GREEN"
        
    else
        print_message "ℹ️  Standart kurulum yapıldı (Exit Node kapalı)." "$YELLOW"
        print_message "Aşağıdaki komutu kopyalayıp çalıştırın:\nsudo tailscale up" "$GREEN"
    fi
}
