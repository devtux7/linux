#!/bin/bash

# =============================================================================
# SİSTEM FONKSİYONLARI
# =============================================================================

# Sistem bilgilerini göster
show_system_info() {
    print_message "\n📊 SİSTEM BİLGİLERİ" "$CYAN"
    print_message "────────────────────" "$BLUE"
    print_message "• Mevcut Kullanıcı: $(whoami)" "$YELLOW"
    print_message "• Hostname: $(hostname)" "$YELLOW"
    print_message "• Dağıtım: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')" "$YELLOW"
    print_message "• Çekirdek: $(uname -r)" "$YELLOW"
    print_message "• Yerel IP: $(hostname -I | awk '{print $1}')" "$YELLOW"
}

# Sistem güncellemeleri
update_system() {
    print_message "\n📦 SİSTEM GÜNCELLEMELERİ" "$CYAN"
    print_message "────────────────────────" "$BLUE"

    print_message "🔄 Paket listesi güncelleniyor..." "$YELLOW"
    sudo apt update >> "$LOG_FILE" 2>&1

    print_message "⚡ Sistem güncelleniyor..." "$YELLOW"
    sudo apt upgrade -y >> "$LOG_FILE" 2>&1

    print_message "🧹 Temizlik yapılıyor..." "$YELLOW"
    sudo apt autoremove -y >> "$LOG_FILE" 2>&1

    print_message "✅ Sistem güncellemeleri tamamlandı" "$GREEN"
}

# Güvenlik güncellemeleri
configure_security_updates() {
    print_message "\n🛡️  OTOMATİK GÜVENLİK GÜNCELLEMELERİ" "$CYAN"
    print_message "──────────────────────────────────" "$BLUE"

    sudo apt install -y unattended-upgrades >> "$LOG_FILE" 2>&1

    sudo tee /etc/apt/apt.conf.d/50unattended-upgrades > /dev/null << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    sudo tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    print_message "✅ Otomatik güvenlik güncellemeleri yapılandırıldı" "$GREEN"
}

# Paket kurulumu
install_packages() {
    print_message "\n📦 GEREKLİ PAKET KURULUMU" "$CYAN"
    print_message "─────────────────────────" "$BLUE"

    local packages=("openssh-server" "ufw" "fail2ban")

    for pkg in "${packages[@]}"; do
        if dpkg -l | grep -q "^ii  $pkg "; then
            print_message "✅ $pkg zaten kurulu" "$GREEN"
        else
            print_message "📦 $pkg kuruluyor..." "$YELLOW"
            sudo apt install -y "$pkg" >> "$LOG_FILE" 2>&1
            print_message "✅ $pkg kuruldu" "$GREEN"
        fi
    done
}
