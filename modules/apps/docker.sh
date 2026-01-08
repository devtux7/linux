#!/bin/bash

install_docker() {
    print_message "\n🐳 DOCKER & DOCKER COMPOSE KURULUMU" "$CYAN"
    print_message "───────────────────────────────────" "$BLUE"

    if command -v docker &> /dev/null; then
        print_message "✅ Docker zaten kurulu" "$GREEN"
    else
        print_message "📥 Docker kurulum scripti indiriliyor..." "$YELLOW"
        # Resmi Docker kurulum scriptini kullan (en güvenilir yöntem)
        curl -fsSL https://get.docker.com -o get-docker.sh
        
        print_message "⚙️  Docker kuruluyor..." "$YELLOW"
        sudo sh get-docker.sh >> "$LOG_FILE" 2>&1
        rm get-docker.sh
        
        # Kullanıcıyı docker grubuna ekle (sudo'suz çalıştırmak için)
        sudo usermod -aG docker "$NEW_USER"
        print_message "✅ Kullanıcı '$NEW_USER' docker grubuna eklendi" "$GREEN"
        
        # Servisi başlat
        sudo systemctl start docker
        sudo systemctl enable docker >> "$LOG_FILE" 2>&1
        
        print_message "✅ Docker ve Docker Compose plugin kuruldu" "$GREEN"
    fi

    # Docker Log Rotation Ayarı (Kritik Optimizasyon)
    # Varsayılan olarak docker logları sınırsız büyür ve diski doldurabilir.
    print_message "🛠️  Docker log rotasyon ayarları yapılıyor..." "$YELLOW"
    
    if [[ ! -f /etc/docker/daemon.json ]]; then
        sudo mkdir -p /etc/docker
        cat <<EOF | sudo tee /etc/docker/daemon.json > /dev/null
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF
        # Ayarların geçerli olması için servisi yeniden başlat
        sudo systemctl restart docker
        print_message "✅ Log rotasyonu ayarlandı (max-size: 10m, max-file: 3)" "$GREEN"
        log_message "Docker log rotation konfigüre edildi"
    else
        print_message "ℹ️  /etc/docker/daemon.json zaten var, dokunulmadı." "$YELLOW"
    fi
}
