#!/bin/bash

# =============================================================================
# DEĞİŞKENLER VE KONSTANTLAR
# =============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Log dosyasını başlat (eğer main'de tanımlanmamışsa burada tanımlı kalsın, 
# ama genellikle main script başlatılınca bu değişken set edilmiş olur. 
# Yine de modül olarak bağımsız çalışabilmesi için burada da tanımlanabilir 
# veya kontrol edilebilir. Şimdilik orijinal mantığı koruyoruz.)
# Not: Modüler yapıda LOG_FILE değişkeninin bu dosya source edildiğinde 
# oluşması için global kapsamda olması gerekir.
readonly LOG_FILE="/tmp/ssh-setup-$(date +%Y%m%d_%H%M%S).log"

# =============================================================================
# YARDIMCI FONKSİYONLAR
# =============================================================================

# Renkli mesaj fonksiyonu
print_message() {
    echo -e "${2}${1}${NC}"
}

# Log fonksiyonu
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE" > /dev/null
}

# Hata fonksiyonu
error_exit() {
    print_message "❌ $1" "$RED"
    log_message "HATA: $1"
    exit 1
}

# Kontrol fonksiyonu
check_command() {
    if ! command -v "$1" &> /dev/null; then
        print_message "⚠️  $1 komutu bulunamadı. Kuruluyor..." "$YELLOW"
        sudo apt install -y "$1" >> "$LOG_FILE" 2>&1 || print_message "❌ $1 kurulumu başarısız" "$RED"
    fi
}

# Root kontrolü
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error_exit "Bu script root olarak çalıştırılmamalıdır."
    fi
}

# İnternet kontrolü
check_internet() {
    if ! ping -c 1 -W 2 google.com &> /dev/null; then
        print_message "⚠️  İnternet bağlantısı yok. Bazı işlemler atlanacak." "$YELLOW"
        return 1
    fi
    return 0
}
