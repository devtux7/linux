#!/bin/bash

# =============================================================================
# GÜVENLİK AYARLARI VE HATA YAKALAMA
# =============================================================================
set -Eeuo pipefail

# Scriptin bulunduğu dizini bul
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Repo bilgileri (Kullanıcı tarafından güncellenmelidir)
# Eğer script curl ile çalıştırılıyorsa bu repo adresinden modüller indirilecek
GITHUB_USER="devtux7"  # Kullanıcı adı
GITHUB_REPO="linux"    # Repo adı
GITHUB_BRANCH="main"
BASE_URL="https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/$GITHUB_BRANCH/modules"

# Modül dizini ve geçici dizin kontrolü
if [[ -d "$SCRIPT_DIR/modules" ]]; then
    # Yerel çalıştırma (git clone sonrası)
    MODULES_DIR="$SCRIPT_DIR/modules"
    CLEANUP_REQUIRED=false
else
    # Remote çalıştırma (curl | bash)
    echo -e "\033[1;33m⚠️  Yerel modüller bulunamadı. GitHub üzerinden '$GITHUB_REPO' modülleri indiriliyor...\033[0m"
    
    # Geçici dizin oluştur
    MODULES_DIR="$(mktemp -d)"
    CLEANUP_REQUIRED=true
    
    # Modülleri indir
    # Ana modüller
    MODULES=("utils.sh" "system.sh" "user.sh" "ssh.sh" "security.sh" "summary.sh" "apps_menu.sh")
    
    # Apps alt klasörü ve modülleri
    APPS_MODULES=("apps/docker.sh" "apps/tailscale.sh" "apps/zsh.sh")
    
    # Gerekli araç kontrolü
    if ! command -v curl &> /dev/null; then
        echo -e "\033[0;31m❌ Hata: curl komutu bulunamadı. Modülleri indirmek için gereklidir.\033[0m"
        exit 1
    fi
    
    # Ana modülleri indir
    for module in "${MODULES[@]}"; do
        curl -fsSL "$BASE_URL/$module" -o "$MODULES_DIR/$module" || {
            echo -e "\033[0;31m❌ Hata: $module indirilemedi! URL'i kontrol edin:\033[0m"
            echo "$BASE_URL/$module"
            rm -rf "$MODULES_DIR"
            exit 1
        }
    done

    # Apps modüllerini indir
    mkdir -p "$MODULES_DIR/apps"
    for module in "${APPS_MODULES[@]}"; do
        curl -fsSL "$BASE_URL/$module" -o "$MODULES_DIR/$module" || {
            echo -e "\033[0;31m❌ Hata: $module indirilemedi! URL'i kontrol edin:\033[0m"
            echo "$BASE_URL/$module"
            rm -rf "$MODULES_DIR"
            exit 1
        }
    done
fi

# =============================================================================
# MODÜLLERİ YÜKLE
# =============================================================================

# Önce utils yüklenmeli (renkler ve temel fonksiyonlar için)
if [[ -f "$MODULES_DIR/utils.sh" ]]; then
    source "$MODULES_DIR/utils.sh"
else
    echo "❌ HATA: Kritik modül bulunamadı: utils.sh"
    # Fallback to local if MODULES_DIR setup failed unexpectedly, though exit 1 above handles it.
    exit 1
fi

# Diğer modülleri yükle
for module in system.sh user.sh ssh.sh security.sh summary.sh apps_menu.sh; do
    if [[ -f "$MODULES_DIR/$module" ]]; then
        source "$MODULES_DIR/$module"
    else
        print_message "❌ HATA: Modül bulunamadı: $module" "$RED"
        exit 1
    fi
done

# =============================================================================
# TRAP HANDLERS
# =============================================================================
cleanup() {
    local exit_code=$?
    if [[ "$CLEANUP_REQUIRED" == "true" && -d "$MODULES_DIR" ]]; then
        rm -rf "$MODULES_DIR"
    fi
    exit $exit_code
}

trap cleanup EXIT
trap 'echo -e "\033[0;31m❌ Beklenmedik hata oluştu. Script durduruldu.\033[0m"; cleanup' ERR
trap 'echo -e "\033[0;31m\n❌ Kullanıcı tarafından iptal edildi.\033[0m"; cleanup' INT

# =============================================================================
# ANA FONKSİYON
# =============================================================================
main() {
    clear
    print_message "\n🎯 ============================================" "$PURPLE"
    print_message "     Ubuntu Server SSH Kurulum Scripti" "$PURPLE"
    print_message "     Geliştirilmiş ve Güvenli Versiyon (Modüler)" "$PURPLE"
    print_message "============================================\n" "$PURPLE"

    # Log dosyasını başlat
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    log_message "Script başlatıldı"

    # Başlangıç kontrolleri
    check_root
    check_internet

    # Sistem bilgilerini göster
    show_system_info

    # Root parola yönetimi
    manage_root_password

    # Kullanıcı oluşturma
    create_user

    # SSH port ayarı
    configure_ssh_port

    # Sistem güncellemeleri
    update_system

    # Güvenlik güncellemeleri
    configure_security_updates

    # Paket kurulumu
    install_packages

    # SSH konfigürasyonu
    configure_ssh

    # 2FA konfigürasyonu
    if [[ "$AUTH_CHOICE" == "2" || "$AUTH_CHOICE" == "4" ]]; then
        # Geçici olarak hata yakalamayı devre dışı bırak
        set +e
        trap - ERR

        print_message "\n🔄 2FA konfigürasyonu başlatılıyor..." "$YELLOW"
        configure_2fa

        # Hata yakalamayı ve trap'i geri yükle
        set -e
        trap 'echo -e "\033[0;31m❌ Beklenmedik hata oluştu. Script durduruldu.\033[0m"' ERR
    fi

    # SSH anahtar yönetimi
    if [[ "$AUTH_CHOICE" == "3" || "$AUTH_CHOICE" == "4" ]]; then
        # Geçici olarak hata yakalamayı devre dışı bırak
        set +e
        trap - ERR

        print_message "\n🔄 SSH anahtar yönetimi başlatılıyor..." "$YELLOW"
        manage_ssh_keys

        # Hata yakalamayı ve trap'i geri yükle
        set -e
        trap 'echo -e "\033[0;31m❌ Beklenmedik hata oluştu. Script durduruldu.\033[0m"' ERR
    fi

    # Güvenlik duvarı
    configure_firewall

    # Fail2Ban
    configure_fail2ban

    # SSH servisini yeniden başlat
    restart_ssh_service

    # Ekstra Uygulamalar
    install_selected_apps

    # Kurulum özeti
    show_summary

    print_message "\n🎉 KURULUM TAMAMLANDI!" "$GREEN"
    print_message "════════════════════════════════════════════════════════════════════════════════" "$PURPLE"

    # Log dosyasını kapat
    log_message "Kurulum tamamlandı"
}

# =============================================================================
# ANA PROGRAM
# =============================================================================

# Ana fonksiyonu çalıştır
main "$@"
