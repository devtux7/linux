#!/bin/bash

# =============================================================================
# UYGULAMA MENÜSÜ FONKSİYONLARI
# =============================================================================

install_selected_apps() {
    print_message "\n📦 EKSTRA UYGULAMALAR & OPTİMİZASYONLAR" "$PURPLE"
    print_message "─────────────────────────────────────" "$PURPLE"
    print_message "Kurulumu yapılacak ekstra uygulamaları seçin:" "$CYAN"
    
    echo ""
    echo "1) 🐳 Docker & Docker Compose (Optimize edilmiş)"
    echo "2) 🕸️  Tailscale (Güvenli VPN)"
    echo "3) 🐚 Zsh & Oh My Zsh (Gelişmiş Terminal)"
    echo "4) ⏩ Hepsini kur (1, 2, 3)"
    echo "5) ⏭️  Atla (Kurulumu tamamla)"
    echo ""
    
    echo "Çoklu seçim için boşluk bırakarak yazabilirsiniz (örn: 1 3)"
    read -p "Seçiminiz: " app_choices
    
    # Seçimleri diziye çevir
    # Eğer 4 (Hepsi) seçildiyse diğerlerini yoksay ve hepsini ekle
    if [[ "$app_choices" =~ 4 ]]; then
        app_choices="1 2 3"
    elif [[ "$app_choices" =~ 5 ]]; then
        print_message "ℹ️  Ekstra uygulama kurulumu atlanıyor..." "$YELLOW"
        return
    fi
    
    for choice in $app_choices; do
        case $choice in
            1)
                if [[ -f "$MODULES_DIR/apps/docker.sh" ]]; then
                    source "$MODULES_DIR/apps/docker.sh"
                    install_docker
                else
                    print_message "❌ Docker modülü bulunamadı!" "$RED"
                fi
                ;;
            2)
                if [[ -f "$MODULES_DIR/apps/tailscale.sh" ]]; then
                    source "$MODULES_DIR/apps/tailscale.sh"
                    install_tailscale
                else
                    print_message "❌ Tailscale modülü bulunamadı!" "$RED"
                fi
                ;;
            3)
                if [[ -f "$MODULES_DIR/apps/zsh.sh" ]]; then
                    source "$MODULES_DIR/apps/zsh.sh"
                    install_zsh
                else
                    print_message "❌ Zsh modülü bulunamadı!" "$RED"
                fi
                ;;
        esac
    done
}
