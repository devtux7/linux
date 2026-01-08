#!/bin/bash

install_tailscale() {
    print_message "\n🕸️  TAILSCALE VPN KURULUMU" "$CYAN"
    print_message "────────────────────────" "$BLUE"

    if command -v tailscale &> /dev/null; then
        print_message "✅ Tailscale zaten kurulu" "$GREEN"
    else
        print_message "📥 Tailscale GPG key ve repo ekleniyor..." "$YELLOW"
        # Resmi one-line install scripti
        curl -fsSL https://tailscale.com/install.sh | sh >> "$LOG_FILE" 2>&1
        
        if command -v tailscale &> /dev/null; then
            print_message "✅ Tailscale kuruldu" "$GREEN"
            
            # Servisi enable et
            sudo systemctl enable tailscaled >> "$LOG_FILE" 2>&1
            sudo systemctl start tailscaled
            
            print_message "\n⚠️  ÖNEMLİ: Tailscale kurulumu tamamlandı ancak aktif değil!" "$RED"
            print_message "Kurulum bittikten sonra şu komutu çalıştırıp linke tıklamalısınız:" "$YELLOW"
            print_message "sudo tailscale up" "$GREEN"
            
            log_message "Tailscale kuruldu"
        else
            print_message "❌ Tailscale kurulumu başarısız oldu" "$RED"
        fi
    fi
}
