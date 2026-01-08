#!/bin/bash

install_zsh() {
    print_message "\n🐚 ZSH & OH MY ZSH KURULUMU" "$CYAN"
    print_message "──────────────────────────" "$BLUE"

    # Zsh kurulumu
    if ! command -v zsh &> /dev/null; then
        print_message "📦 Zsh kuruluyor..." "$YELLOW"
        sudo apt install -y zsh >> "$LOG_FILE" 2>&1
    fi

    # Oh My Zsh kurulumu (kullanıcı için)
    # Script root yetkisiyle çalışsa da, oh-my-zsh'ı hedef kullanıcı için kurmalıyız.
    
    OMZ_DIR="/home/$NEW_USER/.oh-my-zsh"
    
    if [[ -d "$OMZ_DIR" ]]; then
        print_message "✅ Oh My Zsh zaten kurulu" "$GREEN"
    else
        print_message "✨ Oh My Zsh indiriliyor ve kuruluyor..." "$YELLOW"
        
        # Unattended install for the specific user
        # sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
        
        # Doğru kullanıcı yetkileriyle çalıştırmak için biraz trick yapıyoruz
        sudo -u "$NEW_USER" sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended >> "$LOG_FILE" 2>&1
        
        if [[ -d "$OMZ_DIR" ]]; then
            print_message "✅ Oh My Zsh kuruldu" "$GREEN"
            
            # Varsayılan shell'i değiştir
            sudo chsh -s $(which zsh) "$NEW_USER"
            print_message "✅ Varsayılan shell Zsh yapıldı" "$GREEN"
            
            # Eklentileri öneri olarak mesaj geç (otomasyonu zor olabilir)
            print_message "💡 İpucu: zsh-autosuggestions ve zsh-syntax-highlighting eklentilerini kurmanızı öneririm." "$CYAN"
            
            log_message "Zsh ve Oh My Zsh kuruldu"
        else
            print_message "❌ Oh My Zsh kurulumu başarısız oldu" "$RED"
        fi
    fi
}
