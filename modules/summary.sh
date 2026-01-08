#!/bin/bash

# =============================================================================
# ÖZET VE RAPORLAMA
# =============================================================================

# Kurulum özeti
show_summary() {
    print_message "\n🎯 KURULUM ÖZETİ" "$PURPLE"
    print_message "════════════════════════════════════════════════════════════════════════════════" "$PURPLE"

    local PUBLIC_IP
    if check_internet; then
        PUBLIC_IP=$(curl -s --connect-timeout 3 icanhazip.com 2>/dev/null || echo "Bilinmiyor")
    else
        PUBLIC_IP="Bilinmiyor"
    fi

    SERVER_HOSTNAME=$(hostname | cut -d'.' -f1 | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')
    if [ -z "$SERVER_HOSTNAME" ]; then
        SERVER_HOSTNAME="server"
    fi

    IP_ADDRESS=$(hostname -I | awk '{print $1}')

    echo ""
    print_message "📊 SİSTEM BİLGİLERİ:" "$CYAN"
    print_message "• Sunucu Adı:       $SERVER_HOSTNAME" "$YELLOW"
    print_message "• Kullanıcı:        $NEW_USER" "$YELLOW"
    print_message "• SSH Port:         $SSH_PORT" "$YELLOW"
    print_message "• Yerel IP:         $IP_ADDRESS" "$YELLOW"
    print_message "• Genel IP:         $PUBLIC_IP" "$YELLOW"
    echo ""

    print_message "🔐 GÜVENLİK AYARLARI:" "$CYAN"
    print_message "• Kimlik Doğrulama: $AUTH_METHOD" "$YELLOW"
    print_message "• Güvenlik Seviyesi: $SECURITY_LEVEL" "$YELLOW"
    print_message "• Root Girişi:      Devre Dışı" "$YELLOW"
    print_message "• Max Bağlantı:     3 eşzamanlı" "$YELLOW"
    print_message "• Fail2Ban:         Aktif (5 deneme)" "$YELLOW"
    print_message "• Güvenlik Duvarı:  Aktif" "$YELLOW"
    echo ""

    # SSH anahtar bağlantısı için özel bölüm
    if [[ "$AUTH_CHOICE" == "3" || "$AUTH_CHOICE" == "4" ]]; then
        print_message "🔑 SSH ANAHTAR DURUMU:" "$CYAN"
        print_message "─────────────────────" "$BLUE"

        # Public key kontrolü
        AUTH_KEYS_FILE="/home/$NEW_USER/.ssh/authorized_keys"
        if [[ -f "$AUTH_KEYS_FILE" ]] && [[ -s "$AUTH_KEYS_FILE" ]]; then
            KEY_COUNT=$(sudo -u "$NEW_USER" wc -l < "$AUTH_KEYS_FILE" 2>/dev/null || echo "0")
            KEY_TYPE=$(sudo -u "$NEW_USER" head -1 "$AUTH_KEYS_FILE" 2>/dev/null | awk '{print $1}' || echo "Bilinmiyor")
            print_message "✅ Public key başarıyla eklendi" "$GREEN"
            print_message "   • Key sayısı: $KEY_COUNT" "$CYAN"
            print_message "   • Key tipi: $KEY_TYPE" "$CYAN"
        else
            print_message "❌ Public key EKLENMEDİ!" "$RED"
        fi

        print_message "\n🔗 BAĞLANTI KOMUTU:" "$CYAN"
        print_message "ssh -p $SSH_PORT -i ~/.ssh/$SERVER_HOSTNAME $NEW_USER@$IP_ADDRESS" "$YELLOW"

        if [[ "$PUBLIC_IP" != "Bilinmiyor" ]]; then
            print_message "veya:" "$BLUE"
            print_message "ssh -p $SSH_PORT -i ~/.ssh/$SERVER_HOSTNAME $NEW_USER@$PUBLIC_IP" "$YELLOW"
        fi

    elif [[ "$AUTH_CHOICE" == "1" || "$AUTH_CHOICE" == "2" ]]; then
        print_message "🔑 BAĞLANTI KOMUTU:" "$CYAN"
        print_message "ssh -p $SSH_PORT $NEW_USER@$IP_ADDRESS" "$YELLOW"

        if [[ "$PUBLIC_IP" != "Bilinmiyor" ]]; then
            print_message "veya:" "$BLUE"
            print_message "ssh -p $SSH_PORT $NEW_USER@$PUBLIC_IP" "$YELLOW"
        fi
    fi

    if [[ "$AUTH_CHOICE" == "2" || "$AUTH_CHOICE" == "4" ]]; then
        print_message "\n📱 2FA BİLGİLERİ:" "$CYAN"
        print_message "• Her girişte Google Authenticator kodu gerekecek" "$YELLOW"
        print_message "• 2FA kodları 30 saniyede bir değişir" "$YELLOW"
        print_message "• Kurtarma kodlarını saklayın" "$YELLOW"

        if [[ "$AUTH_CHOICE" == "4" ]]; then
            print_message "• PAROLA İSTEMEZ - sadece SSH anahtarı ve 2FA kodu" "$GREEN"
        fi
    fi

    echo ""
    print_message "✅ AYARLAR KALICIDIR" "$GREEN"
    print_message "📋 Log dosyası: $LOG_FILE" "$BLUE"

    # Özet dosyasını kullanıcı dizinine kaydet
    SUMMARY_FILE="/home/$NEW_USER/ssh_kurulum_ozeti.txt"
    sudo tee "$SUMMARY_FILE" > /dev/null << EOF
SSH KURULUM ÖZETİ - $(date)
════════════════════════════════════════════════════════════════════════════════

SİSTEM BİLGİLERİ:
• Sunucu Adı:       $SERVER_HOSTNAME
• Kullanıcı:        $NEW_USER
• SSH Port:         $SSH_PORT
• Yerel IP:         $IP_ADDRESS
• Genel IP:         $PUBLIC_IP

GÜVENLİK AYARLARI:
• Kimlik Doğrulama: $AUTH_METHOD
• Güvenlik Seviyesi: $SECURITY_LEVEL
• Root Girişi:      Devre Dışı
• Max Bağlantı:     3 eşzamanlı
• Fail2Ban:         Aktif (5 deneme)
• Güvenlik Duvarı:  Aktif

$(if [[ "$AUTH_CHOICE" == "3" || "$AUTH_CHOICE" == "4" ]]; then
echo "SSH BAĞLANTI KOMUTU:"
echo "ssh -p $SSH_PORT -i ~/.ssh/$SERVER_HOSTNAME $NEW_USER@$IP_ADDRESS"
if [[ "$PUBLIC_IP" != "Bilinmiyor" ]]; then
echo "veya: ssh -p $SSH_PORT -i ~/.ssh/$SERVER_HOSTNAME $NEW_USER@$PUBLIC_IP"
fi
echo ""
elif [[ "$AUTH_CHOICE" == "1" || "$AUTH_CHOICE" == "2" ]]; then
echo "PAROLA BAĞLANTISI:"
echo "ssh -p $SSH_PORT $NEW_USER@$IP_ADDRESS"
if [[ "$PUBLIC_IP" != "Bilinmiyor" ]]; then
echo "veya: ssh -p $SSH_PORT $NEW_USER@$PUBLIC_IP"
fi
echo ""
fi)

$(if [[ "$AUTH_CHOICE" == "2" || "$AUTH_CHOICE" == "4" ]]; then
echo "2FA NOTLARI:"
echo "- Her girişte Google Authenticator kodu gerekecek"
echo "- 2FA kodları 30 saniyede bir değişir"
echo "- Kurtarma kodlarını saklayın"
if [[ "$AUTH_CHOICE" == "4" ]]; then
echo "- PAROLA İSTEMEZ - sadece SSH anahtarı ve 2FA kodu"
fi
echo ""
fi)

KURULUM TARİHİ: $(date)
LOG DOSYASI: $LOG_FILE

ÖNEMLİ NOT: SSH anahtarınızı ve 2FA kurtarma kodlarını güvenli bir yerde saklayın!
EOF

    sudo chown "$NEW_USER:$NEW_USER" "$SUMMARY_FILE"
    sudo chmod 600 "$SUMMARY_FILE"

    print_message "\n📄 Özet dosyası: $SUMMARY_FILE" "$BLUE"
    print_message "   (Bu dosyada tüm bağlantı bilgileri ve komutlar mevcut)" "$CYAN"
}
