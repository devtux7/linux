#!/bin/bash

# =============================================================================
# KULLANICI YÖNETİMİ
# =============================================================================

# Root parola yönetimi
manage_root_password() {
    print_message "\n🔐 ROOT PAROLA YÖNETİMİ" "$CYAN"
    print_message "───────────────────────" "$BLUE"

    echo ""
    echo "1) Varsayılan root parolasını değiştir (önerilen)"
    echo "2) Mevcut root parolasını koru (riskli)"
    echo ""

    while true; do
        read -p "Seçiminiz (1/2): " root_choice

        case $root_choice in
            1)
                print_message "\n🔑 Yeni ROOT parolasını girin:" "$BLUE"
                print_message "(Parola görünmez, kopyala-yapıştır desteklenir)" "$YELLOW"
                read -rs root_pass1
                echo ""
                print_message "Parolayı tekrar girin:" "$YELLOW"
                read -rs root_pass2
                echo ""

                if [[ "$root_pass1" == "$root_pass2" && -n "$root_pass1" ]]; then
                    echo "root:$root_pass1" | sudo chpasswd
                    if [[ $? -eq 0 ]]; then
                        print_message "✅ Root parolası başarıyla değiştirildi" "$GREEN"
                        log_message "Root parolası değiştirildi"
                        break
                    else
                        print_message "❌ Parola değiştirilemedi" "$RED"
                    fi
                else
                    print_message "❌ Parolalar eşleşmiyor veya boş!" "$RED"
                fi
                ;;
            2)
                print_message "⚠️  Root parolasını değiştirmediğiniz için güvenlik riski oluşabilir!" "$RED"
                log_message "Root parolası değiştirilmedi"
                break
                ;;
            *)
                print_message "❌ Geçersiz seçim!" "$RED"
                ;;
        esac
    done
}

# Kullanıcı oluşturma
create_user() {
    print_message "\n👥 KULLANICI YÖNETİMİ" "$CYAN"
    print_message "────────────────────" "$BLUE"

    echo ""
    echo "1) Yeni bir kullanıcı hesabı oluştur (önerilir)"
    echo "2) Mevcut kullanıcı hesabı ile devam et"
    echo ""

    while true; do
        read -p "Seçiminiz (1/2): " user_choice

        case $user_choice in
            1)
                # YENİ KULLANICI OLUŞTURMA AKIŞI
                while true; do
                    read -p "✨ Yeni kullanıcı adı girin: " NEW_USER

                    if [[ -z "$NEW_USER" ]]; then
                        print_message "❌ Kullanıcı adı boş olamaz!" "$RED"
                        continue
                    fi

                    if id "$NEW_USER" &>/dev/null; then
                        print_message "ℹ️  Kullanıcı '$NEW_USER' zaten var. Mevcut kullanıcıyı kullanacaksınız." "$YELLOW"
                        break
                    fi
                    break
                done

                # Kullanıcı yoksa oluştur
                if ! id "$NEW_USER" &>/dev/null; then
                    sudo adduser --disabled-password --gecos "" "$NEW_USER" > /dev/null 2>&1

                    # Parola ayarı için döngü
                    while true; do
                        print_message "\n🔑 '$NEW_USER' için parola belirleyin:" "$BLUE"
                        print_message "(Parola görünmez, kopyala-yapıştır desteklenir)" "$YELLOW"
                        read -rs user_pass1
                        echo ""
                        print_message "Parolayı tekrar girin:" "$YELLOW"
                        read -rs user_pass2
                        echo ""

                        if [[ "$user_pass1" == "$user_pass2" && -n "$user_pass1" ]]; then
                            echo "$NEW_USER:$user_pass1" | sudo chpasswd
                            if [[ $? -eq 0 ]]; then
                                print_message "✅ Kullanıcı '$NEW_USER' oluşturuldu ve parola ayarlandı" "$GREEN"
                                log_message "Kullanıcı $NEW_USER oluşturuldu"
                                break
                            else
                                print_message "❌ Parola ayarlanamadı, tekrar deneyin" "$RED"
                            fi
                        else
                            print_message "❌ Parolalar eşleşmiyor veya boş! Tekrar deneyin." "$RED"
                        fi
                    done
                else
                    print_message "ℹ️  Mevcut kullanıcı '$NEW_USER' kullanılacak" "$YELLOW"
                fi
                break
                ;;
            
            2)
                # MEVCUT KULLANICI İLE DEVAM ETME AKIŞI
                NEW_USER=$(whoami)
                
                # Sadece root değilse kabul et, root ise uyarı ver
                if [[ "$NEW_USER" == "root" ]]; then
                    print_message "⚠️  Root kullanıcısı olarak devam edemezsiniz. Lütfen yeni bir kullanıcı oluşturun." "$RED"
                    continue
                fi
                
                print_message "ℹ️  Mevcut kullanıcı '$NEW_USER' ile devam ediliyor." "$YELLOW"
                log_message "Mevcut kullanıcı seçildi: $NEW_USER"
                break
                ;;
            
            *)
                print_message "❌ Geçersiz seçim!" "$RED"
                ;;
        esac
    done

    # ORTAK ADIMLAR: Kullanıcıyı gruplara ekle
    # (Hem yeni oluşturulan hem de mevcut seçilen kullanıcı için uygulanır)
    sudo usermod -aG sudo "$NEW_USER"
    sudo groupadd -f sshusers
    sudo usermod -aG sshusers "$NEW_USER"

    print_message "✅ Kullanıcı '$NEW_USER' sudo ve sshusers gruplarına eklendi/doğrulandı" "$GREEN"
}
