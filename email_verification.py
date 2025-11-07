import os
import jwt
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from flask import current_app, url_for

# Flask-Mail konfigürasyonu
def configure_mail(app):
    # Ortam değişkenlerinden veya varsayılan değerlerden konfigürasyon
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'YOUR_EMAIL_ADDRESS') # BURAYI KENDİ E-POSTA ADRESİNİZLE DEĞİŞTİRİN
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'YOUR_EMAIL_PASSWORD') # BURAYI KENDİ E-POSTA ŞİFRENİZLE DEĞİŞTİRİN
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])
    
    # Güvenlik için JWT Secret Key
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', app.config.get('SECRET_KEY', '') + '_JWT_SECRET')
    
    mail = Mail(app)
    return mail

# E-posta doğrulama token'ı oluşturma
def generate_verification_token(user_id, email):
    try:
        payload = {
            'exp': datetime.utcnow() + timedelta(hours=24), # Token 24 saat geçerli
            'iat': datetime.utcnow(),
            'sub': user_id,
            'email': email
        }
        return jwt.encode(
            payload,
            current_app.config['JWT_SECRET_KEY'],
            algorithm='HS256'
        )
    except Exception as e:
        # current_app may not be available during import-time; guard logging
        try:
            current_app.logger.error(f"Token oluşturma hatası: {e}")
        except Exception:
            pass
        return None

# E-posta doğrulama token'ını çözme
def verify_verification_token(token):
    try:
        payload = jwt.decode(
            token,
            current_app.config['JWT_SECRET_KEY'],
            algorithms=['HS256']
        )
        return payload['sub'], payload['email']
    except jwt.ExpiredSignatureError:
        return 'expired', None # Token süresi dolmuş
    except jwt.InvalidTokenError:
        return 'invalid', None # Geçersiz token
    except Exception as e:
        try:
            current_app.logger.error(f"Token doğrulama hatası: {e}")
        except Exception:
            pass
        return None, None

# E-posta gönderme fonksiyonu
def send_verification_email(mail, recipient_email, user_id):
    try:
        token = generate_verification_token(user_id, recipient_email)
        if not token:
            return False

        # Onay linkini oluştur
        # _external=True kullanmak için app context içinde olmalı
        with current_app.app_context():
            verification_url = url_for('verify_email', token=token, _external=True)

        msg = Message(
            'Hesabınızı Onaylayın',
            recipients=[recipient_email],
            html=f"""
            <p>Merhaba,</p>
            <p>Kaydınızı tamamlamak için lütfen aşağıdaki linke tıklayarak e-posta adresinizi onaylayın:</p>
            <p><a href="{verification_url}">Hesabımı Onayla</a></p>
            <p>Bu link 24 saat geçerlidir.</p>
            <p>Eğer bu kaydı siz yapmadıysanız, bu e-postayı dikkate almayınız.</p>
            <p>Saygılarımızla,</p>
            <p>Uygulama Ekibi</p>
            """
        )
        mail.send(msg)
        try:
            current_app.logger.info(f"Doğrulama e-postası {recipient_email} adresine gönderildi.")
        except Exception:
            pass
        return True
    except Exception as e:
        try:
            current_app.logger.error(f"E-posta gönderme hatası: {e}")
        except Exception:
            pass
        return False
