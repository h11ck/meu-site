from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import os
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configurações para o Gmail
smtp_server = 'smtp.gmail.com'
smtp_port = 587  # ou 465 para SSL

# Autenticação
username = 'henriquenique914@gmail.com'  # Substitua pelo seu endereço de e-mail
password = 'qurk cdde bybn ptvf'  # Substitua pela sua senha normal ou senha de aplicativo

# Criar a mensagem
msg = MIMEMultipart()
msg['From'] = username
msg['To'] = 'destinatario@example.com'  # Substitua pelo e-mail do destinatário
msg['Subject'] = 'Assunto do e-mail'

# Corpo do e-mail
body = 'Este é o corpo do e-mail.'
msg.attach(MIMEText(body, 'plain'))

try:
    # Conectar ao servidor SMTP
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()  # Usar STARTTLS para criptografia
    server.login(username, password)  # Autenticar
    server.sendmail(username, 'destinatario@example.com', msg.as_string())  # Enviar e-mail
    print('E-mail enviado com sucesso!')
    server.quit()  # Fechar a conexão
except smtplib.SMTPAuthenticationError as e:
    print(f'Erro de autenticação: {e}')
except Exception as e:
    print(f'Ocorreu um erro: {e}')

app = Flask(__name__)

# Configuração
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/Henrique/Desktop/p/instance/database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configurações do Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'henriquenique914@gmail.com'
app.config['MAIL_PASSWORD'] = 'qurk cdde bybn ptvf'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

# Modelos
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    reset_token = db.Column(db.String(100), nullable=True)

# Criação do banco de dados
if not os.path.exists('instance'):
    os.makedirs('instance')

with app.app_context():
    db.drop_all()  # Se você já tem dados, use com cautela
    db.create_all()

# Rotas
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not username or not email or not password:
            flash('Por favor, preencha todos os campos.', 'danger')
            return redirect(url_for('registro'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email já cadastrado. Por favor, faça login.', 'danger')
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Usuário registrado com sucesso!', 'success')
        return redirect(url_for('login'))
    
    return render_template('registro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        print("Form Data:", request.form)  # Adicione esta linha para depuração
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Por favor, preencha corretamente os campos.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Login mal-sucedido. Verifique o usuário e a senha.', 'danger')
    
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = secrets.token_hex(16)
            user.reset_token = token
            db.session.commit()
            
            # Enviar o e-mail de recuperação
            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message('Redefinição de Senha',
                          sender='seuemail@gmail.com',
                          recipients=[email])
            msg.body = f'Para redefinir sua senha, clique no seguinte link: {reset_link}'
            mail.send(msg)
            
            flash(f'Link de recuperação enviado para {email}.', 'info')
        else:
            flash('Email não encontrado.', 'danger')
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    if user is None:
        flash('Token inválido ou expirado.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')
        
        user.password = hashed_password
        user.reset_token = None  # Limpar o token após a redefinição
        db.session.commit()
        
        flash('Senha redefinida com sucesso!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Por favor, faça login para acessar esta página', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Você foi desconectado!', 'success')
    return redirect(url_for('home'))

@app.route('/sobre')
def sobre():
    return render_template('sobre.html')

@app.route('/servicos')
def servicos():
    return render_template('servicos.html')

@app.route('/contato')
def contato():
    return render_template('contato.html')

@app.route('/schedule_appointment', methods=['POST'])
def schedule_appointment():
    # Aqui você pode adicionar lógica para salvar o agendamento no banco de dados
    flash('Seu horário foi agendado com sucesso!', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
