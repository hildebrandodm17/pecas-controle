"""
Sistema de Gestão de Estoque e Solicitação de Peças
Arquitetura: Flask + SQLAlchemy + Bootstrap
Arquivo principal completo
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
import qrcode
import io
import base64
from reportlab.lib.pagesizes import A4, landscape
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import os
import json
import csv
import tempfile
import zipfile
from functools import wraps
from sqlalchemy import func, extract, and_

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Função helper para templates
@app.template_filter('datetime')
def datetime_filter(dt):
    return dt.strftime('%d/%m/%Y %H:%M')

@app.template_filter('date')
def date_filter(dt):
    return dt.strftime('%d/%m/%Y')

# Context processor para disponibilizar data atual
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

# ============= MODELOS DO BANCO DE DADOS =============
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # master, admin, solicitante, receptor
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    company = db.relationship('Company', backref='users')

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    cnpj = db.Column(db.String(20), unique=True)
    address = db.Column(db.Text)
    contact_email = db.Column(db.String(120))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    company = db.relationship('Company', backref='locations')

class Equipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100))
    serial_number = db.Column(db.String(100))
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    location = db.relationship('Location', backref='equipments')
    company = db.relationship('Company', backref='equipments')

class Part(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    part_number = db.Column(db.String(50))
    base_code = db.Column(db.String(20), unique=True)
    category = db.Column(db.String(50))
    unit_measure = db.Column(db.String(20))  # unidade, kg, metro, etc
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    part_id = db.Column(db.Integer, db.ForeignKey('part.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    quantity = db.Column(db.Integer, default=0)
    min_quantity = db.Column(db.Integer, default=0)  # estoque mínimo
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

    part = db.relationship('Part', backref='stocks')
    company = db.relationship('Company', backref='stocks')

class PartInstance(db.Model):
    """Instâncias individuais de peças com QR Code único"""
    id = db.Column(db.Integer, primary_key=True)
    part_id = db.Column(db.Integer, db.ForeignKey('part.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    unique_code = db.Column(db.String(50), unique=True, nullable=False)  # ex: MONITOR17"001
    qr_code = db.Column(db.Text)  # QR code em base64
    status = db.Column(db.String(20), default='em_estoque')  # em_estoque, enviado, recebido
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sent_at = db.Column(db.DateTime)
    received_at = db.Column(db.DateTime)
    warranty_expires = db.Column(db.Date)

    part = db.relationship('Part', backref='instances')
    company = db.relationship('Company', backref='part_instances')

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=True)
    status = db.Column(db.String(20), default='pendente')  # pendente, enviado, recebido, cancelado
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    requester = db.relationship('User', backref='requests')
    company = db.relationship('Company', backref='requests')
    location = db.relationship('Location', backref='requests')
    equipment = db.relationship('Equipment', backref='equipment_requests')

class RequestItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    part_id = db.Column(db.Integer, db.ForeignKey('part.id'), nullable=False)
    quantity_requested = db.Column(db.Integer, nullable=False)
    quantity_sent = db.Column(db.Integer, default=0)
    quantity_received = db.Column(db.Integer, default=0)

    request = db.relationship('Request', backref='items')
    part = db.relationship('Part', backref='request_items')

class Shipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shipping_method = db.Column(db.String(200))  # modo de envio
    tracking_number = db.Column(db.String(100))
    notes = db.Column(db.Text)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)

    request = db.relationship('Request', backref='shipments')
    sender = db.relationship('User', backref='sent_shipments')

class ShipmentItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shipment_id = db.Column(db.Integer, db.ForeignKey('shipment.id'), nullable=False)
    part_instance_id = db.Column(db.Integer, db.ForeignKey('part_instance.id'), nullable=False)

    shipment = db.relationship('Shipment', backref='items')
    part_instance = db.relationship('PartInstance', backref='shipment_items')

# ============= DECORADORES PARA CONTROLE DE ACESSO =============
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                flash('Acesso negado. Você não tem permissão para acessar esta página.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def company_access_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role == 'master':
            return f(*args, **kwargs)

        # Verificar se o usuário tem acesso à empresa
        company_id = request.view_args.get('company_id') or request.args.get('company_id')
        if company_id and str(current_user.company_id) != str(company_id):
            flash('Acesso negado. Você não tem permissão para acessar dados desta empresa.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ============= UTILITÁRIOS =============
def generate_base_code(part_name):
    """Gera código base a partir do nome da peça (ex: Monitor 17 → MON17)"""
    import re

    # Remover acentos e caracteres especiais
    clean_name = part_name.upper()
    clean_name = re.sub(r'[ÀÁÂÃÄÅ]', 'A', clean_name)
    clean_name = re.sub(r'[ÈÉÊË]', 'E', clean_name)
    clean_name = re.sub(r'[ÌÍÎÏ]', 'I', clean_name)
    clean_name = re.sub(r'[ÒÓÔÕÖ]', 'O', clean_name)
    clean_name = re.sub(r'[ÙÚÛÜ]', 'U', clean_name)
    clean_name = re.sub(r'[Ç]', 'C', clean_name)

    # Extrair letras e números
    words = clean_name.split()
    code = ""

    for word in words:
        # Pegar primeiras 3 letras de cada palavra significativa
        letters = re.sub(r'[^A-Z]', '', word)
        numbers = re.sub(r'[^0-9]', '', word)

        if len(letters) >= 3:
            code += letters[:3]
        elif len(letters) > 0:
            code += letters

        if numbers:
            code += numbers

    # Limitar a 10 caracteres
    base_code = code[:10]

    # Verificar se já existe, se sim, adicionar sufixo
    counter = 1
    original_code = base_code
    while Part.query.filter_by(base_code=base_code).first():
        base_code = f"{original_code}{counter}"
        counter += 1
        if len(base_code) > 10:
            base_code = f"{original_code[:8]}{counter}"

    return base_code


def generate_instance_code(part_id):
    """Gera código incremental para instância da peça (ex: MON17001)"""
    part = Part.query.get(part_id)
    print(f"DEBUG: Buscando peça ID {part_id}")  # DEBUG

    if not part:
        print(f"DEBUG: ERRO - Peça ID {part_id} não encontrada!")  # DEBUG
        return None

    if not part.base_code:
        print(f"DEBUG: ERRO - Peça '{part.name}' não tem base_code!")  # DEBUG
        print(f"DEBUG: base_code atual: {repr(part.base_code)}")  # DEBUG
        # Tentar gerar base_code se não existir
        part.base_code = generate_base_code(part.name)
        db.session.commit()
        print(f"DEBUG: base_code gerado automaticamente: {part.base_code}")  # DEBUG

    print(f"DEBUG: Peça encontrada: '{part.name}' | base_code: '{part.base_code}'")  # DEBUG

    # Buscar último número usado para esta peça
    last_instance = PartInstance.query.filter_by(part_id=part_id) \
        .order_by(PartInstance.id.desc()) \
        .first()

    if last_instance:
        print(f"DEBUG: Última instância: {last_instance.unique_code}")  # DEBUG
        # Extrair número do último código (ex: MON17005 → 5)
        try:
            last_number = int(last_instance.unique_code[-3:])
            next_number = last_number + 1
            print(f"DEBUG: Último número: {last_number}, próximo: {next_number}")  # DEBUG
        except (ValueError, IndexError) as e:
            print(f"DEBUG: Erro ao extrair número: {e}, usando 1")  # DEBUG
            next_number = 1
    else:
        next_number = 1
        print(f"DEBUG: Primeira instância, usando número: {next_number}")  # DEBUG

    # Gerar código: BASE + número com 3 dígitos
    instance_code = f"{part.base_code}{next_number:03d}"
    print(f"DEBUG: Código gerado: {instance_code}")  # DEBUG

    # Garantir que não existe (segurança extra)
    attempts = 0
    while PartInstance.query.filter_by(unique_code=instance_code).first():
        attempts += 1
        next_number += 1
        instance_code = f"{part.base_code}{next_number:03d}"
        print(f"DEBUG: Código já existe, tentativa {attempts}: {instance_code}")  # DEBUG

        if attempts > 100:  # Evitar loop infinito
            print(f"DEBUG: ERRO - Muitas tentativas, abortando!")  # DEBUG
            return None

    print(f"DEBUG: Código final: {instance_code}")  # DEBUG
    return instance_code

def generate_qr_code(data):
    """Gera QR Code e retorna em base64"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)

    return base64.b64encode(buffer.getvalue()).decode()

# ============= ROTAS PRINCIPAIS =============
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password) and user.is_active:
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Usuário ou senha inválidos', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout realizado com sucesso', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Dados do dashboard baseados no role do usuário
    context = {
        'user': current_user,
        'companies': [],
        'requests': [],
        'pending_shipments': [],
        'stock_alerts': []
    }

    if current_user.role == 'master':
        context['companies'] = Company.query.filter_by(is_active=True).all()
        context['total_users'] = User.query.filter_by(is_active=True).count()
        context['total_parts'] = Part.query.filter_by(is_active=True).count()

    elif current_user.role in ['admin', 'receptor']:
        # Dados da empresa do usuário
        if current_user.company_id:
            context['requests'] = Request.query.filter_by(
                company_id=current_user.company_id
            ).order_by(Request.created_at.desc()).limit(10).all()

            context['stock_alerts'] = db.session.query(Stock, Part).join(Part).filter(
                Stock.company_id == current_user.company_id,
                Stock.quantity <= Stock.min_quantity
            ).all()

    elif current_user.role == 'solicitante':
        context['requests'] = Request.query.filter_by(
            requester_id=current_user.id
        ).order_by(Request.created_at.desc()).limit(10).all()

    return render_template('dashboard.html', **context)

# ============= GESTÃO DE EMPRESAS =============
@app.route('/companies')
@login_required
@role_required('master')
def manage_companies():
    companies = Company.query.filter_by(is_active=True).all()
    return render_template('companies.html', companies=companies)

@app.route('/companies/new', methods=['GET', 'POST'])
@login_required
@role_required('master')
def new_company():
    if request.method == 'POST':
        name = request.form['name']
        cnpj = request.form['cnpj']
        address = request.form['address']
        contact_email = request.form['contact_email']

        company = Company(
            name=name,
            cnpj=cnpj,
            address=address,
            contact_email=contact_email
        )

        db.session.add(company)
        db.session.commit()

        flash('Empresa criada com sucesso!', 'success')
        return redirect(url_for('manage_companies'))

    return render_template('company_form.html')

@app.route('/companies/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('master')
def edit_company(id):
    company = Company.query.get_or_404(id)

    if request.method == 'POST':
        company.name = request.form['name']
        company.cnpj = request.form['cnpj']
        company.address = request.form['address']
        company.contact_email = request.form['contact_email']

        db.session.commit()
        flash('Empresa atualizada com sucesso!', 'success')
        return redirect(url_for('manage_companies'))

    return render_template('company_form.html', company=company)

# ============= GESTÃO DE USUÁRIOS =============
@app.route('/users')
@login_required
@role_required('master', 'admin')
def manage_users():
    if current_user.role == 'master':
        users = User.query.filter_by(is_active=True).all()
        companies = Company.query.filter_by(is_active=True).all()
    else:
        users = User.query.filter_by(company_id=current_user.company_id, is_active=True).all()
        companies = [current_user.company]

    return render_template('users.html', users=users, companies=companies)

@app.route('/users/new', methods=['GET', 'POST'])
@login_required
@role_required('master', 'admin')
def new_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        company_id = request.form.get('company_id')

        # Validações
        if User.query.filter_by(username=username).first():
            flash('Nome de usuário já existe!', 'error')
            return redirect(url_for('new_user'))

        if User.query.filter_by(email=email).first():
            flash('Email já cadastrado!', 'error')
            return redirect(url_for('new_user'))

        # Verificar se admin pode criar usuário para sua empresa
        if current_user.role == 'admin' and str(company_id) != str(current_user.company_id):
            flash('Você só pode criar usuários para sua empresa!', 'error')
            return redirect(url_for('new_user'))

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=role,
            company_id=company_id if role != 'master' else None
        )

        db.session.add(user)
        db.session.commit()

        flash('Usuário criado com sucesso!', 'success')
        return redirect(url_for('manage_users'))

    companies = Company.query.filter_by(is_active=True).all() if current_user.role == 'master' else [current_user.company]
    return render_template('user_form.html', companies=companies)


# ============= ROTAS ADICIONAIS PARA USUÁRIOS =============
# Adicionar essas rotas no arquivo app.py após a função new_user()

@app.route('/users/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('master', 'admin')
def edit_user(id):
    user = User.query.get_or_404(id)

    # Verificar se admin pode editar usuário de sua empresa
    if current_user.role == 'admin' and user.company_id != current_user.company_id:
        flash('Você só pode editar usuários de sua empresa!', 'error')
        return redirect(url_for('manage_users'))

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']

        # Verificar se username/email já existem (exceto o próprio usuário)
        existing_user = User.query.filter(
            User.username == user.username,
            User.id != user.id
        ).first()
        if existing_user:
            flash('Nome de usuário já existe!', 'error')
            return redirect(url_for('edit_user', id=id))

        existing_email = User.query.filter(
            User.email == user.email,
            User.id != user.id
        ).first()
        if existing_email:
            flash('Email já cadastrado!', 'error')
            return redirect(url_for('edit_user', id=id))

        # Atualizar senha se fornecida
        new_password = request.form.get('password')
        if new_password:
            user.password_hash = generate_password_hash(new_password)

        # Atualizar empresa se master
        if current_user.role == 'master':
            company_id = request.form.get('company_id')
            user.company_id = company_id if user.role != 'master' else None

        try:
            db.session.commit()
            flash('Usuário atualizado com sucesso!', 'success')
            return redirect(url_for('manage_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar usuário: {str(e)}', 'error')

    companies = Company.query.filter_by(is_active=True).all() if current_user.role == 'master' else [
        current_user.company]
    return render_template('user_form.html', user=user, companies=companies, edit=True)


# ============= APIs PARA USUÁRIOS =============

@app.route('/api/users/<int:id>/toggle-status', methods=['POST'])
@login_required
@role_required('master', 'admin')
def api_toggle_user_status(id):
    user = User.query.get_or_404(id)

    # Verificar permissões
    if current_user.role == 'admin' and user.company_id != current_user.company_id:
        return jsonify({'success': False, 'message': 'Acesso negado'})

    # Não permitir desativar o próprio usuário
    if user.id == current_user.id:
        return jsonify({'success': False, 'message': 'Você não pode desativar sua própria conta'})

    try:
        user.is_active = not user.is_active
        db.session.commit()

        status = 'ativado' if user.is_active else 'desativado'
        return jsonify({
            'success': True,
            'message': f'Usuário {status} com sucesso',
            'new_status': user.is_active
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/users/<int:id>/reset-password', methods=['POST'])
@login_required
@role_required('master', 'admin')
def api_reset_password(id):
    user = User.query.get_or_404(id)

    # Verificar permissões
    if current_user.role == 'admin' and user.company_id != current_user.company_id:
        return jsonify({'success': False, 'message': 'Acesso negado'})

    try:
        import random
        import string

        # Gerar nova senha aleatória
        new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        user.password_hash = generate_password_hash(new_password)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Senha redefinida com sucesso',
            'new_password': new_password
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/users/<int:id>/welcome-email', methods=['POST'])
@login_required
@role_required('master', 'admin')
def api_send_welcome_email(id):
    user = User.query.get_or_404(id)

    # Verificar permissões
    if current_user.role == 'admin' and user.company_id != current_user.company_id:
        return jsonify({'success': False, 'message': 'Acesso negado'})

    try:
        # Aqui você pode implementar o envio real de email
        # Por enquanto, apenas simular

        return jsonify({
            'success': True,
            'message': f'Email de boas-vindas enviado para {user.email}'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/users/<int:id>', methods=['DELETE'])
@login_required
@role_required('master', 'admin')
def api_delete_user(id):
    user = User.query.get_or_404(id)

    # Verificar permissões
    if current_user.role == 'admin' and user.company_id != current_user.company_id:
        return jsonify({'success': False, 'message': 'Acesso negado'})

    # Não permitir excluir o próprio usuário
    if user.id == current_user.id:
        return jsonify({'success': False, 'message': 'Você não pode excluir sua própria conta'})

    # Não permitir excluir usuário master se for o último
    if user.role == 'master':
        master_count = User.query.filter_by(role='master', is_active=True).count()
        if master_count <= 1:
            return jsonify({'success': False, 'message': 'Não é possível excluir o último usuário master'})

    try:
        # Em vez de excluir, desativar o usuário para manter histórico
        user.is_active = False
        user.username = f"{user.username}_deleted_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        user.email = f"deleted_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{user.email}"

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Usuário excluído com sucesso'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


# ============= GESTÃO DE PEÇAS =============
@app.route('/parts')
@login_required
@role_required('master', 'admin', 'receptor')
def manage_parts():
    parts = Part.query.filter_by(is_active=True).all()
    return render_template('parts.html', parts=parts)

@app.route('/parts/new', methods=['GET', 'POST'])
@login_required
@role_required('master')
def new_part():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        part_number = request.form['part_number']
        category = request.form['category']
        unit_measure = request.form['unit_measure']

        # Verificar se já existe peça com mesmo nome
        existing_part = Part.query.filter_by(name=name).first()
        if existing_part:
            flash('Já existe uma peça com este nome!', 'error')
            return render_template('part_form.html')

        # Gerar código base automaticamente
        base_code = generate_base_code(name)
        print(f"DEBUG: Código gerado: {base_code} para peça: {name}")  # DEBUG

        part = Part(
            name=name,
            description=description,
            part_number=part_number,
            base_code=base_code,  # ← CRÍTICO: incluir esta linha
            category=category,
            unit_measure=unit_measure
        )

        db.session.add(part)
        db.session.commit()

        print(f"DEBUG: Peça salva com ID: {part.id} e base_code: {part.base_code}")  # DEBUG

        flash(f'Peça "{name}" cadastrada com código {base_code}!', 'success')
        return redirect(url_for('manage_parts'))

    return render_template('part_form.html')

# ============= ROTAS ADICIONAIS PARA PEÇAS =============
# Adicionar essas rotas no arquivo app.py após a função new_part()

@app.route('/parts/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('master')
def edit_part(id):
    part = Part.query.get_or_404(id)

    if request.method == 'POST':
        old_name = part.name
        part.name = request.form['name']
        part.description = request.form['description']
        part.part_number = request.form['part_number']
        part.category = request.form['category']
        part.unit_measure = request.form['unit_measure']

        # Se o nome mudou, regenerar código base
        if old_name != part.name:
            new_base_code = generate_base_code(part.name)

            # Verificar se o novo código não conflita com outra peça
            existing_part = Part.query.filter(
                Part.base_code == new_base_code,
                Part.id != part.id
            ).first()

            if not existing_part:
                part.base_code = new_base_code
                flash(f'Nome e código atualizados! Novo código: {new_base_code}', 'info')
            else:
                flash('Nome atualizado, mas código mantido para evitar conflitos.', 'warning')

        # Verificar se já existe peça com mesmo nome (exceto a própria)
        existing_part = Part.query.filter(
            Part.name == part.name,
            Part.id != part.id
        ).first()
        if existing_part:
            flash('Já existe uma peça com este nome!', 'error')
            return redirect(url_for('edit_part', id=id))

        # Verificar part_number se fornecido
        if part.part_number:
            existing_part_number = Part.query.filter(
                Part.part_number == part.part_number,
                Part.id != part.id
            ).first()
            if existing_part_number:
                flash('Já existe uma peça com este código!', 'error')
                return redirect(url_for('edit_part', id=id))

        try:
            db.session.commit()
            flash('Peça atualizada com sucesso!', 'success')
            return redirect(url_for('manage_parts'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar peça: {str(e)}', 'error')

    return render_template('part_form.html', part=part, edit=True)

@app.route('/parts/<int:id>/view')
@login_required
def view_part(id):
    part = Part.query.get_or_404(id)

    # Obter estatísticas da peça
    total_stock = 0
    total_companies = 0
    total_requests = 0
    total_sent = 0
    total_received = 0

    for stock in part.stocks:
        total_stock += stock.quantity
        total_companies += 1

    for request_item in part.request_items:
        total_requests += request_item.quantity_requested
        total_sent += request_item.quantity_sent
        total_received += request_item.quantity_received

    # Últimas movimentações
    recent_requests = db.session.query(Request, RequestItem).join(RequestItem).filter(
        RequestItem.part_id == part.id
    ).order_by(Request.created_at.desc()).limit(10).all()

    # Instâncias da peça
    instances = PartInstance.query.filter_by(part_id=part.id).order_by(PartInstance.created_at.desc()).limit(20).all()

    context = {
        'part': part,
        'total_stock': total_stock,
        'total_companies': total_companies,
        'total_requests': total_requests,
        'total_sent': total_sent,
        'total_received': total_received,
        'recent_requests': recent_requests,
        'instances': instances
    }

    return render_template('view_part.html', **context)


# ============= APIs PARA PEÇAS =============

@app.route('/api/parts/<int:id>/toggle-status', methods=['POST'])
@login_required
@role_required('master')
def api_toggle_part_status(id):
    part = Part.query.get_or_404(id)

    try:
        part.is_active = not part.is_active
        db.session.commit()

        status = 'ativada' if part.is_active else 'desativada'
        return jsonify({
            'success': True,
            'message': f'Peça {status} com sucesso',
            'new_status': part.is_active
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/parts/<int:id>/stock-summary')
@login_required
@role_required('master', 'admin', 'receptor')
def api_part_stock_summary(id):
    part = Part.query.get_or_404(id)

    stock_by_company = []
    for stock in part.stocks:
        if current_user.role == 'master' or stock.company_id == current_user.company_id:
            stock_by_company.append({
                'company_name': stock.company.name,
                'quantity': stock.quantity,
                'min_quantity': stock.min_quantity,
                'last_updated': stock.last_updated.strftime('%d/%m/%Y %H:%M'),
                'status': 'baixo' if stock.quantity <= stock.min_quantity else 'normal'
            })

    return jsonify({
        'success': True,
        'data': {
            'part_name': part.name,
            'total_stock': sum(s.quantity for s in part.stocks),
            'companies': stock_by_company
        }
    })


@app.route('/api/parts/<int:id>/usage-stats')
@login_required
@role_required('master', 'admin', 'receptor')
def api_part_usage_stats(id):
    part = Part.query.get_or_404(id)

    # Estatísticas dos últimos 6 meses
    six_months_ago = datetime.utcnow() - timedelta(days=180)

    monthly_usage = db.session.query(
        extract('year', Request.created_at).label('year'),
        extract('month', Request.created_at).label('month'),
        func.sum(RequestItem.quantity_requested).label('requested'),
        func.sum(RequestItem.quantity_sent).label('sent')
    ).join(RequestItem).filter(
        RequestItem.part_id == part.id,
        Request.created_at >= six_months_ago
    ).group_by(
        extract('year', Request.created_at),
        extract('month', Request.created_at)
    ).order_by('year', 'month').all()

    usage_data = []
    for stat in monthly_usage:
        usage_data.append({
            'period': f"{int(stat.month):02d}/{int(stat.year)}",
            'requested': int(stat.requested or 0),
            'sent': int(stat.sent or 0)
        })

    return jsonify({
        'success': True,
        'data': usage_data
    })


@app.route('/api/parts/categories')
@login_required
def api_part_categories():
    """Retorna lista de categorias existentes"""
    categories = db.session.query(Part.category).filter(
        Part.category.isnot(None),
        Part.is_active == True
    ).distinct().all()

    category_list = [cat[0] for cat in categories if cat[0]]

    # Adicionar categorias padrão se não existirem
    default_categories = ['Informática', 'Eletrônicos', 'Móveis', 'Cabos', 'Ferramentas', 'Acessórios']
    for cat in default_categories:
        if cat not in category_list:
            category_list.append(cat)

    return jsonify({
        'success': True,
        'categories': sorted(category_list)
    })


@app.route('/api/parts/search')
@login_required
def api_search_parts():
    """API para busca de peças"""
    query = request.args.get('q', '').lower()
    category = request.args.get('category', '')
    limit = int(request.args.get('limit', 10))

    parts_query = Part.query.filter(Part.is_active == True)

    if query:
        parts_query = parts_query.filter(
            db.or_(
                Part.name.ilike(f'%{query}%'),
                Part.description.ilike(f'%{query}%'),
                Part.part_number.ilike(f'%{query}%')
            )
        )

    if category:
        parts_query = parts_query.filter(Part.category == category)

    parts = parts_query.limit(limit).all()

    results = []
    for part in parts:
        total_stock = sum(stock.quantity for stock in part.stocks)
        results.append({
            'id': part.id,
            'name': part.name,
            'description': part.description,
            'part_number': part.part_number,
            'category': part.category,
            'unit_measure': part.unit_measure,
            'total_stock': total_stock
        })

    return jsonify({
        'success': True,
        'results': results
    })


# ============= ROTA PARA DUPLICAR PEÇA =============

@app.route('/parts/<int:id>/duplicate', methods=['POST'])
@login_required
@role_required('master')
def duplicate_part(id):
    original_part = Part.query.get_or_404(id)

    try:
        # Criar nova peça baseada na original
        new_part = Part(
            name=f"{original_part.name} (Cópia)",
            description=original_part.description,
            part_number=None,  # Part number deve ser único
            category=original_part.category,
            unit_measure=original_part.unit_measure
        )

        db.session.add(new_part)
        db.session.commit()

        flash(f'Peça "{new_part.name}" criada com sucesso!', 'success')
        return redirect(url_for('edit_part', id=new_part.id))

    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao duplicar peça: {str(e)}', 'error')
        return redirect(url_for('manage_parts'))


# ============= ROTA PARA HISTÓRICO DA PEÇA =============

@app.route('/parts/<int:id>/history')
@login_required
@role_required('master', 'admin', 'receptor')
def part_history(id):
    part = Part.query.get_or_404(id)

    # Histórico de solicitações
    requests_history = db.session.query(Request, RequestItem, User, Company, Location).join(
        RequestItem, Request.id == RequestItem.request_id
    ).join(
        User, Request.requester_id == User.id
    ).join(
        Company, Request.company_id == Company.id
    ).join(
        Location, Request.location_id == Location.id
    ).filter(
        RequestItem.part_id == part.id
    ).order_by(Request.created_at.desc()).all()

    # Filtrar por empresa se não for master
    if current_user.role != 'master':
        requests_history = [r for r in requests_history if r[0].company_id == current_user.company_id]

    # Histórico de movimentação de estoque
    stock_movements = []
    for stock in part.stocks:
        if current_user.role == 'master' or stock.company_id == current_user.company_id:
            # Buscar instâncias criadas para esta peça/empresa
            instances = PartInstance.query.filter_by(
                part_id=part.id,
                company_id=stock.company_id
            ).order_by(PartInstance.created_at.desc()).all()

            for instance in instances:
                stock_movements.append({
                    'date': instance.created_at,
                    'type': 'entrada',
                    'quantity': 1,
                    'company': stock.company.name,
                    'reference': instance.unique_code,
                    'status': instance.status
                })

    # Ordenar movimentações por data
    stock_movements.sort(key=lambda x: x['date'], reverse=True)

    return render_template('part_history.html',
                           part=part,
                           requests_history=requests_history,
                           stock_movements=stock_movements)
# ============= GESTÃO DE LOCAIS =============
@app.route('/locations')
@login_required
@role_required('master', 'admin')
def manage_locations():
    if current_user.role == 'master':
        locations = Location.query.filter_by(is_active=True).all()
    else:
        locations = Location.query.filter_by(company_id=current_user.company_id, is_active=True).all()

    return render_template('locations.html', locations=locations)

@app.route('/locations/new', methods=['GET', 'POST'])
@login_required
@role_required('master', 'admin')
def new_location():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        company_id = request.form.get('company_id') or current_user.company_id

        location = Location(
            name=name,
            description=description,
            company_id=company_id
        )

        db.session.add(location)
        db.session.commit()

        flash('Local cadastrado com sucesso!', 'success')
        return redirect(url_for('manage_locations'))

    companies = Company.query.filter_by(is_active=True).all() if current_user.role == 'master' else [current_user.company]
    return render_template('location_form.html', companies=companies)

# ============= GESTÃO DE EQUIPAMENTOS =============
@app.route('/equipments')
@login_required
@role_required('master', 'admin')
def manage_equipments():
    if current_user.role == 'master':
        equipments = Equipment.query.filter_by(is_active=True).all()
    else:
        equipments = Equipment.query.filter_by(company_id=current_user.company_id, is_active=True).all()

    return render_template('equipments.html', equipments=equipments)

@app.route('/equipments/new', methods=['GET', 'POST'])
@login_required
@role_required('master', 'admin')
def new_equipment():
    if request.method == 'POST':
        name = request.form['name']
        model = request.form['model']
        serial_number = request.form['serial_number']
        location_id = request.form['location_id']
        company_id = request.form.get('company_id') or current_user.company_id

        equipment = Equipment(
            name=name,
            model=model,
            serial_number=serial_number,
            location_id=location_id,
            company_id=company_id
        )

        db.session.add(equipment)
        db.session.commit()

        flash('Equipamento cadastrado com sucesso!', 'success')
        return redirect(url_for('manage_equipments'))

    if current_user.role == 'master':
        locations = Location.query.filter_by(is_active=True).all()
        companies = Company.query.filter_by(is_active=True).all()
    else:
        locations = Location.query.filter_by(company_id=current_user.company_id, is_active=True).all()
        companies = [current_user.company]

    return render_template('equipment_form.html', locations=locations, companies=companies)

# ============= SOLICITAÇÕES =============
@app.route('/requests/new', methods=['GET', 'POST'])
@login_required
@role_required('solicitante', 'admin', 'master')
def new_request():
    if request.method == 'POST':
        location_id = request.form['location_id']
        equipment_id = request.form.get('equipment_id') or None
        notes = request.form['notes']
        part_ids = request.form.getlist('part_ids')
        quantities = request.form.getlist('quantities')

        # ✅ CORREÇÃO: Determinar company_id corretamente
        if current_user.role == 'master':
            # Master precisa escolher a empresa
            company_id = request.form.get('company_id')
            if not company_id:
                flash('Masters devem selecionar uma empresa para a solicitação!', 'error')
                return redirect(url_for('new_request'))
        else:
            # Outros usuários usam sua empresa
            company_id = current_user.company_id
            if not company_id:
                flash('Seu usuário não possui empresa associada. Contate o administrador!', 'error')
                return redirect(url_for('dashboard'))

        print(f"DEBUG: Criando solicitação - User: {current_user.username}, Company: {company_id}")  # DEBUG

        # Criar a solicitação
        new_req = Request(
            requester_id=current_user.id,
            company_id=int(company_id),  # ✅ Garantir que é int
            location_id=int(location_id),
            equipment_id=int(equipment_id) if equipment_id else None,
            notes=notes
        )

        db.session.add(new_req)
        db.session.flush()  # Para obter o ID

        # Adicionar itens da solicitação
        for i, part_id in enumerate(part_ids):
            if part_id and quantities[i]:
                item = RequestItem(
                    request_id=new_req.id,
                    part_id=int(part_id),
                    quantity_requested=int(quantities[i])
                )
                db.session.add(item)

        db.session.commit()

        flash('Solicitação criada com sucesso!', 'success')
        return redirect(url_for('my_requests'))

    # ✅ Obter dados para o formulário
    if current_user.role == 'master':
        companies = Company.query.filter_by(is_active=True).all()
        locations = Location.query.filter_by(is_active=True).all()
        equipments = Equipment.query.filter_by(is_active=True).all()
    else:
        companies = [current_user.company] if current_user.company else []
        if not companies:
            flash('Seu usuário não possui empresa associada. Contate o administrador!', 'error')
            return redirect(url_for('dashboard'))
        locations = Location.query.filter_by(company_id=current_user.company_id, is_active=True).all()
        equipments = Equipment.query.filter_by(company_id=current_user.company_id, is_active=True).all()

    parts = Part.query.filter_by(is_active=True).all()

    return render_template('request_form.html',
                           locations=locations,
                           equipments=equipments,
                           parts=parts,
                           companies=companies)  # ✅ Passar companies para o template
@app.route('/requests/mine')
@login_required
def my_requests():
    if current_user.role == 'master':
        requests = Request.query.order_by(Request.created_at.desc()).all()
    elif current_user.role == 'admin':
        requests = Request.query.filter_by(company_id=current_user.company_id).order_by(Request.created_at.desc()).all()
    else:
        requests = Request.query.filter_by(requester_id=current_user.id).order_by(Request.created_at.desc()).all()

    return render_template('my_requests.html', requests=requests)

@app.route('/requests/<int:id>')
@login_required
def view_request(id):
    req = Request.query.get_or_404(id)

    # Verificar permissão
    if (current_user.role not in ['master', 'admin'] and
        req.requester_id != current_user.id and
        req.company_id != current_user.company_id):
        flash('Acesso negado!', 'error')
        return redirect(url_for('dashboard'))

    return render_template('view_request.html', request=req)

@app.route('/requests/pending')
@login_required
@role_required('receptor', 'admin', 'master')
def pending_requests():
    if current_user.role == 'master':
        requests = Request.query.filter_by(status='pendente').order_by(Request.created_at.desc()).all()
    else:
        requests = Request.query.filter_by(
            company_id=current_user.company_id,
            status='pendente'
        ).order_by(Request.created_at.desc()).all()

    return render_template('pending_requests.html', requests=requests)

# ============= GESTÃO DE ESTOQUE =============
@app.route('/stock')
@login_required
@role_required('receptor', 'admin', 'master')
def manage_stock():
    if current_user.role == 'master':
        company_id = request.args.get('company_id')
        if company_id:
            stocks = db.session.query(Stock, Part).join(Part).filter(Stock.company_id==company_id).all()
            company = Company.query.get(company_id)
        else:
            stocks = db.session.query(Stock, Part).join(Part).all()
            company = None
        companies = Company.query.filter_by(is_active=True).all()
    else:
        stocks = db.session.query(Stock, Part).join(Part).filter(Stock.company_id==current_user.company_id).all()
        company = current_user.company
        companies = [company]

    parts = Part.query.filter_by(is_active=True).all()

    return render_template('stock.html', stocks=stocks, parts=parts, companies=companies, current_company=company)


# ============= CORREÇÃO DA FUNÇÃO ADD_STOCK =============
# Substituir a função add_stock existente por esta versão corrigida

@app.route('/stock/add', methods=['POST'])
@login_required
@role_required('receptor', 'admin', 'master')
def add_stock():
    try:
        part_id = int(request.form['part_id'])
        quantity = int(request.form['quantity'])
        company_id = int(request.form.get('company_id') or current_user.company_id)

        print(f"DEBUG: Adicionando estoque - Part ID: {part_id}, Quantity: {quantity}, Company: {company_id}")

        # Validações
        if quantity <= 0:
            flash('Quantidade deve ser maior que zero!', 'error')
            return redirect(url_for('manage_stock'))

        if quantity > 1000:
            flash('Quantidade muito alta! Máximo 1000 unidades por vez.', 'error')
            return redirect(url_for('manage_stock'))

        # Verificar se a peça existe
        part = Part.query.get(part_id)
        if not part:
            flash('Peça não encontrada!', 'error')
            return redirect(url_for('manage_stock'))

        print(f"DEBUG: Peça encontrada: {part.name} | base_code: {part.base_code}")

        # Garantir que a peça tem base_code
        if not part.base_code:
            print(f"DEBUG: Gerando base_code para peça {part.name}")
            part.base_code = generate_base_code(part.name)
            db.session.commit()
            print(f"DEBUG: base_code gerado: {part.base_code}")

        # Verificar se já existe estoque para esta peça/empresa
        stock = Stock.query.filter_by(part_id=part_id, company_id=company_id).first()

        if stock:
            print(f"DEBUG: Estoque existente encontrado: {stock.quantity}")
            stock.quantity += quantity
            stock.last_updated = datetime.utcnow()
        else:
            print(f"DEBUG: Criando novo registro de estoque")
            stock = Stock(
                part_id=part_id,
                company_id=company_id,
                quantity=quantity
            )
            db.session.add(stock)

        # Commit do estoque primeiro
        db.session.commit()
        print(f"DEBUG: Estoque atualizado. Novo total: {stock.quantity}")

        # Criar instâncias individuais com códigos incrementais
        created_codes = []
        failed_codes = []

        for i in range(quantity):
            print(f"DEBUG: Criando instância {i + 1}/{quantity}")

            # Gerar código incremental único
            unique_code = generate_instance_code(part_id)
            print(f"DEBUG: Código gerado: {unique_code}")

            if unique_code:
                try:
                    # Dados para o QR code
                    qr_data = {
                        'part_id': part_id,
                        'company_id': company_id,
                        'unique_code': unique_code,
                        'part_name': part.name,
                        'base_code': part.base_code
                    }
                    qr_code_b64 = generate_qr_code(json.dumps(qr_data))

                    instance = PartInstance(
                        part_id=part_id,
                        company_id=company_id,
                        unique_code=unique_code,
                        qr_code=qr_code_b64,
                        status='em_estoque'
                    )
                    db.session.add(instance)
                    created_codes.append(unique_code)
                    print(f"DEBUG: Instância criada: {unique_code}")

                except Exception as e:
                    print(f"DEBUG: Erro ao criar instância {unique_code}: {e}")
                    failed_codes.append(f"Erro: {e}")
            else:
                print(f"DEBUG: FALHOU ao gerar código para instância {i + 1}")
                failed_codes.append(f"Instância {i + 1}")

        # Commit das instâncias
        try:
            db.session.commit()
            print(f"DEBUG: {len(created_codes)} instâncias salvas com sucesso")
        except Exception as e:
            print(f"DEBUG: ERRO ao salvar instâncias: {e}")
            db.session.rollback()
            flash(f'Erro ao criar instâncias: {str(e)}', 'error')
            return redirect(url_for('manage_stock'))

        # Mensagem de sucesso
        success_msg = f'{quantity} unidades de "{part.name}" adicionadas ao estoque!'

        if created_codes:
            codes_preview = ", ".join(created_codes[:3])
            if len(created_codes) > 3:
                codes_preview += f" e mais {len(created_codes) - 3}"
            success_msg += f' Códigos criados: {codes_preview}'

        if failed_codes:
            success_msg += f" | {len(failed_codes)} instâncias falharam"

        flash(success_msg, 'success')

        if failed_codes:
            flash(f'Algumas instâncias falharam: {", ".join(failed_codes[:5])}', 'warning')

        return redirect(url_for('manage_stock'))

    except ValueError as e:
        print(f"DEBUG: Erro de valor: {e}")
        flash('Dados inválidos fornecidos!', 'error')
    except Exception as e:
        print(f"DEBUG: Erro geral: {e}")
        db.session.rollback()
        flash(f'Erro ao adicionar estoque: {str(e)}', 'error')

    return redirect(url_for('manage_stock'))


# ============= FUNÇÃO AUXILIAR MELHORADA =============
# Substituir a função generate_instance_code por esta versão melhorada

def generate_instance_code(part_id):
    """Gera código incremental para instância da peça (ex: MON17001) - Versão melhorada"""
    try:
        part = Part.query.get(part_id)
        print(f"DEBUG generate_instance_code: Buscando peça ID {part_id}")

        if not part:
            print(f"DEBUG: ERRO - Peça ID {part_id} não encontrada!")
            return None

        # Garantir que há base_code
        if not part.base_code:
            print(f"DEBUG: base_code vazio para peça '{part.name}', gerando...")
            part.base_code = generate_base_code(part.name)
            db.session.commit()
            print(f"DEBUG: base_code gerado: {part.base_code}")

        print(f"DEBUG: Peça encontrada: '{part.name}' | base_code: '{part.base_code}'")

        # Buscar último número usado para esta peça (método mais robusto)
        last_instance = PartInstance.query.filter_by(part_id=part_id) \
            .filter(PartInstance.unique_code.like(f'{part.base_code}%')) \
            .order_by(PartInstance.id.desc()) \
            .first()

        next_number = 1
        if last_instance:
            print(f"DEBUG: Última instância encontrada: {last_instance.unique_code}")
            try:
                # Extrair número do código (pegar os últimos dígitos)
                code_suffix = last_instance.unique_code.replace(part.base_code, '')
                if code_suffix.isdigit():
                    last_number = int(code_suffix)
                    next_number = last_number + 1
                    print(f"DEBUG: Último número extraído: {last_number}, próximo: {next_number}")
                else:
                    # Se não conseguir extrair, buscar próximo número disponível
                    next_number = _find_next_available_number(part.base_code, part_id)
                    print(f"DEBUG: Número não pôde ser extraído, usando próximo disponível: {next_number}")
            except Exception as e:
                print(f"DEBUG: Erro ao extrair número: {e}, usando 1")
                next_number = 1
        else:
            print(f"DEBUG: Primeira instância para esta peça, usando número: {next_number}")

        # Gerar código com tentativas de fallback
        max_attempts = 100
        for attempt in range(max_attempts):
            instance_code = f"{part.base_code}{next_number:03d}"

            # Verificar se já existe
            existing = PartInstance.query.filter_by(unique_code=instance_code).first()
            if not existing:
                print(f"DEBUG: Código único encontrado: {instance_code}")
                return instance_code

            print(f"DEBUG: Código {instance_code} já existe, tentando próximo...")
            next_number += 1

        print(f"DEBUG: ERRO - Não foi possível gerar código único após {max_attempts} tentativas!")
        return None

    except Exception as e:
        print(f"DEBUG: ERRO na generate_instance_code: {e}")
        return None


def _find_next_available_number(base_code, part_id):
    """Encontra o próximo número disponível para o código base"""
    try:
        # Buscar todos os códigos existentes para esta peça
        existing_codes = db.session.query(PartInstance.unique_code).filter_by(part_id=part_id).all()
        existing_numbers = []

        for code_tuple in existing_codes:
            code = code_tuple[0]
            suffix = code.replace(base_code, '')
            if suffix.isdigit():
                existing_numbers.append(int(suffix))

        if not existing_numbers:
            return 1

        # Encontrar o primeiro gap ou retornar o próximo após o maior
        existing_numbers.sort()

        for i, num in enumerate(existing_numbers):
            expected = i + 1
            if num != expected:
                return expected

        return existing_numbers[-1] + 1

    except Exception as e:
        print(f"DEBUG: Erro em _find_next_available_number: {e}")
        return 1


# ============= ROTA DE DEBUG PARA TESTAR GERAÇÃO =============
@app.route('/debug/test-instance-generation/<int:part_id>')
@login_required
@role_required('master')
def debug_test_instance_generation(part_id):
    """Rota de debug para testar geração de códigos"""
    try:
        part = Part.query.get_or_404(part_id)

        # Testar geração de 5 códigos
        test_codes = []
        for i in range(5):
            code = generate_instance_code(part_id)
            test_codes.append(code)

        return jsonify({
            'success': True,
            'part_name': part.name,
            'base_code': part.base_code,
            'generated_codes': test_codes,
            'existing_instances': [inst.unique_code for inst in part.instances]
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
# ============= ENVIO DE PEÇAS =============
@app.route('/requests/<int:id>/ship', methods=['GET', 'POST'])
@login_required
@role_required('receptor', 'admin', 'master')
def ship_request(id):
    req = Request.query.get_or_404(id)

    if request.method == 'POST':
        shipping_method = request.form['shipping_method']
        tracking_number = request.form.get('tracking_number', '')
        notes = request.form.get('notes', '')

        # Criar envio
        shipment = Shipment(
            request_id=req.id,
            sender_id=current_user.id,
            shipping_method=shipping_method,
            tracking_number=tracking_number,
            notes=notes
        )
        db.session.add(shipment)
        db.session.flush()

        # Processar itens enviados
        for item in req.items:
            part_instances = request.form.getlist(f'instances_{item.id}')
            quantity_sent = len(part_instances)

            if quantity_sent > 0:
                item.quantity_sent += quantity_sent

                # Adicionar instâncias ao envio
                for instance_id in part_instances:
                    shipment_item = ShipmentItem(
                        shipment_id=shipment.id,
                        part_instance_id=int(instance_id)
                    )
                    db.session.add(shipment_item)

                    # Atualizar status da instância
                    instance = PartInstance.query.get(instance_id)
                    instance.status = 'enviado'
                    instance.sent_at = datetime.utcnow()

                # Reduzir estoque
                stock = Stock.query.filter_by(
                    part_id=item.part_id,
                    company_id=current_user.company_id
                ).first()
                if stock:
                    stock.quantity -= quantity_sent
                    stock.last_updated = datetime.utcnow()

        # Atualizar status da solicitação
        req.status = 'enviado'

        db.session.commit()

        flash('Peças enviadas com sucesso!', 'success')
        return redirect(url_for('pending_requests'))

    # Obter instâncias disponíveis para envio
    available_instances = {}
    for item in req.items:
        instances = PartInstance.query.filter_by(
            part_id=item.part_id,
            company_id=current_user.company_id,
            status='em_estoque'
        ).limit(item.quantity_requested - item.quantity_sent).all()
        available_instances[item.id] = instances

    return render_template('ship_request.html', request=req, available_instances=available_instances)

# ============= GERAÇÃO DE QR CODES =============
@app.route('/qrcodes')
@login_required
@role_required('receptor', 'admin', 'master')
def generate_qr_codes():
    if current_user.role == 'master':
        company_id = request.args.get('company_id') or '1'
        companies = Company.query.filter_by(is_active=True).all()
    else:
        company_id = current_user.company_id
        companies = [current_user.company]

    instances = PartInstance.query.filter_by(
        company_id=company_id,
        status='em_estoque'
    ).join(Part).all()

    return render_template('qr_codes.html', instances=instances, companies=companies, current_company_id=int(company_id))

@app.route('/qrcodes/download/<int:company_id>')
@login_required
@role_required('receptor', 'admin', 'master')
def download_qr_codes(company_id):
    # Criar PDF com QR codes
    instances = PartInstance.query.filter_by(
        company_id=company_id,
        status='em_estoque'
    ).join(Part).all()

    if not instances:
        flash('Nenhuma instância encontrada para gerar QR codes!', 'error')
        return redirect(url_for('generate_qr_codes'))

    # Gerar PDF temporário
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    c = canvas.Canvas(temp_file.name, pagesize=A4)

    # Configurações da página
    width, height = A4
    cols = 3
    rows = 8
    cell_width = width / cols
    cell_height = height / rows

    x_offset = 20
    y_offset = 20
    current_col = 0
    current_row = 0

    for instance in instances:
        # Calcular posição
        x = x_offset + (current_col * cell_width)
        y = height - y_offset - ((current_row + 1) * cell_height)

        # Desenhar QR code (simulação - em produção, usar biblioteca de QR)
        c.rect(x, y + 40, 80, 80)  # Placeholder para QR code

        # Texto da peça
        c.drawString(x, y + 30, f"{instance.part.name}")
        c.drawString(x, y + 15, f"{instance.unique_code}")

        current_col += 1
        if current_col >= cols:
            current_col = 0
            current_row += 1

        if current_row >= rows:
            c.showPage()
            current_row = 0

    c.save()
    temp_file.close()

    return send_file(temp_file.name, as_attachment=True, download_name=f'qr_codes_empresa_{company_id}.pdf')

# ============= RELATÓRIOS =============
@app.route('/reports')
@login_required
@role_required('admin', 'master', 'receptor')
def reports():
    if current_user.role == 'master':
        companies = Company.query.filter_by(is_active=True).all()
        company_id = request.args.get('company_id')
    else:
        companies = [current_user.company]
        company_id = current_user.company_id

    # Filtros de data
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    report_type = request.args.get('report_type', 'summary')

    context = {
        'companies': companies,
        'current_company_id': int(company_id) if company_id else None,
        'start_date': start_date,
        'end_date': end_date,
        'report_type': report_type
    }

    if company_id and start_date and end_date:
        start = datetime.strptime(start_date, '%Y-%m-%d')
        end = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)

        # Relatório por tipo
        if report_type == 'requests_by_requester':
            context['report_data'] = get_requests_by_requester_report(company_id, start, end)
        elif report_type == 'requests_by_location':
            context['report_data'] = get_requests_by_location_report(company_id, start, end)
        elif report_type == 'parts_movement':
            context['report_data'] = get_parts_movement_report(company_id, start, end)
        elif report_type == 'stock_status':
            context['report_data'] = get_stock_status_report(company_id)
        else:
            context['report_data'] = get_summary_report(company_id, start, end)

    return render_template('reports.html', **context)

def get_summary_report(company_id, start_date, end_date):
    """Relatório resumo do período"""
    # Total de solicitações
    total_requests = Request.query.filter(
        Request.company_id == company_id,
        Request.created_at.between(start_date, end_date)
    ).count()

    # Solicitações por status
    status_data = db.session.query(
        Request.status,
        func.count(Request.id).label('count')
    ).filter(
        Request.company_id == company_id,
        Request.created_at.between(start_date, end_date)
    ).group_by(Request.status).all()

    # Peças mais solicitadas
    most_requested = db.session.query(
        Part.name,
        func.sum(RequestItem.quantity_requested).label('total_requested')
    ).join(RequestItem).join(Request).filter(
        Request.company_id == company_id,
        Request.created_at.between(start_date, end_date)
    ).group_by(Part.id).order_by(func.sum(RequestItem.quantity_requested).desc()).limit(10).all()

    # Solicitantes mais ativos
    top_requesters = db.session.query(
        User.username,
        func.count(Request.id).label('total_requests')
    ).join(Request).filter(
        Request.company_id == company_id,
        Request.created_at.between(start_date, end_date)
    ).group_by(User.id).order_by(func.count(Request.id).desc()).limit(10).all()

    return {
        'total_requests': total_requests,
        'status_data': status_data,
        'most_requested': most_requested,
        'top_requesters': top_requesters
    }

def get_requests_by_requester_report(company_id, start_date, end_date):
    """Relatório de solicitações por requisitante"""
    return db.session.query(
        User.username,
        User.email,
        func.count(Request.id).label('total_requests'),
        func.count(func.nullif(Request.status, 'pendente')).label('processed_requests'),
        func.sum(RequestItem.quantity_requested).label('total_items')
    ).join(Request).join(RequestItem).filter(
        Request.company_id == company_id,
        Request.created_at.between(start_date, end_date)
    ).group_by(User.id).order_by(func.count(Request.id).desc()).all()

def get_requests_by_location_report(company_id, start_date, end_date):
    """Relatório de solicitações por local"""
    return db.session.query(
        Location.name,
        func.count(Request.id).label('total_requests'),
        func.sum(RequestItem.quantity_requested).label('total_items'),
        func.avg(RequestItem.quantity_requested).label('avg_items')
    ).join(Request).join(RequestItem).filter(
        Request.company_id == company_id,
        Request.created_at.between(start_date, end_date)
    ).group_by(Location.id).order_by(func.count(Request.id).desc()).all()

def get_parts_movement_report(company_id, start_date, end_date):
    """Relatório de movimentação de peças"""
    return db.session.query(
        Part.name,
        Part.part_number,
        func.sum(RequestItem.quantity_requested).label('requested'),
        func.sum(RequestItem.quantity_sent).label('sent'),
        func.sum(RequestItem.quantity_received).label('received')
    ).join(RequestItem).join(Request).filter(
        Request.company_id == company_id,
        Request.created_at.between(start_date, end_date)
    ).group_by(Part.id).order_by(func.sum(RequestItem.quantity_requested).desc()).all()

def get_stock_status_report(company_id):
    """Relatório de status do estoque atual"""
    return db.session.query(
        Part.name,
        Part.category,
        Stock.quantity,
        Stock.min_quantity,
        func.count(PartInstance.id).label('total_instances'),
        func.sum(func.case([(PartInstance.status == 'em_estoque', 1)], else_=0)).label('available_instances'),
        func.sum(func.case([(PartInstance.status == 'enviado', 1)], else_=0)).label('sent_instances')
    ).join(Stock).outerjoin(PartInstance).filter(
        Stock.company_id == company_id
    ).group_by(Part.id).all()

# ============= API ROUTES =============
@app.route('/api/locations/<int:company_id>')
@login_required
def api_locations(company_id):
    locations = Location.query.filter_by(company_id=company_id, is_active=True).all()
    return jsonify([{'id': l.id, 'name': l.name} for l in locations])

@app.route('/api/equipments/<int:location_id>')
@login_required
def api_equipments(location_id):
    equipments = Equipment.query.filter_by(location_id=location_id, is_active=True).all()
    return jsonify([{'id': e.id, 'name': e.name} for e in equipments])

@app.route('/api/requests/<int:id>/receive', methods=['POST'])
@login_required
@role_required('receptor', 'admin', 'master')
def api_receive_request(id):
    req = Request.query.get_or_404(id)

    try:
        # Atualizar status da solicitação
        req.status = 'recebido'

        # Atualizar instâncias para recebidas
        for shipment in req.shipments:
            for item in shipment.items:
                item.part_instance.status = 'recebido'
                item.part_instance.received_at = datetime.utcnow()

        # Atualizar quantidades recebidas nos itens
        for item in req.items:
            item.quantity_received = item.quantity_sent

        db.session.commit()

        return jsonify({'success': True, 'message': 'Solicitação marcada como recebida'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/stock/<int:id>/min', methods=['PUT'])
@login_required
@role_required('receptor', 'admin', 'master')
def api_update_min_stock(id):
    stock = Stock.query.get_or_404(id)

    try:
        data = request.get_json()
        stock.min_quantity = int(data['min_quantity'])
        stock.last_updated = datetime.utcnow()

        db.session.commit()

        return jsonify({'success': True, 'message': 'Estoque mínimo atualizado'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/qr/scan', methods=['POST'])
@login_required
def api_qr_scan():
    """API para leitura de QR Code via câmera"""
    try:
        data = request.get_json()
        qr_content = data.get('qr_content')

        # Decodificar QR code
        qr_data = json.loads(qr_content)

        # Buscar instância
        instance = PartInstance.query.filter_by(
            unique_code=qr_data['unique_code']
        ).first()

        if not instance:
            return jsonify({
                'success': False,
                'message': 'QR Code não encontrado no sistema'
            })

        return jsonify({
            'success': True,
            'data': {
                'part_name': instance.part.name,
                'unique_code': instance.unique_code,
                'status': instance.status,
                'company': instance.company.name,
                'created_at': instance.created_at.strftime('%d/%m/%Y'),
                'part_id': instance.part_id,
                'instance_id': instance.id
            }
        })

    except json.JSONDecodeError:
        return jsonify({
            'success': False,
            'message': 'QR Code inválido - formato não reconhecido'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro ao processar QR Code: {str(e)}'
        })


# ============= APIs FALTANTES PARA O SISTEMA DE ENVIO =============
# Adicionar essas rotas no arquivo app.py após as outras APIs

@app.route('/api/parts/<int:part_id>/instances')
@login_required
@role_required('receptor', 'admin', 'master')
def api_part_instances(part_id):
    """Retorna instâncias disponíveis de uma peça para envio"""
    try:
        # Filtrar por empresa se não for master
        if current_user.role == 'master':
            company_id = request.args.get('company_id')
            if not company_id:
                return jsonify({'success': False, 'message': 'Company ID é obrigatório para usuários master'})
        else:
            company_id = current_user.company_id

        # Buscar instâncias disponíveis
        instances = PartInstance.query.filter_by(
            part_id=part_id,
            company_id=company_id,
            status='em_estoque'
        ).join(Part).all()

        instances_data = []
        for instance in instances:
            instances_data.append({
                'id': instance.id,
                'unique_code': instance.unique_code,
                'created_at': instance.created_at.strftime('%d/%m/%Y %H:%M'),
                'warranty_expires': instance.warranty_expires.strftime(
                    '%d/%m/%Y') if instance.warranty_expires else None,
                'part_name': instance.part.name
            })

        return jsonify({
            'success': True,
            'instances': instances_data,
            'total': len(instances_data)
        })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/requests/<int:request_id>/available-instances')
@login_required
@role_required('receptor', 'admin', 'master')
def api_request_available_instances(request_id):
    """Retorna todas as instâncias disponíveis para itens de uma solicitação"""
    try:
        req = Request.query.get_or_404(request_id)

        # Verificar permissão
        if current_user.role != 'master' and req.company_id != current_user.company_id:
            return jsonify({'success': False, 'message': 'Acesso negado'})

        available_instances = {}

        for item in req.items:
            # Calcular quantas instâncias ainda precisam ser enviadas
            quantity_needed = item.quantity_requested - item.quantity_sent

            if quantity_needed > 0:
                instances = PartInstance.query.filter_by(
                    part_id=item.part_id,
                    company_id=current_user.company_id if current_user.role != 'master' else req.company_id,
                    status='em_estoque'
                ).limit(quantity_needed).all()

                instances_data = []
                for instance in instances:
                    instances_data.append({
                        'id': instance.id,
                        'unique_code': instance.unique_code,
                        'created_at': instance.created_at.strftime('%d/%m/%Y %H:%M'),
                        'warranty_expires': instance.warranty_expires.strftime(
                            '%d/%m/%Y') if instance.warranty_expires else None
                    })

                available_instances[item.id] = {
                    'part_name': item.part.name,
                    'quantity_requested': item.quantity_requested,
                    'quantity_sent': item.quantity_sent,
                    'quantity_needed': quantity_needed,
                    'instances': instances_data
                }

        return jsonify({
            'success': True,
            'request_id': request_id,
            'available_instances': available_instances
        })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/stock/summary')
@login_required
@role_required('receptor', 'admin', 'master')
def api_stock_summary():
    """Retorna resumo do estoque atual"""
    try:
        if current_user.role == 'master':
            company_id = request.args.get('company_id')
            if not company_id:
                # Retornar resumo de todas as empresas
                stocks = db.session.query(
                    Company.name.label('company_name'),
                    Part.name.label('part_name'),
                    Stock.quantity,
                    Stock.min_quantity,
                    func.count(PartInstance.id).label('total_instances')
                ).join(Stock, Company.id == Stock.company_id) \
                    .join(Part, Stock.part_id == Part.id) \
                    .outerjoin(PartInstance, and_(
                    PartInstance.part_id == Part.id,
                    PartInstance.company_id == Company.id
                )).group_by(Company.id, Part.id).all()
            else:
                stocks = db.session.query(
                    Part.name.label('part_name'),
                    Stock.quantity,
                    Stock.min_quantity,
                    func.count(PartInstance.id).label('total_instances')
                ).join(Part).outerjoin(PartInstance, and_(
                    PartInstance.part_id == Part.id,
                    PartInstance.company_id == Stock.company_id
                )).filter(Stock.company_id == company_id) \
                    .group_by(Part.id).all()
        else:
            stocks = db.session.query(
                Part.name.label('part_name'),
                Stock.quantity,
                Stock.min_quantity,
                func.count(PartInstance.id).label('total_instances')
            ).join(Part).outerjoin(PartInstance, and_(
                PartInstance.part_id == Part.id,
                PartInstance.company_id == Stock.company_id
            )).filter(Stock.company_id == current_user.company_id) \
                .group_by(Part.id).all()

        stock_data = []
        for stock in stocks:
            stock_info = {
                'part_name': stock.part_name,
                'quantity': stock.quantity,
                'min_quantity': stock.min_quantity,
                'total_instances': stock.total_instances or 0,
                'status': 'baixo' if stock.quantity <= stock.min_quantity else 'normal'
            }

            if current_user.role == 'master' and hasattr(stock, 'company_name'):
                stock_info['company_name'] = stock.company_name

            stock_data.append(stock_info)

        return jsonify({
            'success': True,
            'stock_data': stock_data,
            'total_items': len(stock_data)
        })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/parts/<int:part_id>/generate-instances', methods=['POST'])
@login_required
@role_required('receptor', 'admin', 'master')
def api_generate_part_instances(part_id):
    """Gera instâncias adicionais para uma peça existente no estoque"""
    try:
        data = request.get_json()
        quantity = int(data.get('quantity', 1))
        company_id = data.get('company_id') or current_user.company_id

        if quantity <= 0 or quantity > 100:
            return jsonify({'success': False, 'message': 'Quantidade deve ser entre 1 e 100'})

        # Verificar se a peça existe
        part = Part.query.get_or_404(part_id)

        # Verificar se existe estoque para esta peça/empresa
        stock = Stock.query.filter_by(part_id=part_id, company_id=company_id).first()
        if not stock:
            return jsonify({'success': False, 'message': 'Não existe estoque cadastrado para esta peça'})

        # Verificar se há estoque suficiente sem instâncias
        existing_instances = PartInstance.query.filter_by(
            part_id=part_id,
            company_id=company_id
        ).count()

        if existing_instances >= stock.quantity:
            return jsonify(
                {'success': False, 'message': 'Todas as unidades do estoque já possuem instâncias individuais'})

        # Limitar quantidade às unidades faltantes
        max_quantity = stock.quantity - existing_instances
        if quantity > max_quantity:
            quantity = max_quantity

        # Gerar instâncias
        created_codes = []
        for i in range(quantity):
            unique_code = generate_instance_code(part_id)
            if unique_code:
                # Dados para o QR code
                qr_data = {
                    'part_id': part_id,
                    'company_id': company_id,
                    'unique_code': unique_code,
                    'part_name': part.name,
                    'base_code': part.base_code
                }
                qr_code_b64 = generate_qr_code(json.dumps(qr_data))

                instance = PartInstance(
                    part_id=part_id,
                    company_id=company_id,
                    unique_code=unique_code,
                    qr_code=qr_code_b64
                )
                db.session.add(instance)
                created_codes.append(unique_code)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'{len(created_codes)} instâncias criadas com sucesso',
            'created_codes': created_codes,
            'part_name': part.name
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/instances/<int:instance_id>/update-status', methods=['PUT'])
@login_required
@role_required('receptor', 'admin', 'master')
def api_update_instance_status(instance_id):
    """Atualiza status de uma instância específica"""
    try:
        instance = PartInstance.query.get_or_404(instance_id)

        # Verificar permissão
        if current_user.role != 'master' and instance.company_id != current_user.company_id:
            return jsonify({'success': False, 'message': 'Acesso negado'})

        data = request.get_json()
        new_status = data.get('status')

        valid_statuses = ['em_estoque', 'enviado', 'recebido', 'danificado', 'perdido']
        if new_status not in valid_statuses:
            return jsonify({'success': False, 'message': 'Status inválido'})

        # Atualizar status
        old_status = instance.status
        instance.status = new_status

        # Atualizar timestamps conforme necessário
        if new_status == 'enviado' and old_status != 'enviado':
            instance.sent_at = datetime.utcnow()
        elif new_status == 'recebido' and old_status != 'recebido':
            instance.received_at = datetime.utcnow()

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Status atualizado de "{old_status}" para "{new_status}"',
            'old_status': old_status,
            'new_status': new_status,
            'instance_code': instance.unique_code
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/debug/part-instances/<int:part_id>')
@login_required
@role_required('master')  # Apenas para debug, restringir ao master
def api_debug_part_instances(part_id):
    """API de debug para verificar instâncias de uma peça"""
    try:
        part = Part.query.get_or_404(part_id)

        instances = PartInstance.query.filter_by(part_id=part_id).all()
        stocks = Stock.query.filter_by(part_id=part_id).all()

        debug_data = {
            'part_info': {
                'id': part.id,
                'name': part.name,
                'base_code': part.base_code
            },
            'instances': [],
            'stocks': [],
            'total_instances': len(instances),
            'total_stock_quantity': sum(s.quantity for s in stocks)
        }

        for instance in instances:
            debug_data['instances'].append({
                'id': instance.id,
                'unique_code': instance.unique_code,
                'status': instance.status,
                'company_id': instance.company_id,
                'created_at': instance.created_at.isoformat()
            })

        for stock in stocks:
            debug_data['stocks'].append({
                'company_id': stock.company_id,
                'company_name': stock.company.name,
                'quantity': stock.quantity,
                'min_quantity': stock.min_quantity
            })

        return jsonify({
            'success': True,
            'debug_data': debug_data
        })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/admin/diagnostics')
@login_required
@role_required('master', 'admin')
def system_diagnostics():
    """Página de diagnósticos do sistema"""
    try:
        diagnostics = {}

        # Verificar peças sem base_code
        parts_without_base_code = Part.query.filter(
            db.or_(Part.base_code.is_(None), Part.base_code == '')
        ).all()

        # Verificar estoque sem instâncias
        stocks_without_instances = []
        for stock in Stock.query.all():
            instance_count = PartInstance.query.filter_by(
                part_id=stock.part_id,
                company_id=stock.company_id
            ).count()
            if stock.quantity > instance_count:
                stocks_without_instances.append({
                    'stock': stock,
                    'missing_instances': stock.quantity - instance_count
                })

        # Verificar instâncias órfãs
        orphan_instances = PartInstance.query.filter(
            ~PartInstance.part_id.in_(db.session.query(Part.id))
        ).all()

        # Verificar duplicatas de códigos
        duplicate_codes = db.session.query(
            PartInstance.unique_code,
            func.count(PartInstance.id).label('count')
        ).group_by(PartInstance.unique_code).having(
            func.count(PartInstance.id) > 1
        ).all()

        # Verificar solicitações pendentes sem instâncias disponíveis
        problematic_requests = []
        pending_requests = Request.query.filter_by(status='pendente').all()

        for req in pending_requests:
            for item in req.items:
                needed = item.quantity_requested - item.quantity_sent
                if needed > 0:
                    available = PartInstance.query.filter_by(
                        part_id=item.part_id,
                        company_id=req.company_id,
                        status='em_estoque'
                    ).count()

                    if available < needed:
                        problematic_requests.append({
                            'request': req,
                            'item': item,
                            'needed': needed,
                            'available': available
                        })

        diagnostics = {
            'parts_without_base_code': parts_without_base_code,
            'stocks_without_instances': stocks_without_instances,
            'orphan_instances': orphan_instances,
            'duplicate_codes': duplicate_codes,
            'problematic_requests': problematic_requests,
            'total_parts': Part.query.count(),
            'total_stocks': Stock.query.count(),
            'total_instances': PartInstance.query.count(),
            'total_requests': Request.query.count()
        }

        return render_template('diagnostics.html', diagnostics=diagnostics)

    except Exception as e:
        flash(f'Erro ao executar diagnósticos: {str(e)}', 'error')
        return redirect(url_for('dashboard'))


@app.route('/admin/fix-base-codes', methods=['POST'])
@login_required
@role_required('master')
def fix_base_codes():
    """Corrigir peças sem base_code"""
    try:
        parts_fixed = 0
        parts_without_code = Part.query.filter(
            db.or_(Part.base_code.is_(None), Part.base_code == '')
        ).all()

        for part in parts_without_code:
            part.base_code = generate_base_code(part.name)
            parts_fixed += 1

        db.session.commit()
        flash(f'{parts_fixed} peças tiveram seus códigos base corrigidos!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao corrigir códigos base: {str(e)}', 'error')

    return redirect(url_for('system_diagnostics'))


@app.route('/admin/generate-missing-instances', methods=['POST'])
@login_required
@role_required('master', 'admin')
def generate_missing_instances():
    """Gerar instâncias faltantes para estoques"""
    try:
        instances_created = 0
        company_id = request.form.get('company_id')

        # Filtrar por empresa se especificado
        if company_id:
            stocks = Stock.query.filter_by(company_id=company_id).all()
        elif current_user.role == 'admin':
            stocks = Stock.query.filter_by(company_id=current_user.company_id).all()
        else:
            stocks = Stock.query.all()

        for stock in stocks:
            instance_count = PartInstance.query.filter_by(
                part_id=stock.part_id,
                company_id=stock.company_id
            ).count()

            missing_instances = stock.quantity - instance_count

            if missing_instances > 0:
                # Limitar a 100 instâncias por vez para evitar sobrecarga
                missing_instances = min(missing_instances, 100)

                for i in range(missing_instances):
                    unique_code = generate_instance_code(stock.part_id)
                    if unique_code:
                        part = Part.query.get(stock.part_id)
                        qr_data = {
                            'part_id': stock.part_id,
                            'company_id': stock.company_id,
                            'unique_code': unique_code,
                            'part_name': part.name,
                            'base_code': part.base_code
                        }
                        qr_code_b64 = generate_qr_code(json.dumps(qr_data))

                        instance = PartInstance(
                            part_id=stock.part_id,
                            company_id=stock.company_id,
                            unique_code=unique_code,
                            qr_code=qr_code_b64,
                            status='em_estoque'
                        )
                        db.session.add(instance)
                        instances_created += 1

        db.session.commit()
        flash(f'{instances_created} instâncias faltantes foram criadas!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao gerar instâncias: {str(e)}', 'error')

    return redirect(url_for('system_diagnostics'))


@app.route('/admin/clean-orphans', methods=['POST'])
@login_required
@role_required('master')
def clean_orphan_instances():
    """Remover instâncias órfãs"""
    try:
        orphans = PartInstance.query.filter(
            ~PartInstance.part_id.in_(db.session.query(Part.id))
        ).all()

        orphan_count = len(orphans)

        for orphan in orphans:
            db.session.delete(orphan)

        db.session.commit()
        flash(f'{orphan_count} instâncias órfãs foram removidas!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao limpar instâncias órfãs: {str(e)}', 'error')

    return redirect(url_for('system_diagnostics'))


@app.route('/admin/fix-duplicates', methods=['POST'])
@login_required
@role_required('master')
def fix_duplicate_codes():
    """Corrigir códigos duplicados"""
    try:
        fixed_count = 0

        # Buscar duplicatas
        duplicate_codes = db.session.query(
            PartInstance.unique_code,
            func.count(PartInstance.id).label('count')
        ).group_by(PartInstance.unique_code).having(
            func.count(PartInstance.id) > 1
        ).all()

        for code, count in duplicate_codes:
            # Buscar todas as instâncias com este código
            instances = PartInstance.query.filter_by(unique_code=code).all()

            # Manter a primeira, renomear as outras
            for i, instance in enumerate(instances[1:], 1):
                new_code = generate_instance_code(instance.part_id)
                if new_code:
                    instance.unique_code = new_code
                    fixed_count += 1

        db.session.commit()
        flash(f'{fixed_count} códigos duplicados foram corrigidos!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao corrigir duplicatas: {str(e)}', 'error')

    return redirect(url_for('system_diagnostics'))


@app.route('/admin/system-info')
@login_required
@role_required('master')
def system_info():
    """Informações detalhadas do sistema"""
    try:
        info = {
            'database_stats': {
                'companies': Company.query.count(),
                'users': User.query.count(),
                'active_users': User.query.filter_by(is_active=True).count(),
                'locations': Location.query.count(),
                'equipments': Equipment.query.count(),
                'parts': Part.query.count(),
                'active_parts': Part.query.filter_by(is_active=True).count(),
                'stocks': Stock.query.count(),
                'instances': PartInstance.query.count(),
                'requests': Request.query.count(),
                'pending_requests': Request.query.filter_by(status='pendente').count(),
                'shipments': Shipment.query.count()
            },
            'instance_status': db.session.query(
                PartInstance.status,
                func.count(PartInstance.id).label('count')
            ).group_by(PartInstance.status).all(),
            'request_status': db.session.query(
                Request.status,
                func.count(Request.id).label('count')
            ).group_by(Request.status).all(),
            'recent_activity': {
                'recent_requests': Request.query.order_by(Request.created_at.desc()).limit(5).all(),
                'recent_instances': PartInstance.query.order_by(PartInstance.created_at.desc()).limit(5).all(),
                'low_stock': db.session.query(Stock, Part).join(Part).filter(
                    Stock.quantity <= Stock.min_quantity
                ).limit(10).all()
            }
        }

        return jsonify({
            'success': True,
            'system_info': info
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })
# ============= INICIALIZAÇÃO DO BANCO DE DADOS =============
def init_db():
    with app.app_context():
        db.create_all()

        # Criar usuário master padrão se não existir
        if not User.query.filter_by(role='master').first():
            master_user = User(
                username='master',
                email='master@sistema.com',
                password_hash=generate_password_hash('master123'),
                role='master'
            )
            db.session.add(master_user)
            db.session.commit()
            print("Usuário master criado: master / master123")

def create_sample_data():
    """Criar dados de exemplo para testes"""
    with app.app_context():
        # Verificar se já existem dados
        if Company.query.first():
            return

        # Criar empresa de exemplo
        company = Company(
            name='Empresa Teste Ltda',
            cnpj='12.345.678/0001-90',
            address='Rua Exemplo, 123 - Centro',
            contact_email='contato@empresa.com'
        )
        db.session.add(company)
        db.session.flush()

        # Criar usuários de exemplo
        users_data = [
            ('admin', 'admin@empresa.com', 'admin123', 'admin'),
            ('receptor1', 'receptor@empresa.com', 'receptor123', 'receptor'),
            ('solicitante1', 'solicitante@empresa.com', 'sol123', 'solicitante'),
        ]

        for username, email, password, role in users_data:
            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                role=role,
                company_id=company.id
            )
            db.session.add(user)

        # Criar peças de exemplo
        parts_data = [
            ('Monitor 17"', 'Monitor LCD 17 polegadas', 'MON-17-001', 'Informática'),
            ('Teclado USB', 'Teclado padrão USB', 'TEC-USB-001', 'Informática'),
            ('Mouse Óptico', 'Mouse óptico USB', 'MOU-OPT-001', 'Informática'),
            ('Cabo HDMI', 'Cabo HDMI 1.5m', 'CAB-HDMI-001', 'Cabos'),
        ]

        for name, desc, part_num, category in parts_data:
            part = Part(
                name=name,
                description=desc,
                part_number=part_num,
                category=category,
                unit_measure='unidade'
            )
            db.session.add(part)

        # Criar local de exemplo
        location = Location(
            name='Sala 101 - TI',
            description='Sala do departamento de TI',
            company_id=company.id
        )
        db.session.add(location)
        db.session.flush()

        # Criar equipamento de exemplo
        equipment = Equipment(
            name='Workstation 01',
            model='Dell OptiPlex 7090',
            serial_number='DL789456123',
            location_id=location.id,
            company_id=company.id
        )
        db.session.add(equipment)

        db.session.commit()
        print("Dados de exemplo criados com sucesso!")
        print("Usuários criados:")
        print("- master / master123 (Master)")
        print("- admin / admin123 (Admin)")
        print("- receptor1 / receptor123 (Receptor)")
        print("- solicitante1 / sol123 (Solicitante)")

if __name__ == '__main__':
    init_db()
    create_sample_data()
    app.run(debug=True, host='0.0.0.0', port=5000)