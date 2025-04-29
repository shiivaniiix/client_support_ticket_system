from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import random
import string
from flask_migrate import Migrate

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///tickets.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'donotreplytohellohelp@gmail.com')
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    role = db.Column(db.String(20))  # admin, manager, team_member, client
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    phone = db.Column(db.String(20))
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))
    managed_teams = db.relationship('Team', backref='manager', foreign_keys='Team.manager_id')
    otp = db.Column(db.String(6), nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    category = db.Column(db.String(50))
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Make manager_id optional
    members = db.relationship('User', backref='team', foreign_keys='User.team_id')
    
    def add_member(self, user):
        if user not in self.members:
            self.members.append(user)
            if user.role == 'manager' and not self.manager_id:
                self.manager_id = user.id
            db.session.commit()
    
    def remove_member(self, user):
        if user in self.members:
            self.members.remove(user)
            if user.id == self.manager_id:
                self.manager_id = None
            db.session.commit()

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    subject = db.Column(db.String(200))
    content = db.Column(db.Text)
    category = db.Column(db.String(50))
    priority = db.Column(db.String(20))  # low, medium, high, urgent
    status = db.Column(db.String(20))  # pending, open, resolved, closed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    sla_respond_by = db.Column(db.DateTime)
    sla_resolve_by = db.Column(db.DateTime)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    attachments = db.relationship('Attachment', backref='ticket', lazy=True)
    replies = db.relationship('Reply', backref='ticket', lazy=True)
    client = db.relationship('User', foreign_keys=[client_id], backref='tickets')
    assigned_staff = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_tickets')

    @property
    def business_days_over(self):
        if not self.sla_respond_by:
            return 0
        now = datetime.utcnow()
        if now <= self.sla_respond_by:
            return 0
        # Calculate business days (excluding weekends)
        days = 0
        current = self.sla_respond_by
        while current < now:
            if current.weekday() < 5:  # Monday to Friday
                days += 1
            current += timedelta(days=1)
        return days

    @property
    def days_over_to_solve(self):
        if not self.sla_resolve_by or self.status != 'resolved':
            return 0
        # Calculate business days (excluding weekends)
        days = 0
        current = self.sla_resolve_by
        while current < datetime.utcnow():
            if current.weekday() < 5:  # Monday to Friday
                days += 1
            current += timedelta(days=1)
        return days

    def calculate_sla_dates(self):
        now = datetime.utcnow()
        sla_settings = SLASettings.query.filter_by(priority=self.priority).first()
        
        if sla_settings:
            self.sla_respond_by = now + timedelta(hours=sla_settings.response_time)
            self.sla_resolve_by = now + timedelta(hours=sla_settings.resolution_time)
        else:
            # Fallback to default values if no SLA settings found
            if self.priority == 'urgent':
                self.sla_respond_by = now + timedelta(hours=4)
                self.sla_resolve_by = now + timedelta(hours=8)
            elif self.priority == 'high':
                self.sla_respond_by = now + timedelta(hours=24)
                self.sla_resolve_by = now + timedelta(hours=48)
            elif self.priority == 'medium':
                self.sla_respond_by = now + timedelta(hours=48)
                self.sla_resolve_by = now + timedelta(hours=72)
            else:  # low
                self.sla_respond_by = now + timedelta(hours=72)
                self.sla_resolve_by = now + timedelta(hours=120)

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='replies')

class FAQ(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(500))
    answer = db.Column(db.Text)
    category = db.Column(db.String(50))

class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    path = db.Column(db.String(255))
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ChatbotQA(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(500))
    answer = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SLASettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    priority = db.Column(db.String(20), unique=True)  # urgent, high, medium, low
    response_time = db.Column(db.Integer)  # in hours
    resolution_time = db.Column(db.Integer)  # in hours

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'client':
            return redirect(url_for('client_dashboard'))
        elif current_user.role == 'team_member':
            return redirect(url_for('team_member_dashboard'))
        elif current_user.role == 'manager':
            return redirect(url_for('manager_dashboard'))
        elif current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.check_password(password):
            flash('Please check your login details and try again.', 'error')
            return redirect(url_for('login'))
            
        login_user(user, remember=remember)
        return redirect(url_for('index'))
        
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate OTP
            otp = generate_otp()
            user.otp = otp
            db.session.commit()
            
            # Send OTP email
            send_otp_email(user.email, otp)
            flash('OTP has been sent to your email')
            return redirect(url_for('verify_otp', email=email))
        flash('Email not found')
    return render_template('reset_password.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        email = request.form.get('email')
        otp = request.form.get('otp')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('verify_otp', email=email))
        
        user = User.query.filter_by(email=email).first()
        if user and user.otp == otp:
            user.set_password(new_password)
            user.otp = None  # Clear the OTP after successful verification
            db.session.commit()
            flash('Password reset successful. Please login with your new password.')
            return redirect(url_for('login'))
        
        flash('Invalid OTP')
    return render_template('verify_otp.html', email=request.args.get('email'))

@app.route('/client_home')
@login_required
def client_home():
    try:
        if current_user.role != 'client':
            abort(403)
        
        return render_template('client_home.html')
    
    except Exception as e:
        app.logger.error(f"Error in client_home: {str(e)}")
        flash('An error occurred while loading the home page. Please try again.', 'danger')
        return redirect(url_for('login'))

@app.route('/create_ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        category = request.form.get('category')
        subject = request.form.get('subject')
        content = request.form.get('content')
        attachments = request.files.getlist('attachments')
        
        # Calculate SLA based on priority
        priority = 'medium'  # Default priority
        if 'urgent' in subject.lower() or 'urgent' in content.lower():
            priority = 'urgent'
        elif 'high' in subject.lower() or 'high' in content.lower():
            priority = 'high'
        
        # Calculate SLA dates
        now = datetime.utcnow()
        if priority == 'urgent':
            respond_by = now + timedelta(hours=2)
            resolve_by = now + timedelta(hours=4)
        elif priority == 'high':
            respond_by = now + timedelta(hours=4)
            resolve_by = now + timedelta(hours=8)
        else:
            respond_by = now + timedelta(hours=8)
            resolve_by = now + timedelta(hours=24)
        
        ticket = Ticket(
            client_id=current_user.id,
            subject=subject,
            content=content,
            category=category,
            priority=priority,
            status='pending',
            sla_respond_by=respond_by,
            sla_resolve_by=resolve_by
        )
        
        db.session.add(ticket)
        db.session.commit()
        
        # Handle attachments
        for attachment in attachments:
            if attachment.filename:
                filename = secure_filename(attachment.filename)
                attachment_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                attachment.save(attachment_path)
                ticket.attachments.append(Attachment(filename=filename, path=attachment_path))
        
        db.session.commit()
        
        # Send notification email
        send_ticket_created_email(ticket)
        
        flash('Ticket created successfully!')
        return redirect(url_for('client_home'))
    
    categories = ['Technical', 'Billing', 'Account', 'General']
    return render_template('create_ticket.html', categories=categories)

@app.route('/ticket/<int:ticket_id>')
@login_required
def ticket_details(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.role == 'client' and ticket.client_id != current_user.id:
        abort(403)
    return render_template('ticket_details.html', ticket=ticket)

@app.route('/update_ticket_status/<int:ticket_id>', methods=['POST'])
@login_required
def update_ticket_status(ticket_id):
    if current_user.role != 'team_member':
        abort(403)
    
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Check if the ticket is assigned to the current user
    if ticket.assigned_to != current_user.id:
        flash('You can only update tickets assigned to you.', 'danger')
        return redirect(url_for('my_tickets'))
    
    new_status = request.form.get('status')
    if new_status not in ['open', 'pending', 'resolved', 'closed']:
        flash('Invalid status.', 'danger')
        return redirect(url_for('my_tickets'))
    
    # Update ticket status
    ticket.status = new_status
    ticket.last_updated = datetime.utcnow()
    
    # If status is resolved, update SLA resolve date
    if new_status == 'resolved':
        ticket.sla_resolve_by = datetime.utcnow()
    
    # Add a reply to notify the client
    reply = Reply(
        content=f"Ticket status updated to {new_status}.",
        ticket_id=ticket.id,
        user_id=current_user.id
    )
    db.session.add(reply)
    
    try:
        db.session.commit()
        
        # Send email notification to client
        if new_status == 'closed':
            msg = Message(
                f'Ticket #{ticket.id} - Status Update',
                sender=('HelloHelp Support', 'donotreplytohellohelp@gmail.com'),
                recipients=[ticket.client.email]
            )
            msg.body = f'''Dear {ticket.client.first_name},

Your support ticket #{ticket.id} has been closed.

Ticket Details:
- Subject: {ticket.subject}
- Category: {ticket.category}
- Priority: {ticket.priority}
- Created: {ticket.created_at.strftime('%Y-%m-%d %H:%M')}
- Closed: {ticket.last_updated.strftime('%Y-%m-%d %H:%M')}

If you have any further questions or need additional assistance, please feel free to create a new support ticket.

Thank you for using HelloHelp Support Services.

Best regards,
HelloHelp Support Team
'''
        else:
            msg = Message(
                f'Ticket #{ticket.id} - Status Update',
                sender=('HelloHelp Support', 'donotreplytohellohelp@gmail.com'),
                recipients=[ticket.client.email]
            )
            msg.body = f'''Dear {ticket.client.first_name},

The status of your support ticket #{ticket.id} has been updated to {new_status}.

Ticket Details:
- Subject: {ticket.subject}
- Category: {ticket.category}
- Priority: {ticket.priority}
- Current Status: {new_status}
- Last Updated: {ticket.last_updated.strftime('%Y-%m-%d %H:%M')}

You can view the latest updates on your ticket by clicking here: {url_for('ticket_details', ticket_id=ticket.id, _external=True)}

Best regards,
HelloHelp Support Team
'''
        
        mail.send(msg)
        flash('Ticket status updated successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while updating the ticket status.', 'danger')
    
    return redirect(url_for('my_tickets'))

@app.route('/add_reply/<int:ticket_id>', methods=['POST'])
@login_required
def add_reply(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.role == 'client' and ticket.client_id != current_user.id:
        abort(403)
    if current_user.role == 'team_member' and ticket.assigned_to != current_user.id:
        abort(403)
    
    content = request.form.get('content')
    if not content:
        flash('Message cannot be empty', 'error')
        return redirect(url_for('ticket_details', ticket_id=ticket_id))
        
    reply = Reply(
        ticket_id=ticket_id,
        user_id=current_user.id,
        content=content
    )
    
    db.session.add(reply)
    ticket.last_updated = datetime.utcnow()
    db.session.commit()
    
    # Send notification email
    try:
        if current_user.role == 'team_member':
            # Send update notification using the proper function
            send_ticket_update_notification(ticket, content)
        elif current_user.role == 'client':
            # Send to assigned team member
            if ticket.assigned_to:
                msg = Message(
                    f'New Reply on Ticket #{ticket.id}',
                    sender=('HelloHelp Support', 'donotreplytohellohelp@gmail.com'),
                    recipients=[ticket.assigned_staff.email]
                )
                msg.body = f'''Hello {ticket.assigned_staff.first_name},

A new reply has been added to ticket #{ticket.id}:

{content}

You can view and respond to this ticket by clicking here: {url_for('ticket_details', ticket_id=ticket.id, _external=True)}

Best regards,
HelloHelp Support Team'''
                mail.send(msg)
    except Exception as e:
        print(f"Error sending email notification: {str(e)}")
        flash('Reply added successfully, but email notification could not be sent.', 'warning')
    
    return redirect(url_for('ticket_details', ticket_id=ticket_id))

@app.route('/assign_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def assign_ticket(ticket_id):
    if current_user.role not in ['admin', 'manager']:
        abort(403)
    
    ticket = Ticket.query.get_or_404(ticket_id)
    staff_id = request.form.get('staff_id')
    staff = User.query.get(staff_id)
    
    # If manager, verify that the staff member is in their team
    if current_user.role == 'manager':
        team = Team.query.filter_by(manager_id=current_user.id).first()
        if not team or staff not in team.members:
            flash('You can only assign tickets to members of your team.', 'danger')
            return redirect(url_for('manager_dashboard'))
    
    if staff and staff.role == 'team_member':
        ticket.assigned_to = staff.id
        ticket.status = 'open'
        ticket.last_updated = datetime.utcnow()
        db.session.commit()
        
        # Send notification email
        send_ticket_assigned_email(ticket, staff)
        
        flash('Ticket assigned successfully!')
    else:
        flash('Invalid staff member selected!')
    
    if current_user.role == 'manager':
        return redirect(url_for('manager_dashboard'))
    else:
        return redirect(url_for('admin_dashboard'))

@app.route('/create_team', methods=['GET', 'POST'])
@login_required
def create_team():
    if current_user.role != 'admin':
        abort(403)
    
    if request.method == 'POST':
        name = request.form.get('name')
        category = request.form.get('category')
        
        team = Team(
            name=name,
            category=category
        )
        
        db.session.add(team)
        db.session.commit()
        
        # Add members if selected
        member_ids = request.form.getlist('members')
        for member_id in member_ids:
            user = User.query.get(member_id)
            if user:
                team.add_member(user)
        
        flash('Team created successfully!')
        return redirect(url_for('admin_dashboard'))
    
    # Get all users who can be team members (staff and managers)
    potential_members = User.query.filter(User.role.in_(['manager', 'team_member'])).all()
    return render_template('create_team.html', potential_members=potential_members)

@app.route('/add_staff', methods=['GET', 'POST'])
@login_required
def add_staff():
    if current_user.role != 'admin':
        abort(403)
    
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        role = request.form.get('role')
        team_id = request.form.get('team_id')
        phone = request.form.get('phone')
        
        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('A user with this email already exists!', 'error')
            return redirect(url_for('add_staff'))
        
        # Generate a random password
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        
        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            role=role,
            phone=phone
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # If team_id is provided, add the user to the team
        if team_id:
            team = Team.query.get(team_id)
            if team:
                team.add_member(user)
        
        # Try to send welcome email, but don't fail if it doesn't work
        try:
            send_welcome_email(user, password)
            flash(f'Staff member added successfully! Welcome email sent. Password: {password}', 'success')
        except Exception as e:
            flash(f'Staff member added successfully! Note: Welcome email could not be sent. Password: {password}', 'warning')
            print(f"Email sending error: {str(e)}")
        
        return redirect(url_for('admin_dashboard'))
    
    # Get all teams for the dropdown
    teams = Team.query.all()
    return render_template('add_staff.html', teams=teams)

@app.route('/add_client', methods=['GET', 'POST'])
@login_required
def add_client():
    if current_user.role != 'admin':
        abort(403)
    
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        phone = request.form.get('phone')
        password = request.form.get('password')
        
        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('A user with this email already exists!', 'error')
            return redirect(url_for('add_client'))
        
        # Create new client user
        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            role='client',
            phone=phone
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Try to send welcome email, but don't fail if it doesn't work
        try:
            send_welcome_email(user, password)
            flash(f'Client added successfully! Welcome email sent.', 'success')
        except Exception as e:
            flash(f'Client added successfully! Note: Welcome email could not be sent. Please provide the credentials to the client manually.', 'warning')
            print(f"Email sending error: {str(e)}")
        
        return redirect(url_for('admin_dashboard'))
    
    return render_template('add_client.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        abort(403)
    
    # Get statistics
    total_tickets = Ticket.query.count()
    pending_tickets = Ticket.query.filter_by(status='pending').count()
    resolved_tickets = Ticket.query.filter_by(status='resolved').count()
    total_staff = User.query.filter(User.role.in_(['manager', 'team_member'])).count()
    
    # Get recent tickets
    recent_tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(5).all()
    
    # Get status counts
    status_counts = {
        'open': Ticket.query.filter_by(status='open').count(),
        'pending': Ticket.query.filter_by(status='pending').count(),
        'resolved': Ticket.query.filter_by(status='resolved').count(),
        'closed': Ticket.query.filter_by(status='closed').count()
    }
    
    # Get category counts
    categories = ['Technical', 'Billing', 'Account', 'General']
    category_counts = [Ticket.query.filter_by(category=cat).count() for cat in categories]
    
    # Add status color to tickets
    for ticket in recent_tickets:
        ticket.status_color = {
            'open': 'primary',
            'pending': 'warning',
            'resolved': 'success',
            'closed': 'secondary'
        }.get(ticket.status, 'info')
    
    return render_template('admin_dashboard.html',
                         total_tickets=total_tickets,
                         pending_tickets=pending_tickets,
                         resolved_tickets=resolved_tickets,
                         total_staff=total_staff,
                         recent_tickets=recent_tickets,
                         status_counts=status_counts,
                         category_counts=category_counts,
                         category_labels=categories)

@app.route('/manager_dashboard')
@login_required
def manager_dashboard():
    if current_user.role != 'manager':
        abort(403)
    
    # Get team statistics
    team = Team.query.filter_by(manager_id=current_user.id).first()
    if not team:
        flash('You are not assigned to manage any team.', 'warning')
        return redirect(url_for('profile'))
    
    team_member_ids = [m.id for m in team.members]
    team_tickets = Ticket.query.filter(Ticket.assigned_to.in_(team_member_ids)).count()
    pending_tickets = Ticket.query.filter(Ticket.assigned_to.in_(team_member_ids), Ticket.status=='pending').count()
    resolved_tickets = Ticket.query.filter(Ticket.assigned_to.in_(team_member_ids), Ticket.status=='resolved').count()
    team_members = len(team.members)
    
    # Get unassigned tickets
    unassigned_tickets = Ticket.query.filter(
        Ticket.assigned_to == None,
        Ticket.status.in_(['pending', 'open'])
    ).order_by(Ticket.created_at.desc()).all()
    
    # Add priority colors to unassigned tickets
    for ticket in unassigned_tickets:
        ticket.priority_color = {
            'urgent': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'success'
        }.get(ticket.priority, 'secondary')
    
    # Get team performance
    team_performance = []
    team_member_names = []
    tickets_resolved = []
    tickets_pending = []
    
    for member in team.members:
        assigned_tickets = Ticket.query.filter_by(assigned_to=member.id).count()
        member_resolved = Ticket.query.filter_by(assigned_to=member.id, status='resolved').count()
        member_pending = Ticket.query.filter_by(assigned_to=member.id, status='pending').count()
        
        team_member_names.append(f"{member.first_name} {member.last_name}")
        tickets_resolved.append(member_resolved)
        tickets_pending.append(member_pending)
        
        team_performance.append({
            'first_name': member.first_name,
            'last_name': member.last_name,
            'assigned_tickets': assigned_tickets,
            'resolved_tickets': member_resolved,
            'avg_response_time': 0,  # You can implement this calculation
            'avg_resolution_time': 0  # You can implement this calculation
        })
    
    # Get recent team tickets
    recent_tickets = Ticket.query.filter(Ticket.assigned_to.in_(team_member_ids))\
        .order_by(Ticket.created_at.desc())\
        .limit(5).all()
    
    # Add status colors to tickets
    for ticket in recent_tickets:
        ticket.status_color = {
            'open': 'primary',
            'pending': 'warning',
            'resolved': 'success',
            'closed': 'secondary'
        }.get(ticket.status, 'info')
    
    return render_template('manager_dashboard.html',
                         team_tickets=team_tickets,
                         pending_tickets=pending_tickets,
                         resolved_tickets=resolved_tickets,
                         team_members=team_members,
                         team_performance=team_performance,
                         recent_tickets=recent_tickets,
                         team_member_names=team_member_names,
                         tickets_resolved=tickets_resolved,
                         tickets_pending=tickets_pending,
                         unassigned_tickets=unassigned_tickets,
                         team_members_list=team.members)

@app.route('/team_member_dashboard')
@login_required
def team_member_dashboard():
    if current_user.role != 'team_member':
        abort(403)
    
    try:
        # Get personal statistics
        assigned_tickets = Ticket.query.filter_by(assigned_to=current_user.id).count()
        pending_tickets = Ticket.query.filter_by(assigned_to=current_user.id, status='pending').count()
        resolved_tickets = Ticket.query.filter_by(assigned_to=current_user.id, status='resolved').count()
        
        # Get assigned tickets with proper ordering
        assigned_tickets_list = Ticket.query.filter_by(assigned_to=current_user.id)\
            .order_by(Ticket.created_at.desc())\
            .limit(5).all()
        
        # Calculate average response time (in hours)
        total_response_time = 0
        response_count = 0
        avg_response_time = 0
        
        for ticket in assigned_tickets_list:
            if ticket.last_updated and ticket.created_at:
                response_time = (ticket.last_updated - ticket.created_at).total_seconds() / 3600
                total_response_time += response_time
                response_count += 1
        
        if response_count > 0:
            avg_response_time = round(total_response_time / response_count, 2)
        
        # Get last 7 days of data
        response_time_labels = []
        response_time_data = []
        resolution_time_labels = []
        resolution_time_data = []
        
        for i in range(6, -1, -1):  # Last 7 days in chronological order
            date = datetime.utcnow() - timedelta(days=i)
            date_str = date.strftime('%Y-%m-%d')
            
            # Response time data
            day_tickets = Ticket.query.filter(
                Ticket.assigned_to == current_user.id,
                Ticket.created_at >= date,
                Ticket.created_at < date + timedelta(days=1)
            ).all()
            
            response_time_labels.append(date_str)
            if day_tickets:
                valid_tickets = [t for t in day_tickets if t.last_updated and t.created_at]
                if valid_tickets:
                    avg_day_response = sum(
                        (t.last_updated - t.created_at).total_seconds() / 3600 
                        for t in valid_tickets
                    ) / len(valid_tickets)
                    response_time_data.append(round(avg_day_response, 2))
                else:
                    response_time_data.append(0)
            else:
                response_time_data.append(0)
            
            # Resolution time data
            resolved_tickets = Ticket.query.filter(
                Ticket.assigned_to == current_user.id,
                Ticket.status == 'resolved',
                Ticket.last_updated >= date,
                Ticket.last_updated < date + timedelta(days=1)
            ).all()
            
            resolution_time_labels.append(date_str)
            if resolved_tickets:
                valid_tickets = [t for t in resolved_tickets if t.last_updated and t.created_at]
                if valid_tickets:
                    avg_day_resolution = sum(
                        (t.last_updated - t.created_at).total_seconds() / 3600 
                        for t in valid_tickets
                    ) / len(valid_tickets)
                    resolution_time_data.append(round(avg_day_resolution, 2))
                else:
                    resolution_time_data.append(0)
            else:
                resolution_time_data.append(0)
        
        # Add status and priority colors to tickets
        for ticket in assigned_tickets_list:
            ticket.status_color = {
                'open': 'primary',
                'pending': 'warning',
                'resolved': 'success',
                'closed': 'secondary'
            }.get(ticket.status, 'info')
            
            ticket.priority_color = {
                'high': 'danger',
                'medium': 'warning',
                'low': 'info'
            }.get(ticket.priority, 'secondary')
        
        return render_template('team_member_dashboard.html',
                            assigned_tickets=assigned_tickets,
                            pending_tickets=pending_tickets,
                            resolved_tickets=resolved_tickets,
                            avg_response_time=avg_response_time,
                            assigned_tickets_list=assigned_tickets_list,
                            response_time_labels=response_time_labels,
                            response_time_data=response_time_data,
                            resolution_time_labels=resolution_time_labels,
                            resolution_time_data=resolution_time_data)
        
    except Exception as e:
        app.logger.error(f"Error in team_member_dashboard: {str(e)}")
        flash('An error occurred while loading the dashboard.', 'danger')
        return redirect(url_for('login'))

@app.route('/client_dashboard')
@login_required
def client_dashboard():
    try:
        if current_user.role != 'client':
            abort(403)
        
        return render_template('client_home.html')
    
    except Exception as e:
        app.logger.error(f"Error in client_dashboard: {str(e)}")
        flash('An error occurred while loading the dashboard. Please try again.', 'danger')
        return redirect(url_for('login'))

@app.route('/faq')
@login_required
def faq():
    # Get all FAQs
    faqs = FAQ.query.all()
    
    return render_template('faq.html', faqs=faqs)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.first_name = request.form.get('first_name')
        current_user.last_name = request.form.get('last_name')
        current_user.phone = request.form.get('phone')
        
        # Handle password change if provided
        new_password = request.form.get('new_password')
        if new_password:
            current_user.set_password(new_password)
        
        db.session.commit()
        flash('Profile updated successfully!')
        return redirect(url_for('profile'))
    
    return render_template('profile.html')

@app.route('/all_tickets')
@login_required
def all_tickets():
    # Get page number from query parameters
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    if current_user.role == 'admin':
        # Admin can see all tickets
        tickets = Ticket.query.order_by(Ticket.created_at.desc()).paginate(page=page, per_page=per_page)
    elif current_user.role == 'manager':
        # Manager can see tickets assigned to their team members
        team_member_ids = [member.id for member in current_user.team.members]
        tickets = Ticket.query.filter(Ticket.assigned_to.in_(team_member_ids))\
            .order_by(Ticket.created_at.desc())\
            .paginate(page=page, per_page=per_page)
    else:
        abort(403)
    
    # Add status and priority colors to tickets
    for ticket in tickets.items:
        ticket.status_color = {
            'open': 'primary',
            'pending': 'warning',
            'resolved': 'success',
            'closed': 'secondary'
        }.get(ticket.status, 'info')
        
        ticket.priority_color = {
            'high': 'danger',
            'medium': 'warning',
            'low': 'info'
        }.get(ticket.priority, 'secondary')
    
    return render_template('all_tickets.html', tickets=tickets)

@app.route('/my_tickets')
@login_required
def my_tickets():
    if current_user.role != 'client':
        abort(403)
    
    # Get page number from query parameters
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of tickets per page
    
    # Get tickets with pagination
    tickets = Ticket.query.filter_by(client_id=current_user.id)\
        .order_by(Ticket.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    # Add status and priority colors to tickets
    for ticket in tickets.items:
        ticket.status_color = {
            'pending': 'warning',
            'open': 'info',
            'resolved': 'success',
            'closed': 'secondary'
        }.get(ticket.status, 'secondary')
        
        ticket.priority_color = {
            'urgent': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'success'
        }.get(ticket.priority, 'secondary')
    
    return render_template('my_tickets.html', tickets=tickets)

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    if current_user.role != 'admin':
        abort(403)
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add_category':
            category = request.form.get('category')
            if category:
                # Add category to database
                pass
                
        elif action == 'add_faq':
            question = request.form.get('question')
            answer = request.form.get('answer')
            category = request.form.get('category')
            if question and answer and category:
                faq = FAQ(question=question, answer=answer, category=category)
                db.session.add(faq)
                db.session.commit()
                
        elif action == 'add_chatbot_qa':
            question = request.form.get('question')
            answer = request.form.get('answer')
            if question and answer:
                qa = ChatbotQA(question=question, answer=answer)
                db.session.add(qa)
                db.session.commit()
                
        elif action == 'create_team':
            name = request.form.get('name')
            category = request.form.get('category')
            manager_id = request.form.get('manager_id')
            members = request.form.getlist('members')
            
            if name and category and manager_id:
                team = Team(name=name, category=category, manager_id=manager_id)
                db.session.add(team)
                db.session.commit()
                
                # Add members to team
                for member_id in members:
                    member = User.query.get(member_id)
                    if member:
                        team.add_member(member)
                        
        elif action == 'update_sla':
            # Update SLA settings for each priority
            priorities = ['urgent', 'high', 'medium', 'low']
            for priority in priorities:
                response_time = request.form.get(f'{priority}_response')
                resolution_time = request.form.get(f'{priority}_resolution')
                
                if response_time and resolution_time:
                    sla = SLASettings.query.filter_by(priority=priority).first()
                    if not sla:
                        sla = SLASettings(priority=priority)
                        db.session.add(sla)
                    
                    sla.response_time = int(response_time)
                    sla.resolution_time = int(resolution_time)
            
            db.session.commit()
            flash('SLA settings updated successfully', 'success')
    
    # Get all data for the template
    categories = ['Technical', 'Billing', 'General']  # Replace with actual categories from database
    faqs = FAQ.query.all()
    teams = Team.query.all()
    staff = User.query.filter(User.role.in_(['manager', 'team_member'])).all()
    
    # Get SLA settings
    sla_settings = {
        'urgent': {'response': 4, 'resolution': 8},
        'high': {'response': 24, 'resolution': 48},
        'medium': {'response': 48, 'resolution': 72},
        'low': {'response': 72, 'resolution': 120}
    }
    
    # Update with actual values from database
    for priority in sla_settings:
        sla = SLASettings.query.filter_by(priority=priority).first()
        if sla:
            sla_settings[priority] = {
                'response': sla.response_time,
                'resolution': sla.resolution_time
            }
    
    return render_template('admin_settings.html',
                         categories=categories,
                         faqs=faqs,
                         teams=teams,
                         staff=staff,
                         sla_settings=sla_settings)

@app.route('/chatbot', methods=['POST'])
@login_required
def chatbot():
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400
    
    data = request.get_json()
    message = data.get('message', '').lower()
    
    # First check FAQ database
    faqs = FAQ.query.filter(
        db.or_(
            FAQ.question.ilike(f'%{message}%'),
            FAQ.answer.ilike(f'%{message}%')
        )
    ).all()
    
    if faqs:
        # Return the first matching FAQ
        return jsonify({
            'response': faqs[0].answer
        })
    
    # Then check ChatbotQA database
    qas = ChatbotQA.query.filter(
        db.or_(
            ChatbotQA.question.ilike(f'%{message}%'),
            ChatbotQA.answer.ilike(f'%{message}%')
        )
    ).all()
    
    if qas:
        # Return the first matching Q&A
        return jsonify({
            'response': qas[0].answer
        })
    
    # If no match found, provide a generic response
    return jsonify({
        'response': "I couldn't find a specific answer to your question. Would you like to:\n1. Create a support ticket\n2. Browse our FAQs\n3. Try rephrasing your question"
    })

@app.route('/test_email')
def test_email():
    try:
        print(f"Testing email configuration:")
        print(f"Server: {app.config['MAIL_SERVER']}")
        print(f"Port: {app.config['MAIL_PORT']}")
        print(f"Username: {app.config['MAIL_USERNAME']}")
        print(f"Use TLS: {app.config['MAIL_USE_TLS']}")
        
        msg = Message('Test Email',
                     sender=app.config['MAIL_DEFAULT_SENDER'],
                     recipients=['donotreplytohellohelp@gmail.com'])
        msg.body = 'This is a test email from your Flask application.'
        
        print("Attempting to send test email...")
        mail.send(msg)
        print("Test email sent successfully!")
        return jsonify({'status': 'success', 'message': 'Test email sent successfully!'})
    except Exception as e:
        print(f"Error in test_email: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/close_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def close_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.client_id != current_user.id and current_user.role not in ['admin', 'manager', 'team_member']:
        abort(403)
    
    ticket.status = 'closed'
    ticket.last_updated = datetime.utcnow()
    db.session.commit()
    
    send_ticket_closed_email(ticket)
    flash('Ticket has been closed successfully.', 'success')
    return redirect(url_for('ticket_details', ticket_id=ticket_id))

@app.route('/reopen_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def reopen_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.client_id != current_user.id and current_user.role not in ['admin', 'manager', 'team_member']:
        abort(403)
    
    # Create a new ticket with the same content but new ID
    new_ticket = Ticket(
        client_id=ticket.client_id,
        subject=f"Reopened: {ticket.subject}",
        content=f"Original Ticket #{ticket.id} was reopened.\n\nOriginal content:\n{ticket.content}",
        category=ticket.category,
        priority=ticket.priority,
        status='open',
        created_at=datetime.utcnow(),
        last_updated=datetime.utcnow()
    )
    new_ticket.calculate_sla_dates()
    
    db.session.add(new_ticket)
    db.session.commit()
    
    # Send notification email
    try:
        send_ticket_created_email(new_ticket)
        flash('Ticket has been reopened with a new ticket number.', 'success')
    except Exception as e:
        print(f"Error sending email notification: {str(e)}")
        flash('Ticket reopened but email notification could not be sent.', 'warning')
    
    return redirect(url_for('ticket_details', ticket_id=new_ticket.id))

# Helper Functions
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    msg = Message('Password Reset OTP', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Your OTP for password reset is: {otp}'
    mail.send(msg)

def send_ticket_created_email(ticket):
    try:
        with open('templates/emails/ticket_created.txt', 'r') as f:
            template = f.read()
        
        # Format the email content
        email_content = template.format(
            ticket_number=ticket.id,
            client_name=ticket.client.first_name,
            content=ticket.content
        )
        
        # Debug log
        print(f"Debug - Ticket Created Email Content:\n{email_content}")
        
        msg = Message(
            subject=f"Ticket Created - {ticket.id}",
            recipients=[ticket.client.email]
        )
        msg.body = email_content
        mail.send(msg)
    except Exception as e:
        print(f"Error sending ticket created email: {str(e)}")
        raise

def send_ticket_resolved_email(ticket):
    msg = Message('Ticket Resolved', sender=app.config['MAIL_USERNAME'], recipients=[ticket.client.email])
    msg.body = f'Your ticket #{ticket.id} has been resolved.'
    mail.send(msg)

def send_reply_notification_email(ticket, reply, is_staff=False):
    if is_staff:
        recipients = [ticket.client.email]
    else:
        recipients = [ticket.assigned_to.email]
    
    msg = Message('New Reply on Ticket', sender=app.config['MAIL_USERNAME'], recipients=recipients)
    msg.body = f'A new reply has been added to ticket #{ticket.id}.'
    mail.send(msg)

def send_ticket_assigned_email(ticket, staff):
    try:
        with open('templates/emails/ticket_assigned.txt', 'r') as f:
            template = f.read()
        
        # Format the email content
        email_content = template.format(
            ticket_number=ticket.id,
            client_name=ticket.client.first_name,
            team_member_email=staff.email
        )
        
        # Debug log
        print(f"Debug - Ticket Assigned Email Content:\n{email_content}")
        
        msg = Message(
            subject=f"Ticket Assigned - {ticket.id}",
            recipients=[ticket.client.email]
        )
        msg.body = email_content
        mail.send(msg)
    except Exception as e:
        print(f"Error sending ticket assigned email: {str(e)}")
        raise

def send_welcome_email(user, password):
    try:
        msg = Message('Welcome to Support System',
                     sender=app.config['MAIL_USERNAME'],
                     recipients=[user.email])
        msg.body = f'''Welcome {user.first_name}!

Your account has been created in our support system.

Your login credentials are:
Email: {user.email}
Password: {password}

Please change your password after your first login.

Best regards,
Support Team'''
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send welcome email: {str(e)}")
        raise  # Re-raise the exception to be handled by the caller

def send_ticket_update_notification(ticket, message):
    try:
        with open('templates/emails/ticket_update.txt', 'r') as f:
            template = f.read()
        
        # Format the email content
        email_content = template.format(
            ticket_number=ticket.id,
            client_name=ticket.client.first_name,
            request_content=ticket.content,
            team_member_reply=message
        )
        
        # Debug log
        print(f"Debug - Ticket Update Email Content:\n{email_content}")
        
        msg = Message(
            subject=f"Ticket Update - {ticket.id}",
            recipients=[ticket.client.email]
        )
        msg.body = email_content
        mail.send(msg)
    except Exception as e:
        print(f"Error sending ticket update email: {str(e)}")
        raise

def send_ticket_closed_email(ticket):
    try:
        with open('templates/emails/ticket_closed.txt', 'r') as f:
            template = f.read()
        
        # Format the email content
        email_content = template.format(
            ticket_number=ticket.id,
            client_name=ticket.client.first_name
        )
        
        # Debug log
        print(f"Debug - Ticket Closed Email Content:\n{email_content}")
        
        msg = Message(
            subject=f"Ticket Closed - {ticket.id}",
            recipients=[ticket.client.email]
        )
        msg.body = email_content
        mail.send(msg)
    except Exception as e:
        print(f"Error sending ticket closed email: {str(e)}")
        raise

def create_sample_data():
    # Create sample FAQs
    sample_faqs = [
        FAQ(question="How do I create a new ticket?", 
            answer="Click on 'Create Ticket' in the navigation menu and fill out the form with your issue details.",
            category="General"),
        FAQ(question="What is the response time for tickets?", 
            answer="Response times vary by priority: Urgent (2 hours), High (4 hours), Medium (8 hours), Low (24 hours).",
            category="Technical"),
        FAQ(question="How do I reset my password?", 
            answer="Click on 'Forgot Password' on the login page and follow the instructions sent to your email.",
            category="Account"),
        FAQ(question="What payment methods do you accept?", 
            answer="We accept all major credit cards, PayPal, and bank transfers.",
            category="Billing")
    ]
    
    for faq in sample_faqs:
        if not FAQ.query.filter_by(question=faq.question).first():
            db.session.add(faq)
    
    db.session.commit()

def check_and_close_inactive_tickets():
    """Check for and close tickets that have been inactive for more than 10 hours"""
    inactive_threshold = datetime.utcnow() - timedelta(hours=10)
    inactive_tickets = Ticket.query.filter(
        Ticket.status.in_(['open', 'pending']),
        Ticket.last_updated < inactive_threshold
    ).all()
    
    for ticket in inactive_tickets:
        ticket.status = 'closed'
        ticket.last_updated = datetime.utcnow()
        db.session.commit()
        send_ticket_closed_email(ticket)
        flash(f'Ticket #{ticket.id} has been automatically closed due to inactivity.', 'info')

# Add this to your scheduled tasks or run it periodically
@app.before_request
def check_inactive_tickets():
    if current_user.is_authenticated and current_user.role == 'team_member':
        check_and_close_inactive_tickets()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create admin user if not exists
        admin = User.query.filter_by(email='ashokshivani875@gmail.com').first()
        if not admin:
            admin = User(
                email='ashokshivani875@gmail.com',
                first_name='Admin',
                last_name='User',
                role='admin'
            )
            admin.set_password('Shivani@123')
            db.session.add(admin)
            db.session.commit()
        
        # Create sample data
        create_sample_data()
    
    app.run(host='0.0.0.0', port=10000) 
