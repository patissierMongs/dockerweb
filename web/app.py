from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from sqlalchemy import desc
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from wtforms.validators import DataRequired, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, date, timedelta
from celery import Celery
import os, subprocess, markdown

SUPPORTED_EXTENSIONS = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp']

def make_celery(app):
    celery = Celery(app.import_name, backend=app.config['CELERY_RESULT_BACKEND'],
                    broker=app.config['CELERY_BROKER_URL'])
    celery.conf.update(app.config)
    return celery

app = Flask(__name__, static_url_path='/static', static_folder='static')
app.secret_key = 'your_secret_key'  # Replace with a secure secret key
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config.update(
    CELERY_BROKER_URL='redis://localhost:6379/0',
    CELERY_RESULT_BACKEND='redis://localhost:6379/0'
)

celery = make_celery(app)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    is_admin = BooleanField('Admin User')
    submit = SubmitField('Register')

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)

    user = db.relationship('User', backref=db.backref('activity_logs', lazy=True))

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    date_joined = db.Column(db.Date, default=date.today)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute.')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Calculate available days off based on date_joined
    def calculate_days_off(self):
        current_year = date.today().year
        join_year = self.date_joined.year
        total_days_off = 24

        if current_year == join_year:
            months_worked = 12 - self.date_joined.month + 1
            days_off = int((months_worked / 12) * total_days_off)
        else:
            days_off = total_days_off

        # Subtract used days off
        used_days = sum([leave.total_days() for leave in self.leaves if leave.status == 'Approved' and leave.start_date.year == current_year])
        return days_off - used_days 

class Leave(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default="Pending")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('leaves', lazy=True))

    def total_days(self):
        return (self.end_date - self.start_date).days + 1

# File and Comment models remain the same
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    urgency = db.Column(db.String(50), nullable=False)
    size = db.Column(db.Integer)
    comment = db.Column(db.Text)
    type = db.Column(db.String(50), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    uploader = db.relationship('User', backref=db.backref('files', lazy=True))
    pdf_filename = db.Column(db.String(300), nullable=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=True)
    uploader = db.relationship('User', backref=db.backref('comments', lazy=True))
    file = db.relationship('File', backref=db.backref('comments', lazy=True)) 
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()
    # Create an admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin')
        admin_user.password = 'password'  # Password setter hashes the password
        admin_user.is_admin = True
        db.session.add(admin_user)
        db.session.commit()

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        return "Unauthorized", 403
    users = User.query.all()
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, is_admin=form.is_admin.data)
        if form.password.data:
            user.password = form.password.data
        else:
            flash('Password cannot be empty!', 'error')
            return redirect(url_for('admin'))
        try:
            db.session.add(user)
            db.session.commit()
            flash('User registered successfully!', 'success')
            return redirect(url_for('admin'))
        except:
            db.session.rollback()
            flash('Username already exists', 'error')
            return "Username already exists", 400

    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
    return render_template('admin.html', users=users, form=form)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/view/<int:file_id>')
@login_required
def view_file(file_id):
    file = File.query.get_or_404(file_id)
    if not current_user.is_admin and file.uploader_id != current_user.id:
        return "Unauthorized", 403

    # Get the file extension
    file_extension = os.path.splitext(file.filename)[1].lower()

    # Handle Markdown files
    if file_extension == '.md':
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            html_content = markdown.markdown(content)
            return render_template('view_file.html', file=file, content=html_content, file_type='markdown')
        except Exception as e:
            flash(f'Error reading the file: {str(e)}')
            return redirect(url_for('uploadlist'))

    # Handle other text-based files
    if file_extension in ['.txt', '.csv', '.json', '.xml', '.py', '.html', '.css', '.js', '.rtf']:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return render_template('view_file.html', file=file, content=content, file_type='text')
        except Exception as e:
            flash(f'Error reading the file: {str(e)}')
            return redirect(url_for('uploadlist'))

    # Handle PDF files
    if file.pdf_filename and file.pdf_filename.endswith('.pdf'):
        file_url = url_for('uploaded_file', filename=file.pdf_filename)
        return render_template('view_file.html', file=file, file_url=file_url, file_type='pdf')

    # Handle image files
    if file_extension in ['.png', '.jpg', '.jpeg', '.gif']:
        file_url = url_for('uploaded_file', filename=file.filename)
        return render_template('view_file.html', file=file, file_url=file_url, file_type='image')

    # Unsupported file type
    flash('This file type cannot be displayed.')
    return redirect(url_for('uploadlist'))

@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('mypage'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.verify_password(password):
            login_user(user)
            return redirect(url_for('mypage'))
        else:
            return "Invalid credentials", 401
    return render_template('login.html')

@app.route('/mypage')
@login_required
def mypage():
    return render_template('mypage.html', username=current_user.username)

@celery.task
def convert_to_pdf(input_path, output_path):
    file_extension = os.path.splitext(input_path)[1].lower()
    
    if file_extension in ['.pdf', '.png', '.jpg', '.jpeg', '.gif']:
        return os.path.basename(input_path)
    
    # Check if the file type is supported for conversion
    if file_extension not in SUPPORTED_EXTENSIONS:
        print(f"File {input_path} is not a supported type for conversion, skipping.")
        return

    if file_extension in SUPPORTED_EXTENSIONS:
        try:
            subprocess.call(['libreoffice', '--headless', '--convert-to', 'pdf', input_path, '--outdir', output_path])
            pdf_filename = os.path.splitext(os.path.basename(input_path))[0] + '.pdf'
            return pdf_filename
        except Exception as e:
            print(f"Error during PDF conversion: {e}")
            return None
    else:
        print(f"File {input_path} is not a supported type for conversion, skipping.")
        return None

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        comment_content = request.form.get('comment')
        urgency = request.form.get('urgency', '일반')
        type_ = request.form.get('type', '개인')

        if 'document' in request.files and request.files['document'].filename != '':
            file = request.files['document']
            filename = secure_filename(file.filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            size = os.path.getsize(file_path)

            # Convert to PDF if necessary
            pdf_filename = convert_to_pdf(file_path, app.config['UPLOAD_FOLDER'])

            new_file = File(
                filename=filename,
                pdf_filename=pdf_filename,
                uploader_id=current_user.id,
                urgency=urgency,
                type=type_,
                size=size,
                comment=comment_content,
                upload_time=datetime.utcnow()
            )
            db.session.add(new_file)
            db.session.commit()

            # Log the upload action
            new_log = ActivityLog(
                user_id=current_user.id,
                action='Uploaded a file',
                details=f'File: {filename}'
            )
            db.session.add(new_log)
            db.session.commit()

            return redirect(url_for('uploadlist'))
        elif comment_content:
            # Handle comment upload
            new_comment = Comment(
                content=comment_content,
                uploader_id=current_user.id
            )
            db.session.add(new_comment)
            db.session.commit()

            # Log the comment action
            new_log = ActivityLog(
                user_id=current_user.id,
                action='Uploaded a comment',
                details=f'Comment: {comment_content}'
            )
            db.session.add(new_log)
            db.session.commit()

            return redirect(url_for('uploadlist'))
        else:
            flash('No file or comment provided.', 'error')
            return redirect(url_for('upload'))
    return render_template('upload.html')

@app.route('/uploadlist')
@login_required
def uploadlist():
    if current_user.is_admin:
        files = File.query.all()
        comments = Comment.query.all()
    else:
        files = File.query.filter_by(uploader_id=current_user.id).all()
        comments = Comment.query.filter_by(uploader_id=current_user.id).all()
    return render_template('uploadlist.html', files=files, comments=comments)

@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    file = File.query.get_or_404(file_id)
    if not current_user.is_admin and file.uploader_id != current_user.id:
        return "Unauthorized", 403
    new_log = ActivityLog(
        user_id=current_user.id,
        action='Downloaded a file',
        details=f'File: {file.filename}'
    )
    db.session.add(new_log)
    db.session.commit()
    return send_from_directory(app.config['UPLOAD_FOLDER'], file.filename, as_attachment=True)

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete(file_id):
    file = File.query.get_or_404(file_id)
    if not current_user.is_admin and file.uploader_id != current_user.id:
        return "Unauthorized", 403
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    db.session.delete(file)
    db.session.commit()
    return redirect(url_for('uploadlist'))

@app.route('/edit/<int:file_id>', methods=['GET', 'POST'])
@login_required
def edit(file_id):
    file = File.query.get_or_404(file_id)
    if not current_user.is_admin and file.uploader_id != current_user.id:
        return "Unauthorized", 403
    if request.method == 'POST':
        file.urgency = request.form.get('urgency')
        file.type = request.form.get('type')
        db.session.commit()
        return redirect(url_for('uploadlist'))
    return render_template('edit_upload.html', file=file)

@app.route('/calendar')
@login_required
def calendar():
    leaves = current_user.leaves
    return render_template('calendar.html', leaves=leaves, timedelta=timedelta)

@app.route('/request_leave', methods=['GET', 'POST'])
@login_required
def request_leave():
    if request.method == 'POST':
        start_date_str = request.form['start_date']
        end_date_str = request.form['end_date']
        reason = request.form['reason']

        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()

        new_leave = Leave(
            user_id=current_user.id,
            start_date=start_date,
            end_date=end_date,
            reason=reason,
            status='Pending'
        )

        requested_days = new_leave.total_days()
        available_days = current_user.calculate_days_off()

        if available_days >= requested_days:
            db.session.add(new_leave)
            new_log = ActivityLog(
                user_id=current_user.id,
                action='Requested leave',
                details=f'Start: {start_date_str}, End: {end_date_str}, Reason: {reason}'
            )
            db.session.add(new_log)

            db.session.commit()
            flash('Leave request submitted successfully.')
        else:
            flash('Insufficient days off available.')

        return redirect(url_for('calendar'))
    else:
        # Handle date clicked from calendar
        date_str = request.args.get('date')
        reason = request.args.get('reason')
        if date_str and reason:
            date_clicked = datetime.strptime(date_str, '%Y-%m-%d').date()
            new_leave = Leave(
                user_id=current_user.id,
                start_date=date_clicked,
                end_date=date_clicked,
                reason=reason,
                status='Pending'
            )

            if current_user.calculate_days_off() >= 1:
                db.session.add(new_leave)
                db.session.commit()
                flash('Leave request submitted successfully.')
            else:
                flash('Insufficient days off available.')
            return redirect(url_for('calendar'))

        return "Invalid request", 400

@app.route('/admin/leaves', methods=['GET', 'POST'])
@login_required
def manage_leaves():
    if not current_user.is_admin:
        return "Unauthorized", 403

    approve_id = request.args.get('approve')
    reject_id = request.args.get('reject')

    if approve_id:
        leave = Leave.query.get(approve_id)
        if leave and leave.status == 'Pending':
            leave.status = 'Approved'
            # Log the approval action
            new_log = ActivityLog(
                user_id=current_user.id,
                action='Approved a leave request',
                details=f'Leave ID: {leave.id}, User: {leave.user.username}'
            )
            db.session.add(new_log)
            db.session.commit()
    elif reject_id:
        leave = Leave.query.get(reject_id)
        if leave and leave.status == 'Pending':
            leave.status = 'Rejected'
            # Log the rejection action
            new_log = ActivityLog(
                user_id=current_user.id,
                action='Rejected a leave request',
                details=f'Leave ID: {leave.id}, User: {leave.user.username}'
            )
            db.session.add(new_log)
            db.session.commit()

    if request.method == 'POST':
        leave_id = request.form['leave_id']
        action = request.form['action']
        leave = Leave.query.get(leave_id)

        if action == 'approve':
            leave.status = 'Approved'
            new_log = ActivityLog(
                user_id=current_user.id,
                action='Approved a leave request',
                details=f'Leave ID: {leave.id}, User: {leave.user.username}'
            )
        elif action == 'reject':
            leave.status = 'Rejected'
            new_log = ActivityLog(
                user_id=current_user.id,
                action='Rejected a leave request',
                details=f'Leave ID: {leave.id}, User: {leave.user.username}'
            )

        db.session.add(new_log)
        db.session.commit()

    leaves = Leave.query.all()
    return render_template('admin_leaves.html', leaves=leaves)

@app.route('/admin/logs')
@login_required
def admin_logs():
    if not current_user.is_admin:
        return "Unauthorized", 403
    # Fetch all logs
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    return render_template('admin_logs.html', logs=logs)

@app.route('/admin/calendar')
@login_required
def admin_calendar():
    if not current_user.is_admin:
        return "Unauthorized", 403
    leaves = Leave.query.all()
    logs = ActivityLog.query.filter(ActivityLog.action.ilike('%leave request%')).order_by(ActivityLog.timestamp.desc()).limit(10).all()
    return render_template('admin_calendar.html', leaves=leaves, logs=logs, timedelta=timedelta)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0')

