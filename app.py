from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    folders = db.relationship('Folder', backref='user', lazy=True)
    files = db.relationship('File', backref='user', lazy=True)

class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    files = db.relationship('File', backref='folder', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    path = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/my_files')
@login_required
def my_files():
    folders = Folder.query.filter_by(user_id=current_user.id).all()
    files = File.query.filter_by(user_id=current_user.id, folder_id=None).all()
    return render_template('my_files.html', folders=folders, files=files)

@app.route('/upload_files', methods=['GET', 'POST'])
@login_required
def upload_files():
    if request.method == 'POST':
        file = request.files['file']
        folder_id = request.form.get('folder_id')
        if file:
            user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
            if not os.path.exists(user_upload_dir):
                os.makedirs(user_upload_dir)
            unique_filename = str(uuid.uuid4())
            file_path = os.path.join(user_upload_dir, unique_filename)
            original_filename = secure_filename(file.filename)
            new_file = File(
                name=original_filename,
                path=file_path,
                user_id=current_user.id,
                folder_id=int(folder_id) if folder_id else None
            )
            db.session.add(new_file)
            db.session.commit()
            file.save(file_path)
            flash(f'Файл "{original_filename}" успешно загружен!', 'success')
            return redirect(url_for('my_files'))
    folders = Folder.query.filter_by(user_id=current_user.id).all()
    return render_template('upload_files.html', folders=folders)

@app.route('/create_folder', methods=['GET', 'POST'])
@login_required
def create_folder():
    if request.method == 'POST':
        folder_name = request.form.get('folder_name')
        if folder_name:
            new_folder = Folder(name=folder_name, user_id=current_user.id)
            db.session.add(new_folder)
            db.session.commit()
            flash(f'Папка "{folder_name}" успешно создана!', 'success')
            return redirect(url_for('my_files'))
    return render_template('create_folder.html')

@app.route('/delete_folder/<int:folder_id>')
@login_required
def delete_folder(folder_id):
    folder = Folder.query.get_or_404(folder_id)
    if folder.user_id != current_user.id:
        flash('У вас нет доступа к этой папке.', 'danger')
        return redirect(url_for('my_files'))
    db.session.delete(folder)
    db.session.commit()
    flash(f'Папка "{folder.name}" успешно удалена!', 'success')
    return redirect(url_for('my_files'))

@app.route('/delete_file/<int:file_id>')
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        flash('У вас нет доступа к этому файлу.', 'danger')
        return redirect(url_for('my_files'))
    if os.path.exists(file.path):
        os.remove(file.path)
    db.session.delete(file)
    db.session.commit()
    flash(f'Файл "{file.name}" успешно удален!', 'success')
    return redirect(url_for('my_files'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
