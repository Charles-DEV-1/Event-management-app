from flask import Flask, request, redirect, render_template, session,url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import RequestEntityTooLarge
import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SECRET_KEY"] = "your_secret_key"
app.config['UPLOAD_DIRECTORY'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = ['.jpg', '.jpeg', '.png', '.gif']
db = SQLAlchemy(app)

class User(db.Model):
    
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(30), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    profile_pic = db.Column(db.String(200), nullable=True)
    role = db.Column(db.String(30), default="user")

    events = db.relationship('Event',backref='organizer',lazy=True)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    title = db.Column(db.String(30), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String,  nullable=False)
    organizer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@app.route('/')
def index():
    events = Event.query.order_by(Event.date.asc()).limit(6).all()
    return render_template('index.html', events=events)
@app.route("/register", methods=["POST","GET"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_pass = request.form.get("confirm_pass")
        role = request.form.get("role")
        files = request.files.get("profile_pic")

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists!","warning")
            return redirect(url_for("register"))
        if password != confirm_pass:
            flash("Password do not match!","warning")
            return redirect(url_for("register"))
        if len(password) < 6:
            flash("Password must be at least 6 characters long!","warning")
            return redirect(url_for("register"))
        if len(password) > 20:
            flash("Password Too long!","warning")
            return redirect(url_for("register"))
        hwz = generate_password_hash(password)

        try:
            if files:
                extension = os.path.splitext(files.filename)[1].lower()
                if extension not in app.config['ALLOWED_EXTENSIONS']:
                    flash("File not supported!","warning")
                    return redirect(url_for("register"))
                filename = secure_filename(files.filename)
                files.save(os.path.join(app.config['UPLOAD_DIRECTORY'], filename)) 
                user = User(username=username,email=email,password=hwz,profile_pic=filename,role=role)
                db.session.add(user)
                db.session.commit()   
                flash("Login Successful!","success")  
                return redirect(url_for("login"))               
        except RequestEntityTooLarge:
            flash("File too Large!","warning")
            return
    return render_template("register.html")    


@app.route("/login", methods = ["POST","GET"])
def login():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash("Invalid")
            return redirect(url_for("login"))
        if user.role == "user":
            session["user_id"] = user.id
            flash("login successful!")
            return redirect(url_for("dashboard"))
        else:
            session["user_id"] = user.id
            flash("login successful!")
            return redirect(url_for("organizer_dashboard"))
    return render_template("login.html")
    
@app.route("/dashboard")    
def dashboard():
    if "user_id" not in session:
        flash("Please Login!","warning")
        return redirect(url_for("login"))
    
    user = User.query.get(session["user_id"])
    if user.role == "organizer":
        flash("Access denied! Organizers can’t access user dashboard.","warning")
        return redirect(url_for("organizer_dashboard"))

    return render_template("dashboard.html", user=user)


@app.route("/organizer_dashboard")    
def organizer_dashboard():
    user = User.query.filter_by(id=session["user_id"]).first()
    if "user_id" not in session or user.role == "user":
        flash("Please Login!","warning")
        return redirect(url_for("login"))
    return render_template("admin_dashboard.html",user=user)

@app.route("/create_event", methods=["POST","GET"])
def create_event():
    user = User.query.filter_by(id=session["user_id"]).first()
    if user.role == "organizer":    
        if "user_id" in session:
            if request.method == "POST":
                title = request.form.get("title")
                description = request.form.get("description")
                location = request.form.get("location")
                date = request.form.get("date")

                try:
                    event_date = datetime.strptime(date, "%Y-%m-%dT%H:%M")
                except ValueError:
                    flash("Invalid date format!", "danger")
                    return redirect(url_for("create_event"))

                events = Event(title=title,description=description,location=location,date=event_date, organizer_id=session["user_id"])
                db.session.add(events)
                db.session.commit()
                flash("Event created successfully!","success")
                return redirect(url_for("create_event"))
            return render_template("create_event.html")
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    if "user_id" in session:
        session.clear()
        flash("Logout successful","success")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/event/<int:id>/edit", methods=["POST","GET"])
def edit(id):
    if "user_id" in session:
        user = User.query.get(session["user_id"])
        if user.role == "organizer":
            event = Event.query.filter_by(id=id).first()
            if request.method == "POST":
                event.title = request.form.get("title")
                event.description = request.form.get("description")
                event.location = request.form.get("location")
                try:
                    event.date = datetime.strptime(request.form.get("date"), "%Y-%m-%dT%H:%M")
                except ValueError:
                    flash("Invalid date format!", "danger")
                    return redirect(url_for("edit", id=id))
                db.session.commit()
                flash("Event updated successfully!","success")
                return redirect(url_for("organizer_dashboard"))
            return render_template("edit_event.html", event=event)
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/event/<int:id>/delete", methods=["POST","GET"])
def delete(id):
    if "user_id" in session:
        user = User.query.get(session["user_id"])
        if user.role == "organizer":
            event = Event.query.filter_by(id=id).first()
            db.session.delete(event)
            db.session.commit()
            flash("Event deleted successfully!","success")
            return redirect(url_for("organizer_dashboard"))
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# USER: View all events
@app.route("/events")
def view_events():
    if "user_id" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))

    events = Event.query.all()  # all events
    return render_template("view_events.html", events=events)


# ORGANIZER: View only their events
@app.route("/my_events")
def my_events():
    if "user_id" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    if user.role != "organizer":
        flash("Access denied! Only organizers can view this page.", "danger")
        return redirect(url_for("dashboard"))

    events = Event.query.filter_by(organizer_id=user.id).all()
    return render_template("my_events.html", events=events)
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    if "user_id" in session:
        return send_from_directory(app.config['UPLOAD_DIRECTORY'], filename)
    return redirect(url_for("login"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    

