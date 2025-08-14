
from scf_v2 import app, db, bcrypt
from flask import render_template, flash, request, url_for, session, redirect, send_file
import json

@app.route('/home', methods=["GET", "POST"])
def home():
    return render_template("home.html")


@app.route('/', methods=["GET", "POST"])
@app.route('/login', methods=["GET", "POST"])
def login():
    form_info = request.form
    if request.method == 'POST':
        user = db.Users.find_one({"email": form_info["email"]})
        if user is None:
            flash('email not registered, contact admin!', 'warning')
            return redirect(url_for('login'))
        if bcrypt.check_password_hash(user["password"], form_info["password"]) is False:
            flash('incorrect password', 'danger')
            return redirect(url_for('login'))
        if user['active_status'] == False:
            flash('your account is deactivated, contact your admin!', 'danger')
            return redirect(url_for('login'))
        if bcrypt.check_password_hash(user["password"], form_info["password"]) is True:
            session['userid'] = str(user['_id'])
            flash("Successful login!", "success")
            return redirect(url_for('home'))
    else:
        return render_template("login.html")
    
@app.route('/logout', methods=["GET"])
def logout():
    session.clear()
    flash("log out successfull!", "info")
    return redirect(url_for("login"))


@app.route('/register', methods=["GET", "POST"])
def register():

    with open("../config.json") as config_file:
        config = json.load(config_file)

    if request.method == 'POST':
        form_info = request.form
        if form_info['admin_password'] != config['ADMIN_PASSWORD']:
            flash('wrong admin password!', 'danger')
            return redirect(url_for('register'))
        
        if form_info['password'] != form_info['confirm_password']:
            flash('passwords dont match!', 'error')
            return redirect(url_for('register'))
        
        if db.Users.find_one({"email": form_info["email"]}) != None:
            flash('email already taken, use another!', 'danger')
            return redirect(url_for('register'))
                
        db.Users.insert_one({
            "first_name": form_info["first_name"].strip(),
            "last_name": form_info["last_name"].strip(),
            "email": form_info["email"],
            "password": bcrypt.generate_password_hash(form_info["password"].strip()).decode("utf-8"),
            "role": "Administrator",
            "active_status": True
        })
        flash("You have been registered successfully!", "success")
        return redirect(url_for("login"))
    else:
        return render_template("register.html")


