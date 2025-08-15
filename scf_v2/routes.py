
from scf_v2 import app, db, bcrypt
from flask import render_template, flash, request, url_for, session, redirect, send_file
import json
from bson.objectid import ObjectId
import datetime

@app.route('/home', methods=["GET", "POST"])
def home():
    user = db.Users.find_one({"_id": ObjectId(session.get("userid"))})
    umbrellas = list(db.Umbrellas.find())
    users = list(db.Users.find())

    # adding schemes and umbrellas if exists
    for k in users:
        k['umbrella'] = db.Umbrellas.find_one({'_id': ObjectId(k['umbrella_id'])})['umbrella'] if k.get('umbrella_id') else None
        k['scheme'] = db.Schemes.find_one({'_id': ObjectId(k['scheme_id'])})['scheme_name'] if k.get('scheme_id') else None

    user['umbrella'] = db.Umbrellas.find_one({'_id': ObjectId(user['umbrella_id'])})['umbrella'] if user.get('umbrella_id') != "" else None
    
    return render_template("home.html",
                           user = user,
                           umbrellas = umbrellas,
                           users = users,
                           date = datetime.datetime.today())


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
            "email": form_info["email"].strip(),
            "password": bcrypt.generate_password_hash(form_info["password"].strip()).decode("utf-8"),
            "role": "Administrator",
            "active_status": True
        })
        flash("You have been registered successfully!", "success")
        return redirect(url_for("login"))
    else:
        return render_template("register.html")
    

@app.route('/add_umbrella', methods=["POST"])
def add_umbrella():
    form_info = request.form
    existing_umbrella = db.Umbrellas.find_one({"umbrella": form_info['umbrella'].strip()})
    
    if existing_umbrella != None:
        flash('umbrella already exists!', 'warning')
        return redirect(url_for("home"))
    
    db.Umbrellas.insert_one({
        "umbrella": form_info["umbrella"].strip()
        })
    flash('umbrella added successfully!', 'success')
    return redirect(url_for("home"))


@app.route('/edit_umbrella', methods=["POST"])
def edit_umbrella():
    form_info = request.form
    existing_umbrella = db.Umbrellas.find_one({"umbrella": form_info['umbrella'].strip()})
    if existing_umbrella != None:
        flash('umbrella already exists!', 'warning')
        return redirect(url_for("home"))

    db.Umbrellas.update_one({"_id": ObjectId(form_info['umbrella_id'])}, {
        "$set": {"umbrella": form_info["umbrella"].strip()}
    })
    flash('umbrella info edited successfully!', 'success')
    return redirect(url_for("home"))


@app.route('/delete_umbrella', methods=["POST"])
def delete_umbrella():
    form_info = request.form
    existing_users = list(db.Users.find({"umbrella_id": ObjectId(form_info['umbrella_id'])}))
    if len(existing_users) != 0:
        flash('umbrella has registered employees!', 'danger')
        return redirect(url_for("home"))
    db.Umbrellas.delete_one({"_id": ObjectId(form_info['umbrella_id'])})
    flash('umbrella has been deleted successfully!', 'success')
    return redirect(url_for("home"))



@app.route('/update_profile', methods=["POST"])
def update_profile():
    form_info = request.form
    user_info = db.Users.find_one({"_id": ObjectId(form_info['user_id'])})
    
    if form_info['email'] != user_info['email'] and db.Users.find_one({'email': form_info['email']}) != None:
        flash('profile update failed, check email!', 'danger')
        return redirect(url_for("home"))

    db.Users.update_one({"_id": ObjectId(form_info['user_id'])}, {
        "$set": {"first_name": form_info["first_name"].strip(),
                "last_name": form_info["last_name"].strip(),
                "email": form_info["email"].strip(),
                "umbrella_id": form_info["umbrella_id"].strip()}
    })
    flash('profile update successful!', 'success')
    return redirect(url_for("home"))

@app.route('/change_password', methods=["POST"])
def change_password():
    form_info = request.form
    if form_info['new_password'] != form_info['confirm_password']:
        flash('passwords dont match', 'danger')
        return redirect(url_for("home"))

    db.Users.update_one({"_id": ObjectId(form_info['user_id'])}, {
        "$set": {"password": bcrypt.generate_password_hash(form_info["new_password"].strip()).decode("utf-8")}
    })
    flash('password changed successfully!', 'success')
    return redirect(url_for("home"))

@app.route('/add_user', methods=["POST"])
def add_user():
    form_info = request.form

    if db.Users.find_one({"email": form_info['email']}) != None:
        flash('email already taken', 'warning')
        return redirect(url_for("home"))
    
    db.Users.insert_one({
        "first_name": form_info['first_name'],
        "last_name": form_info['last_name'],
        "email": form_info['email'],
        "password": bcrypt.generate_password_hash(form_info["password"].strip()).decode("utf-8"),
        "role": form_info['role'],
        "umbrella_id": form_info['umbrella_id'],
        "scheme_id": form_info['scheme_id'],
    })
    flash('user added successfully!', 'success')
    return redirect(url_for("home"))


@app.route('/update_user', methods=["POST"])
def update_user():
    form_info = request.form
    user_info = db.Users.find_one({"_id": ObjectId(form_info['user_id'])})

    if form_info['email'] != user_info['email'] and db.Users.find_one({'email': form_info['email']}) != None:
        flash('email already taken failed, check email!', 'danger')
        return redirect(url_for("home"))

    db.Users.update_one({"_id": ObjectId(form_info['user_id'])}, {
        "$set": {"first_name": form_info["first_name"].strip(),
                "last_name": form_info["last_name"].strip(),
                "email": form_info["email"].strip(),
                "role": form_info['role'],
                "umbrella_id": form_info["umbrella_id"].strip(),
                "scheme_id": form_info["scheme_id"].strip()
                }
    })

    flash('user updated successfully!', 'success')
    return redirect(url_for("home"))


@app.route('/delete_user', methods=["POST"])
def delete_user():
    form_info = request.form
    flash('user deleted successfully!', 'success')
    return redirect(url_for("home"))


@app.route('/change_user_password', methods=["POST"])
def change_user_password():
    form_info = request.form
    flash('user deleted successfully!', 'success')
    return redirect(url_for("home"))