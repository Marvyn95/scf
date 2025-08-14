
from scf_v2 import app
from flask import render_template

@app.route('/', methods=["GET", "POST"])
@app.route('/home', methods=["GET", "POST"])
def home():
    return render_template("home.html")
