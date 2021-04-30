import os
from datetime import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///scheduler.db")


@app.route("/")
@login_required
def index():
    return render_template("index.html")


# /login
# Log in to the website
@app.route("/login", methods=["GET", "POST"])
def login():
    # forget any user_id
    session.clear()

    # User reached route via GET
    # For example by clicking a link or via redirect
    if request.method == "GET":
        return render_template("login.html")

    # User reached route via POST
    # ie by filling otu the form on /login.html and pressing submit
    if request.method == "POST":
        return apology("TODO")


# /register
# Register a new account
@app.route("/register", methods=["GET", "POST"])
def register():
    # forget any user_id
    session.clear()

    # User reached route via GET
    # For example by clicking a link or via redirect
    if request.method == "GET":
        return render_template("register.html")

    # User reached route via POST
    # ie by filling out the form on /register.html and pressing submit
    if request.method == "POST":

        # Get data from form
        name = request.form.get("name")
        email = request.form.get("email")
        pw_hash = generate_password_hash(request.form.get("password"))
        pw_conf = generate_password_hash(request.form.get("confirmation"))

        # Ensure all fields were filled out
        if not name or not email or not pw_hash or not pw_conf:
            return apology("Please fill out all the fields")

        # Ensure the passwords match
        if not pw_hash == pw_conf:
            return apology("Please make sure your passwords match")
        

        return apology("TODO")
        