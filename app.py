import os
import string
import random
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


# /create
# Create a new event
@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    # User reached route via GET
    # Usually by clicking on it in the header
    if request.method == "GET":
        return render_template("create.html")

    # User reached route via POST
    # Usually by filling out details for a new event and clicking submit
    if request.method == "POST":
        # Get data from form
        name = request.form.get("name")
        description = request.form.get("description")
        date = request.form.get("date")
        slots = request.form.get("num_slots")

        # Create UUID
        # This is a unique 8-digit (A-Z) ID to identify each event
        # Used for email referral links, search, etc
        uid = ""

        while uid == "":
            # Create a random 8-character string
            uid = "".join(random.choice(string.ascii_uppercase) for _ in range(8))

            # See if an event with that ID already exists
            if db.execute("SELECT * FROM events WHERE hash = ?", uid):
                uid = "";
                print("Seems like there's already an event with this ID")
    
        # add the new event to the events table
        db.execute("INSERT INTO events (name, description, date, owner_id, hash) VALUES (?, ?, ?, ?, ?)",
		           name, description, data, session.get("user_id"), uid)
                   
        # get the event id
        event_id = db.execute("SELECT * FROM events WHERE hash = ?", uid)[0]['id']

        # create slots for the event
        for i in range(slots):
            db.execute("INSERT INTO slots (time_start, time_end, event_id, user_id VALUES (?, ?, ?, ?",
                       0, 0, event_id, 0)

        # create slots dict, mostly for passing to the next function
        slots = db.execute("SELECT * FROM slots WHERE event_id = ?", event_id)

        return render_tempate("create_slots.html", slots=slots)


# /create_slots
# determine the start and end times of each slot for an event
@app.route("/create_slots", methods=["GET", "POST"])
def create_slots():
    # user reached route via GET
    # either through the event creation process, or by requesting to edit the event
    if request.method == "GET":
        return render_template("create_slots.html", slots=slots)

    # User reached route via POST
    # This happens when the user submits start and end times for slots
    if request.method == "POST":
        return apology("TODO")


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
        
        email = request.form.get("email")
        rows = db.execute("SELECT * FROM users WHERE email = ?", email)

        # Ensure that all fields were filled out
        if not email or not request.form.get("password"):
            return apology("Please fill out all of the fields")

        # Ensure the account exists
        if len(rows) == 0:
            return apology("Couldn't find an account with this email")

        # Check the password
        pw = rows[0]['hash']
        if not check_password_hash(pw, request.form.get("password")):
            return apology("invalid password")

        # Create user_id to remember which user is logged in
        session["user_id"] = rows[0]["id"]

        return redirect("/")


# /logout
# log the user out
@app.route("/logout")
def logout():
    # forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


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
        if not check_password_hash(pw_hash, request.form.get("confirmation")):
            return apology("Please make sure your passwords match")

        # Ensure the email doesn't already exist
        if len(db.execute("SELECT * FROM users WHERE email = ?", email)) > 0:
            return apology("There is already an account with this email address!")

        # Once all checks have been passed, create the account
        db.execute("INSERT INTO users (name, hash, email) VALUES (?, ?, ?)", name, pw_hash, email)
        
        # Return to the login page
        return render_template("login.html")
