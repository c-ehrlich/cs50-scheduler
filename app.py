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

# (!) SHOULD ATTEMPT TO DO THIS IN A BETTER WAY (BY SETTING THINGS TO NULL INSTEAD OF 0)
# If there is no user with id=0, then create one
# This is the user that slots.user_id is initialized to when making slots
# Because I can't figure out how to send NULL to sql
# (!) SHOULD ATTEMPT TO DO THIS IN A BETTER WAY (BY SETTING THINGS TO NULL INSTEAD OF 0)
if not db.execute("SELECT * FROM users WHERE id=0"):
    db.execute("INSERT INTO users (id, name, hash, email, is_moderator) VALUES (0, '0', '0', '0', 0)")

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
        slots = int(request.form.get("num_slots"))

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
		           name, description, date, session.get("user_id"), uid)
                   
        # get the event id
        event_id = db.execute("SELECT * FROM events WHERE hash = ?", uid)[0]['id']

        # create slots for the event
        for i in range(slots):
            db.execute("INSERT INTO slots (time_start, time_end, event_id, user_id) VALUES (?, ?, ?, ?)",
                       0, 0, event_id, 0)

        # create slots dict, mostly for passing to the next function
        slots = db.execute("SELECT * FROM slots WHERE event_id = ?", event_id)

        return render_template("create_slots.html", slots=slots)


# /create_slots
# determine the start and end times of each slot for an event
@app.route("/create_slots", methods=["GET", "POST"])
@login_required
def create_slots():
    # user reached route via GET
    # either through the event creation process, or by requesting to edit the event
    if request.method == "GET":
        return render_template("create_slots.html", slots=slots)

    # User reached route via POST
    # This happens when the user submits start and end times for slots
    if request.method == "POST":
        print(f"TKTK - {event_id} - CURRENTLY IN create_slots/POST")
        
        # Create a dictionary with all the slots that were created
        # Example formatting:
        # {'70.start': '09:00', '70.end': '10:00', '71.start': '10:00', '71.end': '11:00'}
        slots = dict(request.form)

        for key, value in slots.items():
            # Split each dictionary entry into data that we can use
            temp = key.split(".")
            index = int(temp[0])
            start_end = temp[1]
            
            # Update the slot start and end times in the database
            if start_end == "start":
                db.execute("UPDATE slots SET time_start = ? WHERE id = ?", value, index)
            if start_end == "end":
                db.execute("UPDATE slots SET time_end = ? WHERE id = ?", value, index)

        # TKTK TODO maybe end by showing a nice layout of the event with slot start and end times?
        return render_template("view.html")


# /created
# shows all meetings created by the active user
@app.route("/created")
@login_required
def created():
    if request.method == "GET":
        meetings = db.execute("SELECT events.id, events.hash, events.date FROM events " +
                              "JOIN users ON events.owner_id = users.id " +
                              "WHERE users.id = ?",
                              session.get("user_id"))
        return render_template("created.html", meetings=meetings)

    else:
        return apology("No PUSH route exists yet for /created")


# /join
# prompts the user for a meeting hash, then redirects to join the meeting with that hash
@app.route("/join", methods=["GET", "POST"])
@login_required
def join_id():

    if request.method == "GET":
        return render_template("join.html")

    if request.method == "POST":
        hash_id = request.form.get("hash_id")
        return redirect(f"join/{hash_id}")


# /join/hash
# Join a meeting with the selected hash (give a form to select a time slot)
# If no hash is provided, display a field to enter a form
@app.route("/join/<hash>", methods=["GET", "POST"])
@login_required
def join(hash):

    # User reached route via GA
    if request.method == "GET":
        if not db.execute("SELECT * FROM events WHERE hash = ?", hash):
            return apology("There is no event with this hash")
        return apology("Found your event, but TODO")
    
    if request.method == "POST":
        return apology("TODO")


# /joined
# shows all meetings joined by the active user
@app.route("/joined")
@login_required
def joined():
    if request.method == "GET":
        meetings = db.execute("SELECT events.id, events.hash, events.date, slots.time_start, slots.time_end FROM events " +
                              "JOIN slots ON events.id = slots.event_id " +
                              "JOIN users ON slots.user_id = users.id " +
                              "WHERE users.id = ?",
                              session.get("user_id"))
        return render_template("joined.html", meetings=meetings)

    else:
        return apology("No PUSH route exists yet for /joined")


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


# /view/event_id
# Views an event with a certain ID
# Views it as a creator if user is the creator
# Views it as a participant / potential participant if the user is not the creator
@app.route("/view/<event_id>")
@login_required
def view(event_id):
    event = db.execute("SELECT * FROM events WHERE hash = ?", event_id)
    slots = db.execute("SELECT * FROM slots " +
                       "JOIN events ON events.id = slots.event_id " +
                       "JOIN users ON events.user_id = users.id" +
                       "WHERE events.hash = ?", 
                       event_id)
    return render_template("view.html", event=event, slots=slots)