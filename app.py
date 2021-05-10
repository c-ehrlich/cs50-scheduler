import os
import string
import random
from datetime import datetime, date, timedelta

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

# old helper functions
from helpers import apology, login_required

# new helper functions
from helpers import delete_event, join_event, leave_event, verify_slots, get_start_time, get_end_time, week_day

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

# If there is no user with id=0, then create one
# This is the user that slots.user_id is initialized to when making slots
if not db.execute("SELECT * FROM users WHERE id = 0"):
    db.execute("INSERT INTO users (id, username, hash, email, is_moderator) VALUES (0, '0', '0', '0', 0)")

@app.route("/")
@login_required
def index():
    user = session.get("user_id")

    # decide how many days of future events to display on the front page
    days_to_display = 7

    # create variables for today and the last day of events to display on the front page
    today = date.today()
    soon = today + timedelta(days = days_to_display)

    # get event information for front page
    events = db.execute("SELECT events.id, events.owner_id, events.eventname, events.description, events.hash, events.date, slots.time_start, slots.time_end " +
                        "FROM events " +
                        "JOIN slots ON events.id = slots.event_id " +
                        "JOIN users ON slots.user_id = users.id " +
                        "WHERE (users.id = ? OR events.owner_id = ?) " +
                        "AND events.date >= ? AND events.date < ?"
                        "GROUP BY events.id " + 
                        "ORDER BY events.date ASC",
                        user, user, today, soon)

    # add total start time
    for event in events:
            event['time_event_start'] = get_start_time(db, event['hash'])
            event['time_event_end'] = get_end_time(db, event['hash'])
            if user == event['owner_id']:
                event['type'] = "Hosting"
            else:
                event['type'] = "Attending"
            event['weekday'] = week_day(event['date'])

    return render_template("index.html", events=events)


# /account
# GET shows the account page
# POST edits account information
@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    # User reached route via GET
    # Usually by clicking on it in the header
    if request.method == "GET":
        return render_template("account.html")

    # User reached route via POST
    # Usually by filling out the change account details form
    if request.method == "POST":

        # attempt to load user from db
        user_id = session.get("user_id")

        # check that current password is correct
        pw =  db.execute("SELECT * FROM users WHERE id = ?", user_id)[0]['hash']
        if not check_password_hash(pw, request.form.get("current_pw")):
            return apology("invalid password")

        # get form data TK move down as far as possible
        new_name = request.form.get("name")
        new_email = request.form.get("email")
        new_password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check new password matches new confirmation
        if new_password != confirmation:
            return apology("please make sure the new password and confirmation match")

        # update values in users db
        if new_name != "":
            db.execute("UPDATE users SET username = ? WHERE id = ?", new_name, user_id)
        if new_email != "":
            db.execute("UPDATE users SET email = ? WHERE id = ?", new_email, user_id)
        if new_password != "" and new_password == confirmation:
            db.execute("UPDATE users SET hash = ?", generate_password_hash(new_password))

        session.clear()

        # show a banner that their settings were updated

        return redirect("/")


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
        # Validate Name
        name = request.form.get("name")
        if name == "":
            return apology("Name must be at least 1 character long")

        # Validate Description
        description = request.form.get("description")
        if description == "":
            return apology("Description must be at least 1 character long")
        
        # Check if date is properly formatted
        date_string = request.form.get("date")       
        date_format = "%Y-%m-%d"

        try:
            datetime.strptime(date_string, date_format)
        except ValueError:
            return apology("Please enter a valid date")

        # Check that the user isn't trying to make an event in the past
        date_formatted = datetime.strptime(date_string, date_format).date()
        if date_formatted < date.today():
            return apology("Please don't try to schedule a event in the past. That's rude!")

        # Make sure that the number of slots is an integer between 1 and 50
        slots = request.form.get("num_slots")
        if not slots.isnumeric():
            return apology("Number of slots needs to be an integer between 1 and 50!")
        slots = int(slots)
        if not 0 < slots <= 50:
            return apology("Number of slots needs to be an integer between 1 and 50!")

        # Create UUID/hash
        # This is a unique 8-digit (A-Z) ID to identify each event
        # Used for email referral links, search, etc
        uid = ""

        while uid == "":
            # Create a random 8-character string
            uid = "".join(random.choice(string.ascii_uppercase) for _ in range(8))

            # See if an event with that ID already exists
            if db.execute("SELECT * FROM events WHERE hash = ?", uid):
                uid = "";
    
        # add the new event to the events table
        db.execute("INSERT INTO events (eventname, description, date, owner_id, hash) VALUES (?, ?, ?, ?, ?)",
		           name, description, date_string, session.get("user_id"), uid)
                   
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
        # Create a dictionary with all the slots that were created
        # Example formatting:
        # {'70.start': '09:00', '70.end': '10:00', '71.start': '10:00', '71.end': '11:00'}
        slots = dict(request.form)

        for key, value in slots.items():
            # Split each dictionary entry into data that we can use
            temp = key.split(".")
            index = int(temp[0])
            start_end = temp[1]

            # validate that it's valid times     
            date_format = "%H:%M"
            try:
                datetime.strptime(value, date_format)
            except ValueError:
                # delete the event
                event_id = db.execute("SELECT event_id FROM slots WHERE id = ?", index)[0]['event_id']
                delete_event(db, event_id, session.get("user_id"))
                return apology("Please submit valid times for all slots")
            
            # Update the slot start and end times in the database
            if start_end == "start":
                db.execute("UPDATE slots SET time_start = ? WHERE id = ?", value, index)
            if start_end == "end":
                db.execute("UPDATE slots SET time_end = ? WHERE id = ?", value, index)

        # get the event hash to pass to the view function
        # oh god this is such a dirty hack
        slot_id = int(list(slots.keys())[0].split(".")[0])
        event_id = db.execute("SELECT event_id FROM slots WHERE id = ?", slot_id)[0]['event_id']
        event_hash = db.execute("SELECT hash FROM events WHERE id = ?", event_id)[0]['hash']

        # Make sure nothing funny is going on with the slots
        slots = db.execute("SELECT time_start, time_end FROM slots WHERE event_id = ?", event_id)
        apology_text = verify_slots(slots)
        if apology_text != "":
            return apology(f"{apology_text}")

        return redirect(f"view/{event_hash}")


# /created
# shows all events created by the active user
@app.route("/created")
@login_required
def created():
    if request.method == "GET":

        # Get today's daye
        today = date.today().strftime("%Y-%m-%d")

        # Get list of today & future events created by the active user
        events = db.execute("SELECT events.id, users.username, events.eventname, events.description, events.hash, events.date FROM events " +
                              "JOIN users ON events.owner_id = users.id " +
                              "WHERE users.id = ? " +
                              "AND events.date >= ? " +
                              "ORDER BY events.date ASC",
                              session.get("user_id"), today)

        # Get list of past events created by the active user
        pastmeet = db.execute("SELECT events.id, users.username, events.eventname, events.description, events.hash, events.date FROM events " +
                              "JOIN users ON events.owner_id = users.id " +
                              "WHERE users.id = ? " +
                              "AND events.date < ? " +
                              "ORDER BY events.date DESC",
                              session.get("user_id"), today)
        
        # Add information about free, full, and total slots to the event dictionary
        # Also Add information about event start time to the events
        for event in events + pastmeet:
            event['slots_total'] = db.execute("SELECT COUNT(*) FROM slots WHERE event_id = ?", 
                                                event['id'])[0]['COUNT(*)']
            event['slots_empty'] = db.execute("SELECT COUNT(*) FROM slots WHERE event_id = ? AND user_id = 0",
                                                event['id'])[0]['COUNT(*)']            
            event['slots_full'] = event['slots_total'] - event['slots_empty']
            event['time_event_start'] = get_start_time(db, event['hash'])
            event['time_event_end'] = get_end_time(db, event['hash'])

        # Show the selected events
        return render_template("created.html", events=events, pastmeet=pastmeet)

    else:
        return apology("No PUSH route exists yet for /created")


# /delete_from_created
# attempts to delete an event, then reloads the created events list
@app.route("/delete_from_created/<event_id>", methods=["POST"])
@login_required
def delete_from_created(event_id):
    if request.method == "POST":
        delete_event(db, event_id, session.get("user_id"))
        return redirect("/created")


# /delete_from_view
# attempts to delete an event, then returns home
@app.route("/delete_from_view/<event_id>", methods=["POST"])
@login_required
def delete_from_view(event_id):
    if request.method == "POST":
        delete_event(db, event_id, session.get("user_id"))
        return redirect("/")


# edit/<event_id>
# edits an event
@app.route("/edit/<event_hash>", methods=["GET", "POST"])
@login_required
def edit(event_hash):
    # Get here by clicking on edit, or calling it from somewhere else
    if request.method == "GET":

        # check if the event exists
        if (db.execute("SELECT COUNT(*) FROM events WHERE hash = ?", event_hash)[0]['COUNT(*)']) != 1:
            return apology(f"Could not find an event with hash {event_hash}")

        # get the event we're editing
        event = db.execute("SELECT * FROM events WHERE hash = ?", event_hash)[0]

        # check if the user owns the event
        if session.get("user_id") != event['owner_id']:
            return apology("Sorry, you don't own this event!")

        # get the slots
        slots = db.execute("SELECT * FROM slots WHERE event_id = ? ORDER BY time_start ASC", event['id'])

        # calculate event start and end times
        event['time_event_start'] = get_start_time(db, event['hash'])
        event['time_event_end'] = get_end_time(db, event['hash'])

        # show the edit page for that event
        return render_template("edit.html", event=event, slots=slots)

    # Get here by editing the name, description, or date on the edit page and pressing submit
    if request.method == "POST":

        # check if the event exists
        if (db.execute("SELECT COUNT(*) FROM events WHERE hash = ?", event_hash)[0]['COUNT(*)']) != 1:
            return apology(f"abc Could not find an event with hash {event_hash}")

        # get the event we're editing
        event = db.execute("SELECT * FROM events WHERE hash = ?", event_hash)[0]

        # check if the user owns the event
        if session.get("user_id") != event['owner_id']:
            return apology("Sorry, you don't own this event!")

        # validate name input
        name = request.form.get("name")
        if name == "":
            return apology("Name must be at least 1 character long")

        # validate description input
        description = request.form.get("description")
        if description == "":
            return apology("Description must be at least 1 character long")

        # validate date input
        date_input = request.form.get("date")
        date_format = "%Y-%m-%d"

        try:
            datetime.strptime(date_input, date_format)
        except ValueError:
            return apology("Please enter a valid date")
        except:
            return apology("Unknown type of error in strptime")
        
        date_formatted = datetime.strptime(date_input, date_format).date()
        if date_formatted < date.today():
            return apology("Please don't try to schedule a event in the past. That's rude!")

        # update event & prepare to feed it to return function
        db.execute("UPDATE events SET eventname = ?, description = ?, date = ? WHERE hash = ?",
                   name, description, date_input, event['hash'])
        event = db.execute("SELECT * FROM events WHERE hash = ?", event_hash)[0]

        slots = db.execute("SELECT * FROM slots WHERE event_id = ? ORDER BY time_start ASC", event['id'])

        return render_template("edit.html", event=event, slots=slots)

# /home
# returns the user to the index page after completing some action
@app.route("/home")
@login_required
def home():

    if request.method == "GET":
        return redirect("/")


# /join
# prompts the user for a event hash, then redirects to join the event with that hash
@app.route("/join", methods=["GET", "POST"])
@login_required
def join_id():

    if request.method == "GET":
        return render_template("join.html")

    if request.method == "POST":
        hash_id = request.form.get("hash_id")

        try:
            event = db.execute("SELECT * FROM events WHERE hash = ?", hash_id)[0]
        except:
            return apology("There is no event with this hash")

        return redirect(f"/view/{hash_id}")


# /join/hash/slot
# User attempts to join a certain slot of a event
# If they don't have a slot yet, it will give them that slot
# If they already have a slot, it will switch them to that slot
@app.route("/join/<event_hash>/<event_slot>", methods=["POST"])
@login_required
def join_slot(event_hash, event_slot):
    if request.method == "POST":
        user = session.get("user_id")

        # don't need to sanitize input here because the join_event function does it
        join_event(db, event_hash, event_slot, user)
        return redirect(f"/view/{event_hash}")


# /joined
# shows all events joined by the active user
@app.route("/joined")
@login_required
def joined():
    if request.method == "GET":

        # get today's date
        today = date.today().strftime("%Y-%m-%d")

        # get today & future events
        events = db.execute("SELECT events.id, events.eventname, events.description, events.hash, events.date, slots.time_start, slots.time_end FROM events " +
                              "JOIN slots ON events.id = slots.event_id " +
                              "JOIN users ON slots.user_id = users.id " +
                              "WHERE users.id = ? " +
                              "AND events.date >= ? " +
                              "ORDER BY events.date ASC",
                              session.get("user_id"), today)

        # get past events
        pastmeet = db.execute("SELECT events.id, events.eventname, events.description, events.hash, events.date, slots.time_start, slots.time_end FROM events " +
                              "JOIN slots ON events.id = slots.event_id " +
                              "JOIN users ON slots.user_id = users.id " +
                              "WHERE users.id = ? " +
                              "AND events.date < ? " +
                              "ORDER BY events.date DESC",
                              session.get("user_id"), today)

         # Add information about event start time and event end time to events and pastmeets
        for event in events + pastmeet:
            event['time_event_start'] = get_start_time(db, event['hash'])
            event['time_event_end'] = get_end_time(db, event['hash'])

        return render_template("joined.html", events=events, pastmeet=pastmeet)

    else:
        return apology("No PUSH route exists yet for /joined")


# /leave/event_hash
# makes a user leave a event with a certain hash
@app.route("/leave/<event_hash>", methods=["POST"])
@login_required
def leave(event_hash):
    if request.method == "POST":
        leave_event(db, event_hash, session.get("user_id"))
        return redirect(f"/view/{event_hash}")


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
        db.execute("INSERT INTO users (username, hash, email) VALUES (?, ?, ?)", name, pw_hash, email)
        
        # Return to the login page
        return render_template("login.html")


# /reset_password
# resets a chosen user's password
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "GET":
        return render_template("reset_pw.html")

    if request.method == "POST":
        email = request.form.get("email")
        user = db.execute("SELECT * FROM users WHERE email = ?", email)
        if len(user) != 1:
            return apology("Could not find a user with that email address")
        pw = generate_password_hash("temp1234")
        db.execute("UPDATE users SET hash = ? WHERE email = ?", pw, email)

        # send a banner saying the new password is temp1234

        return render_template("login.html")


# /remove
# removes an attendee from a event
# works only if the user is the owner of the event
@app.route("/remove/<event>/<user>", methods=["POST"])
@login_required
def remove(event, user):
    if request.method == "POST":
        
        # Ensure that this is being attempted only by the owner of the event
        currentuser = session.get("user_id")
        owner = db.execute("SELECT owner_id FROM events WHERE hash = ?", event)[0]['owner_id']
        if currentuser != owner:
            return apology("Only the owner of an event can cancel other people's appointments")

        # remove the selected user from the event, then reload the event view
        leave_event(db, event, user)
        return redirect(f"/view/{event}")


# /slot_add/event_hash
# adds a new slot to the event with a specified event id
@app.route("/slot_add/<event_hash>", methods=["POST"])
@login_required
def slot_add(event_hash):
    if request.method == "POST":
        event = db.execute("SELECT id, eventname, description, date, hash, owner_id "
                           "FROM events WHERE hash = ?",
                           event_hash)[0];

        # check that the user owns the event
        if session.get("user_id") != event['owner_id']:
            return apology("You don't own this event :(")

        # get the new slot info and save it to some vars
        slot_start = request.form.get("slot_start")
        slot_end = request.form.get("slot_end")    
        # check that start and end are both valid times
        date_format = "%H:%M"
        try:
            datetime.strptime(slot_start, date_format)
            datetime.strptime(slot_end, date_format)
        except ValueError:
            return apology("strptime didn't like your formatting - ValueError")
        except:
            return apology("strptime didn't like your formatting - Some other kind of error")

        # check end is after start
        if slot_start >= slot_end:
            return apology("Slot needs to end AFTER it starts!")

        # check that after adding this slot all the slots would still be without overlap
        # insert the row
        db.execute("INSERT INTO slots (time_start, time_end, event_id, user_id) VALUES (?, ?, ?, ?)",
                    slot_start, slot_end, event['id'], 0)

        # get the rowid of the inserted value (so that we can delete it if it's not good)
        rowid = int((db.execute("SELECT last_insert_rowid()")[0]["last_insert_rowid()"]))

        # get a list of dictionaries containing start and end times of ALL the slots for this event
        slots = db.execute("SELECT id, time_start, time_end FROM slots WHERE event_id = ? ORDER BY time_start ASC",
                            event['id'])

        # run verify slots
        # it returns a string, "" means we're all good
        # if we're not all good, then delete the slot we just created, then throw an error
        verify = verify_slots(slots)
        if verify != "":
            db.execute("DELETE FROM slots WHERE id = ?", rowid)
            return apology(verify)

        # if it's all good, add the slot and reload the page
        return render_template("edit.html", event=event, slots=slots)


# /slot_delete/slot_id
# deletes the slot with the specified id
@app.route("/slot_delete/<slot_id>", methods=["POST"])
@login_required
def slot_delete(slot_id):
    if request.method == "POST":
        event = db.execute("SELECT events.id, events.eventname, events.description, events.date, events.hash, events.owner_id "
                           "FROM events " +
                           "JOIN slots ON slots.event_id = events.id " +
                           "WHERE slots.id = ?",
                           slot_id)[0];

        # make sure the user owns the event
        if session.get("user_id") != event['owner_id']:
            return apology("You don't own this event :(")

        # check that the slot exists & delete it
        try:
            db.execute("DELETE FROM slots WHERE id = ?", slot_id)
        except:
            return apology(f"Can't find a slot with ID {slot_id}")

        # calculate event start and end times
        event['time_event_start'] = get_start_time(db, event['hash'])
        event['time_event_end'] = get_end_time(db, event['hash'])

        # get event slots
        slots = db.execute("SELECT * FROM slots " +
                           "WHERE slots.event_id = ? " +
                           "ORDER BY slots.time_start ASC", 
                           event['id'])

        # run verify slots
        # it returns a string, "" means we're all good
        # if we're not all good, then delete the slot we just created, then throw an error
        verify = verify_slots(slots)
        if verify != "":
            db.execute("DELETE FROM slots WHERE id = ?", rowid)
            return apology(verify)
        
        # go back to view the edit page
        return render_template("edit.html", event=event, slots=slots)


# /slot_edit/slot_id
# edits the start and/or end times of a slot
@app.route("/slot_edit/<slot_id>", methods=["POST"])
@login_required
def slot_edit(slot_id):
    if request.method == "POST":
        event = db.execute("SELECT events.id, events.eventname, events.description, events.date, events.hash, events.owner_id "
                           "FROM events " +
                           "JOIN slots ON slots.event_id = events.id " +
                           "WHERE slots.id = ?",
                           slot_id)[0];

        # make sure the user owns the event
        if session.get("user_id") != event['owner_id']:
            return apology("You don't own this event :(")

        # check that the slot exists & put it in a variable
        try:
            slot = db.execute("SELECT * FROM slots WHERE id = ?", slot_id)[0]
        except:
            return apology(f"Can't find a slot with ID {slot_id}")

        # check that the new start and end are both valid times
        new_time_start = request.form.get(f"{slot_id}.time_start")
        new_time_end = request.form.get(f"{slot_id}.time_end")

        if new_time_start >= new_time_end:
            return error("slots have to end AFTER they start!")

        # create a slot var that has start and end times for all the slots EXCEPT the one we're editing
        slots = db.execute("SELECT * FROM slots WHERE event_id = ? " +
                           "EXCEPT SELECT * FROM slots WHERE id = ? " +
                           "ORDER BY time_start ASC", event['id'], slot_id)

        # chack that the slot is ok (end is after start)
        slots.append({'time_start': new_time_start, 'time_end': new_time_end})

        # check that after editing this slots all the slots would still be without overlap
        # run verify slots
        # it returns a string, "" means we're all good
        # if we're not all good, then delete the slot we just created, then throw an error
        verify = verify_slots(slots)
        if verify != "":
            return apology(verify)
        else:
            db.execute("UPDATE slots SET time_start = ?, time_end = ? " +
                       "WHERE id = ?", new_time_start, new_time_end, slot_id)

        # get an ordered list of slots to return to the render template
        slots = db.execute("SELECT * FROM slots WHERE event_id = ? ORDER BY time_start ASC", event['id'])

        # if it's all good, edit the slot and reload the page
        return render_template("edit.html", event=event, slots=slots) # TK BE SURE TO SORT SLOTS


# /view/event_id
# Views an event with a certain ID
# Views it as a creator if user is the creator
# Views it as a participant / potential participant if the user is not the creator
@app.route("/view/<event_id>")
@login_required
def view(event_id):
    if request.method == "GET":
        event = db.execute("SELECT * FROM events WHERE hash = ?", event_id)[0]

        event['time_event_start'] = get_start_time(db, event['hash'])
        event['time_event_end'] = get_end_time(db, event['hash'])

        slots = db.execute("SELECT * FROM slots " +
                           "WHERE slots.event_id = ? " +
                           "ORDER BY slots.time_start ASC", 
                           event['id'])

        for slot in slots:
            slot['username'] = db.execute("SELECT username FROM users " +
                                         "JOIN slots ON users.id = slots.user_id " +
                                         "WHERE users.id = ?", slot['user_id'])[0]['username']

        owner = db.execute("SELECT * FROM users " +
                           "JOIN events ON events.owner_id = users.id " +
                           "WHERE events.hash = ?", 
                           event_id)[0]['username']

        user = session.get("user_id")
        return render_template("view.html", event=event, slots=slots, owner=owner, user=user)