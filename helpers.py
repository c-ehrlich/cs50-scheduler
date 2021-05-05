import os
import requests
import urllib.parse

from flask import redirect, render_template, request, session
from functools import wraps

from cs50 import SQL


def delete_meeting(db, event_id, user_id):
    """
    Deletes a meeting and all slots associated with it
    (!) This uses event_id instead of event_hash, because id is not user-facing
    Works only if the user is the owner of the meeting
    """

    # Make sure the user trying to delete the event actually owns it
    if user_id != db.execute("SELECT owner_id FROM events WHERE id = ?", event_id)[0]['owner_id']:
        return apology("Sorry, you don't own this event!")
    
    # Make sure the event exists
    if (db.execute("SELECT COUNT(*) FROM events WHERE hash = ?", event_hash)[0]['COUNT(*)']) != 1:
        return apology(f"Could not find an event with hash {event_hash}")

    # Delete all slots associated with this event
    db.execute("DELETE FROM slots WHERE event_id = ?", event_id)

    # Delete the event itself
    db.execute("DELETE FROM events WHERE id = ?", event_id)
    

def join_meeting(db, event_hash, slot_id, user_id):
    """
    Makes a user join a meeting.
    Will remove them from any other slots they are occupying in the current meeting
    Will apologize on bad input
    """

    # Make sure the event exists
    if (db.execute("SELECT COUNT(*) FROM events WHERE hash = ?", event_hash)[0]['COUNT(*)']) != 1:
        return apology(f"Could not find an event with hash {event_hash}")
    
    # Make sure the slot exists
    if (db.execute("SELECT COUNT(*) FROM slots WHERE id = ?", slot_id)[0]['COUNT(*)']) != 1:
        return apology(f"Could not find a slot with ID {slot_id}")

    # Make sure the slot exists in the event
    if (db.execute("SELECT COUNT(*) FROM slots JOIN events ON slots.event_id = events.id WHERE slots.id = ? AND events.hash = ?", slot_id, event_hash)[0]['COUNT(*)']) != 1:
        return apology(f"Slot {slot_id} not found in event {event_hash}")

    # Make sure the slot is vacant (slot.user_id = 0)
    if (db.execute("SELECT COUNT(*) FROM slots WHERE slots.id = ? AND slots.user_id = 0", slot_id)[0]['COUNT(*)']) != 1:
        return apology(f"Slot {slot_id} is not empty!")

    # Remove user from any slots in this event they may already be occupying
    db.execute("UPDATE slots      "
               "SET user_id = 0   "
               "WHERE user_id = ? "
               "AND event_id =    "
               "   (SELECT id     "
               "   FROM events    "
               "   WHERE hash = ?)",
               user_id, event_hash)
    
    # Add the user to the slot they chose
    db.execute("UPDATE slots SET user_id = ? WHERE id = ?", user_id, slot_id)


def leave_meeting(db, event_hash, user_id):
    """
    Makes a user leave the meeting
    Will remove them from any slots they are occupying in the meeting
    Will apologize on bad input
    """
    # Make sure the event exists
    if (db.execute("SELECT COUNT(*) FROM events WHERE hash = ?", event_hash)[0]['COUNT(*)']) != 1:
        return apology(f"Could not find an event with hash {event_hash}")

    # Remove user from any slots in this event they may already be occupying
    db.execute("UPDATE slots      "
               "SET user_id = 0   "
               "WHERE user_id = ? "
               "AND event_id =    "
               "   (SELECT id     "
               "   FROM events    "
               "   WHERE hash = ?)",
               user_id, event_hash)





"""
OLD CS50 HELPER FUNCTIONS BELOW HERE
IF SOMETHING IS WRONG WITH EITHER NEW CODE OR ONE OF THESE FUNCTIONS,
IT'S PROBABLY THE NEW CODE
(BECAUSE I DIDN'T WRITE THESE)
"""


def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function
