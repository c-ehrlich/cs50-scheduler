import os
import requests
import urllib.parse
import calendar

from flask import redirect, render_template, request, session
from functools import wraps
from datetime import date, datetime

from cs50 import SQL


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


def delete_event(db, event_id, user_id):
    """
    Deletes a event and all slots associated with it
    (!) This uses event_id instead of event_hash, because id is not user-facing
    Works only if the user is the owner of the event
    """

    # Make sure the user trying to delete the event actually owns it
    if user_id != db.execute("SELECT owner_id FROM events WHERE id = ?", event_id)[0]['owner_id']:
        return apology("Sorry, you don't own this event!")
    
    # Make sure the event exists
    if (db.execute("SELECT COUNT(*) FROM events WHERE id = ?", event_id)[0]['COUNT(*)']) != 1:
        return apology(f"Could not find an event with hash {event_id}")

    # Delete all slots associated with this event
    db.execute("DELETE FROM slots WHERE event_id = ?", event_id)

    # Delete the event itself
    db.execute("DELETE FROM events WHERE id = ?", event_id)
    

def join_event(db, event_hash, slot_id, user_id):
    """
    Makes a user join a event.
    Will remove them from any other slots they are occupying in the current event
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

    # Make sure the user doesn't own this event
    # This should also be implemented in the HTML of any event view etc, but doing it here to be sure ^_^
    if user_id == db.execute("SELECT owner_id FROM events WHERE hash = ?", event_hash)[0]['owner_id']:
        return apology("You can't join your own event!")

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


def leave_event(db, event_hash, user_id):
    """
    Makes a user leave the event
    Will remove them from any slots they are occupying in the event
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
                

def get_end_time(db, event_hash):
    """
    Returns the end time of a event
    """
    event_id = db.execute("SELECT id FROM events WHERE hash = ?", event_hash)[0]['id']
    try:
        value = db.execute("SELECT time_end FROM slots WHERE event_id = ? ORDER BY time_start DESC LIMIT 1", event_id)[0]['time_end']
        return value
    except:
        return None


def get_start_time(db, event_hash):
    """
    Returns the start time of a event
    """
    event_id = db.execute("SELECT id FROM events WHERE hash = ?", event_hash)[0]['id']
    try:
        value = db.execute("SELECT time_start FROM slots WHERE event_id = ? ORDER BY time_start ASC LIMIT 1", event_id)[0]['time_start']
        return value
    except:
        return None


def verify_slots(slots):
    """
    (!) INPUT: takes a list of dictionaries in the exact format
    [{'time_start': '10:00', 'time_end': '10:25'},...]
    if the key names are wrong or the values are not times in this format, 
        the function will break. Sorry!!!
    GOOD NEWS: the list does not need to be in order. We do that in here
    
    OUTPUT: none
    But it throws an error if any slots have end times that are equal to or earlier than their start times
    Or if there is any overlap in time between any of the slots
    """

    # Sort slots by start time
    slots = sorted(slots, key = lambda i: i['time_start'])

    # Make sure none of the slots end before they start or at the same time
    for slot in slots:
        if slot['time_start'] >= slot['time_end']:
            return "Slots can't end before they start!"

    # Make sure none of the slots overlap
    for i in range(1, len(slots)):
        if slots[i]['time_start'] < slots[i-1]['time_end']:
            return "Slot times can't overlap!"

    return ""


def week_day(date_in):
    # Create weekDays tuple for adding weekday to event information
    weekDays = ("Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday")
    try:
        return weekDays[datetime.strptime(date_in, '%Y-%m-%d').weekday()]
    except:
        return "ERROR GETTING DATE"






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
