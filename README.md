# cs50-scheduler
Final project for Harvard University CS50. Web app that lets users create events and register for time slots.

## Requirements
* cs50
* Flask
* Flask-Session
* requests

## Instructions
1. Duplicate scheduler.bak and rename the copy to scheduler.db
2. In the root directory of the project, `flask run`
3. The default admin account is admin/hunter2, changing the password is recommended

## Learning Outcomes
* Strengthened my understanding of building web apps using Python and Flask
* MVC
* Normal Forms in relational databases (up to 4NF)

## Todo (Functionality)
* Implement delete event and link it on the relevant pages (created meetings and view when owned)
    * Use bootstrap modal element for this?
* Implement edit functionality for events
    * Only linked from view?
    * Go to a new page where all the upper slots can be edited (Title, description, Date)
* Add cancel button / functionality to 'create'
* Add cancel button / functionality to 'create_slots' (this probably involves deleting the half finished event!)
* Prevent user from joining their own meetings
* Add better error checking to create page (currently can crash the website by leaving everything blank)
* Add error checking to slot creation
    * No slot should have non-values
    * slots should not overlap (order them, then check if end time of one is later than start time of the next)
* Add button to "my joined meetings" to get to the edit page of a meeting

* figure out how flashed messages work (CS50 Finance had them)

## Todo (Design) 