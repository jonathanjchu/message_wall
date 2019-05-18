from flask import Flask, render_template, request, redirect, session, flash
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
import re

app = Flask(__name__)
app.secret_key = "HfSG!s$TJx8!9qdi2eZ0P4826SUKHUp!"
bcrypt = Bcrypt(app)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route("/")
def index():  
    return render_template("login.html")

@app.route("/login", methods=['POST'])
def login():
    # see if the username provided exists in the database
    mysql = connectToMySQL("wall")
    query = "SELECT user_id, email, password FROM users WHERE email = %(email)s;"
    data = { "email" : request.form["email"] }
    result = mysql.query_db(query, data)
    if len(result) > 0:
         if bcrypt.check_password_hash(result[0]['password'], request.form['password']):
            # if we get True after checking the password, we may put the user id in session
            session['user_id'] = result[0]['user_id']
            # never render on a post, always redirect!

            # update last login time
            mysql = connectToMySQL("wall")
            query = "UPDATE users SET last_login = NOW(), updated_on = NOW() WHERE user_id = %(user_id)s;"
            data = { 'user_id': result[0]['user_id'] }
            mysql.query_db(query, data)

            return redirect('/wall')
    # if we didn't find anything in the database by searching by username or if the passwords don't match,
    # flash an error message and redirect back to a safe route
    flash("Invalid email and/or password.", "login")
    return redirect("/")

@app.route("/register/process", methods=['POST'])
def create_user():
    # validate input
    is_valid = is_registration_valid(request.form)

    if is_valid:
        mysql = connectToMySQL("wall")
        query = "SELECT user_id FROM users WHERE email = %(email)s"
        data = { "email": request.form['email_reg'] }
        result = mysql.query_db(query, data)
        if len(result) > 0:
            is_valid = False
            flash("User already registered", "register_email")

    if is_valid:
        # include some logic to validate user input before adding them to the database!
        # create the hash
        pw_hash = bcrypt.generate_password_hash(request.form['password'])  
        print(pw_hash)  
        # prints something like b'$2b$12$sqjyok5RQccl9S6eFLhEPuaRaJCcH3Esl2RWLm/cimMIEnhnLb7iC'
        # be sure you set up your database so it can store password hashes this long (60 characters)
        mysql = connectToMySQL("wall")
        query = "INSERT INTO users (first_name, last_name, email, password, created_on, updated_on, last_login) VALUES (%(fname)s, %(lname)s, %(email)s, %(password_hash)s, NOW(), NOW(), NOW());"
        # put the pw_hash in our data dictionary, NOT the password the user provided
        data = {
            "fname": request.form['first_name'],
            "lname": request.form['last_name'],
            "email" : request.form['email_reg'],
            "password_hash" : pw_hash }
        user_id = mysql.query_db(query, data)

        session['user_id'] = user_id
        
        return redirect("/wall")
    else:
        return redirect("/")
    return redirect("/wall")

@app.route("/reset/password")
def password_reset():
    return render_template("password_reset.html")

@app.route("/logout")
def destroy_session():
    session.clear()
    return redirect("/")

@app.route("/wall")
def show_wall():
    if 'user_id' in session:
        user = get_user(session['user_id'])
        other_users = get_all_other_users(session['user_id'])
        msgs = get_messages(session['user_id'])
        sent_msgs_count = count_sent_messages(session['user_id'])


        return render_template("wall.html", you=user, users=other_users, msgs=msgs, send_count=sent_msgs_count)
    else:
        return redirect("/")

@app.route("/messages/send", methods=['POST'])
def send_message():
    if len(request.form['message']) < 1:
        flash("Message not sent, messge is too short", "message_error")
    else:
        # save message to db
        mysql = connectToMySQL("wall")
        query = "INSERT INTO messages (message, created_on, updated_on) " +\
            "VALUES (%(message)s, NOW(), NOW())"
        data = { 'message': request.form['message'] }
        msg_id = mysql.query_db(query, data)

        # save relation b/t both users and msg
        mysql = connectToMySQL("wall")
        query = "INSERT INTO users_messages (sender_user_id, recipient_user_id, message_id) " +\
            "VALUES(%(sender)s, %(receiver)s, %(msg_id)s)"
        data = {
            'sender': session['user_id'],
            'receiver': request.form['recipient_id'],
            'msg_id': msg_id
        }
        mysql.query_db(query, data)

        flash("Message sent", "success-send")
    
    return redirect("/wall")

@app.route("/messages/delete/<int:msg_id>")
def delete_message(msg_id):
    mysql = connectToMySQL("wall")
    query = "DELETE FROM users_messages WHERE message_id = %(message_id)s"
    data = { 'message_id': msg_id }
    mysql.query_db(query, data)

    flash("Message deleted", "success-inbox")


    return redirect("/wall")
    

def get_user(id):
    mysql = connectToMySQL("wall")
    query = "SELECT first_name, last_name, last_login FROM users WHERE user_id = %(user_id)s;"
    data = { "user_id" : id }
    result = mysql.query_db(query, data)
    return result[0]

def get_all_other_users(id):
    mysql = connectToMySQL("wall")
    query = "SELECT user_id, first_name, last_name FROM users WHERE user_id <> %(user_id)s ORDER BY first_name ASC;"
    data = { "user_id" : id }
    results = mysql.query_db(query, data)
    return results   

def get_messages(id):
    mysql = connectToMySQL("wall")
    query = "SELECT messages.message_id, message, messages.created_on, first_name, last_name FROM messages " +\
            "JOIN users_messages ON messages.message_id = users_messages.message_id " +\
            "JOIN users ON users_messages.sender_user_id = users.user_id " +\
            "WHERE users_messages.recipient_user_id = %(user_id)s " +\
            "ORDER BY messages.created_on DESC"
    data = { "user_id" : id }
    results = mysql.query_db(query, data)
    return results   

def count_sent_messages(id):
    mysql = connectToMySQL("wall")
    query = "SELECT COUNT(message_id) as m FROM users_messages " +\
        "WHERE sender_user_id = %(user_id)s"
    data = { 'user_id': id }
    results = mysql.query_db(query, data)
    return results[0]['m']

def is_registration_valid(info):
    is_valid = True

    if len(info['first_name']) < 1:
        flash("Please enter a first name", "register_fname")
        is_valid = False

    if len(info['last_name']) < 1:
        is_valid = False
        flash("Please enter a last name", "register_lname")

    if len(info['email_reg']) < 1:
        is_valid = False
        flash("Please enter an email address", "register_email")
    elif not EMAIL_REGEX.match(info['email_reg']):
        is_valid = False
        flash("Email is not valid!")
    
    if (len(info['password']) < 1):
        is_valid = False
        flash("Please enter a password", "register_password")
    elif (len(info['password']) < 8):
        is_valid = False
        flash("Password must be at least 8 characters and contain letters, numbers, punctuation, Chinese characters and Egyptian hieroglyphics")
    
    if info['password'] != info['confirm_password']:
        is_valid = False
        flash("Passwords don't match", "register_password")
    
    return is_valid

if __name__=="__main__":
    app.run(debug=True)