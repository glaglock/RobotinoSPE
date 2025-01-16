from flask import Flask, render_template, request, url_for, flash, redirect, send_from_directory, session
from werkzeug.exceptions import abort 
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime, timezone
import time

web = Flask(__name__) 
web.config['SECRET_KEY'] = 'RobotinoSPE' 
web.permanent_session_lifetime = timedelta(minutes=30) 

correct_password_hash = generate_password_hash('RobotinoSPE')
#Maximum allowed attempts
MAX_ATTEMPTS = 3
TIME_WINDOW = timedelta(seconds=30) 


@web.route('/login', methods=['GET', 'POST'])
def login(): 
    current_time = datetime.now(timezone.utc)       #timezone.utc is neccessary if not error regarding different time zones
    
    #previously attempted logins 
    if 'login_attempts' not in session: 
        session['login_attempts'] = {'count': 0, 'last_attempt':current_time}

    attempts = session['login_attempts']

    #check if time window has passed..reset the attempts 
    if attempts['last_attempt'] == None: 
        attempts['count'] = 0
        flash(f"Error occured window passed")
    
    try:
        if current_time - attempts['last_attempt'] > TIME_WINDOW: 
                    attempts['count'] = 0
                    flash("You can try again")
    except TypeError as e: 
        flash(f"Error comparing times:{e}")

   #check if the number off attempts is within the limits
    
    if attempts['count'] >= MAX_ATTEMPTS:
        flash(f"You have exceeded the maximum number of login attempts. Please try again in {TIME_WINDOW.seconds} seconds.")
        return render_template('login.html')
    
    if request.method == 'POST': 
        password = request.form['password']

        # Assuming you store the correct password hash
        stored_password_hash = generate_password_hash("RobotinoSPE") 

        if stored_password_hash and check_password_hash(stored_password_hash, password):
            # Reset login attempts on successful login
            session['logged_in'] = True
            session.permanent = True
            session['login_attempts'] = {'count': 0, 'last_attempt': current_time}  # Reset on success
            return redirect(url_for('index'))
        else:
            # Increment the login attempt counter
            attempts['count'] += 1
            attempts['last_attempt'] = current_time
            session['login_attempts'] = attempts  # Update session

            flash("Incorrect password. Please try again.")
    
    return render_template('login.html')


@web.route('/control', methods=['GET', 'POST'])
def control(): 
    return render_template('control.html')

@web.route('/jogForward', methods=['GET', 'POST']) 
def jogForward(): 
    print("Moving Forward...") 
    time.slepp(5)

    return render_template('control.html') 


@web.route('/jogBackward', methods=['GET', 'POST'])
def jogBackward(): 
    print("Moving Backward...") 

    time.sleep(5)

    return render_template('control.html') 


@web.route('/jogLeft', methods=['GET', 'POST'])
def jogLeft(): 
    print("Moving Left...") 
    time.sleep(5)

    return render_template('control.html') 

@web.route('/jogRight', methods=['GET', 'POST'])
def jogRight(): 
    print("Moving Right...") 
    time.sleep(5)

    return render_template('control.html') 

@web.route('/batteryManagement')
def batteryManagement(): 
    return 1

@web.route('/')
def index():  

    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html')


@web.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash("You have been logged out.")
    return redirect(url_for('login'))



if __name__ == '__main__': 
    web.run(host='0.0.0.0', port=5000)