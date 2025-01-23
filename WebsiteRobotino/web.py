from flask import Flask, render_template, request, url_for, flash, redirect, send_from_directory, session
from werkzeug.exceptions import abort 
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime, timezone
import time
import RPi.GPIO as GPIO

#BCM numbering 
GPIO.setmode(GPIO.BCM) 

#Define GPIO Pins

#Pins Motor A
IN1_A_A = 2 # Motor A direction 1 ( Physical Pin  13) 
IN2_A_A = 3 # Motor A direction 2 ( Physical Pin  15) 
ENABLE_A_A = 12 # PWM Signal Motor A ( Physical Pin 19) 

#Pins Motor B 
IN3_B_B = 4 # Motor A direction 1 ( Physical Pin  16) 
IN4_B_B = 5 # Motor A direction 2 ( Physical Pin  18) 
ENABLE_B_B = 13 # PWM Signal Motor B ( Physical Pin 21) 

#Pins Motor C
IN1_A_C = 27 # Motor A direction 1 ( Physical Pin  36) 
IN2_A_C = 22 # Motor A direction 2 ( Physical Pin  31) 
ENABLE_A_C = 18 # PWM Signal Motor C ( Physical Pin 12)

#Pins Motor D
IN3_B_D = 10 # Motor A direction 1 ( Physical Pin  24) 
IN4_B_D = 9  # Motor A direction 2 ( Physical Pin  5) 
ENABLE_B_D = 19 # PWM Signal Motor A ( Physical Pin 35)
  


#Set up GPIO pins as outputs 

#Motor A
GPIO.setup(IN1_A_A, GPIO.OUT) 
GPIO.setup(IN2_A_A, GPIO.OUT) 
GPIO.setup(ENABLE_A_A, GPIO.OUT) 

#Motor B
GPIO.setup(IN3_B_B, GPIO.OUT) 
GPIO.setup(IN4_B_B, GPIO.OUT) 
GPIO.setup(ENABLE_B_B, GPIO.OUT) 

#Motor C
GPIO.setup(IN1_A_C, GPIO.OUT) 
GPIO.setup(IN2_A_C, GPIO.OUT) 
GPIO.setup(ENABLE_A_C, GPIO.OUT) 

#Motor D
GPIO.setup(IN3_B_D, GPIO.OUT) 
GPIO.setup(IN4_B_D, GPIO.OUT) 
GPIO.setup(ENABLE_B_D, GPIO.OUT) 


# Website Code 

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
    
    GPIO.output(IN1_A_A, GPIO.HIGH)
    GPIO.output(IN2_A_A, GPIO.LOW)
    
    GPIO.output(IN3_B_B, GPIO.HIGH)
    GPIO.output(IN4_B_B, GPIO.LOW)
    
    GPIO.output(IN1_A_C, GPIO.HIGH)
    GPIO.output(IN2_A_C, GPIO.LOW)
    
    GPIO.output(IN3_B_D, GPIO.HIGH)
    GPIO.output(IN4_B_D, GPIO.LOW)
    
    
    time.slepp(5)

    return render_template('control.html') 


@web.route('/jogBackward', methods=['GET', 'POST'])
def jogBackward(): 
    print("Moving Backward...") 
    
    GPIO.output(IN1_A_A, GPIO.LOW)
    GPIO.output(IN2_A_A, GPIO.HIGH)
    
    GPIO.output(IN3_B_B, GPIO.LOW)
    GPIO.output(IN4_B_B, GPIO.HIGH)
    
    GPIO.output(IN1_A_C, GPIO.LOW)
    GPIO.output(IN2_A_C, GPIO.HIGH)
    
    GPIO.output(IN3_B_D, GPIO.LOW)
    GPIO.output(IN4_B_D, GPIO.HIGH)
    
    time.sleep(5)
    return render_template('control.html') 


@web.route('/jogLeft', methods=['GET', 'POST'])
def jogLeft(): 
    print("Moving Left...") 
    
    GPIO.output(IN1_A_A, GPIO.HIGH)
    GPIO.output(IN2_A_A, GPIO.LOW)
    
    GPIO.output(IN3_B_B, GPIO.LOW)
    GPIO.output(IN4_B_B, GPIO.HIGH)
    
    GPIO.output(IN1_A_C, GPIO.HIGH)
    GPIO.output(IN2_A_C, GPIO.LOW)
    
    GPIO.output(IN3_B_D, GPIO.LOW)
    GPIO.output(IN4_B_D, GPIO.HIGH)
    
   
    
    time.sleep(5)

    return render_template('control.html') 

@web.route('/jogRight', methods=['GET', 'POST'])
def jogRight(): 
    print("Moving Right...") 
    
    GPIO.output(IN1_A_A, GPIO.LOW)
    GPIO.output(IN2_A_A, GPIO.HIGH)
    
    GPIO.output(IN3_B_B, GPIO.HIGH)
    GPIO.output(IN4_B_B, GPIO.LOW)
    
    GPIO.output(IN1_A_C, GPIO.LOW)
    GPIO.output(IN2_A_C, GPIO.HIGH)
    
    GPIO.output(IN3_B_D, GPIO.HIGH)
    GPIO.output(IN4_B_D, GPIO.LOW)
    
    
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
