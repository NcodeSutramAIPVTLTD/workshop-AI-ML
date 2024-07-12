import bcrypt
from bson import ObjectId
from flask import Flask, jsonify, make_response, render_template, redirect, url_for, session, flash, request
from flask_wtf.csrf import CSRFProtect
from pymongo import MongoClient
from forms import  Profile, LoginForm

import razorpay
from razorpay.errors import SignatureVerificationError
from razorpay.errors import BadRequestError



razorpayClient = razorpay.Client(auth=("rzp_test_5RluvyQOjoDsIQ", "YkCJUuHYrgGR8qZqVSm4VlKL"))


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
csrf = CSRFProtect(app)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}


# MongoDB connection
client = MongoClient('mongodb+srv://root:root@cluster0.akkabue.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
db = client['Workshop']
# Mongodb connection end
# Stripe configuration
 

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))  # Redirect if user is already logged in
    return render_template('index.html')
 

@app.route('/speaker')
def speaker():
    if 'username' in session:
        return redirect(url_for('dashboard'))  # Redirect if user is already logged in
    return render_template('speaker.html')

@app.route('/commited')
def committe():
    if 'username' in session:
        return redirect(url_for('dashboard'))  # Redirect if user is already logged in
    return render_template('commited.html')


@app.route('/contact')
def contact():
    if 'username' in session:
        return redirect(url_for('dashboard'))  # Redirect if user is already logged in 
    return render_template('contact.html')

@app.route('/program1')
def program1():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('program1.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('dashboard'))  # Redirect if user is already logged in

    form = Profile()
    password = form.password.data,
    if form.validate_on_submit():
         
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        profile_data = {
            'username': form.username.data,
            'email': form.email.data,
            'number': form.number.data,
            'password':hashed_password,
            'gender': form.gender.data,
            'father': form.father.data,
            'college': form.college.data,
            'qualification': form.qualification.data,
            'dateofbirth': form.dateofbirth.data.isoformat(),
        }
        if db.registration.find_one({'email':profile_data['email']}):
           flash('Email already registered!', 'danger')
           return redirect(url_for('register'))
        else:
            db.registration.insert_one(profile_data)
            flash('Payment Form Inserted successfully!', 'success')
            return redirect(url_for('checkout', email=profile_data['email'], dateofbirth=profile_data['dateofbirth']))
              
    return render_template('register.html', form=form)

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'username' in session:
        return redirect(url_for('dashboard'))  # Redirect if user is already logged in

    form = LoginForm()
    email = request.args.get('email')
    dateofbirth = request.args.get('dateofbirth')

    if request.method == 'POST':
        email = request.form.get('email')
        dateofbirth = request.form.get('dateofbirth')
        user = db.registration.find_one({'email': email, 'dateofbirth': dateofbirth})
        
        if user:
            # If user is found, set 'username' in session and redirect to payment
            session['username'] = user['username']  # Assuming username is a field in your user document
            session['user_id']= str(user['_id'])
            print(session['user_id'])
            return redirect(url_for('payment'))
        else:
            # Handle case where user is not found or credentials are incorrect
            flash('Invalid email or date of birth. Please try again.', 'danger')  # Flash an error message
            return redirect(url_for('checkout'))  # Redirect back to login page

    # Clear cache-related headers for proper session management
    response = make_response(render_template('checkout.html', form=form, email=email, dateofbirth=dateofbirth))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response



@app.route('/payment', methods=["POST",'GET'])
def payment():
     if 'username' in session:
        username = session['username']
        user_id = session['user_id']
        print(user_id)
        user = db.registration.find_one({'_id': ObjectId(user_id)})
        register_details = db.payments.find_one({'user_email':user['email'], 'payment_type':"Registration Fee"})
        course_details = db.payments.find_one({'user_email':user['email'], 'Payment_type':"Course Fee"})
         
        print(register_details)
        print(course_details)
         
        if register_details:
                if course_details:
                    return render_template('dashboard.html', user=user)
                     
                else:
                    return render_template('full_payment.html', user=user)
        else:
                return render_template('payment.html', user=user)
        
        # if user and user['role'] == "js":
        #     return render_template('dashboard.html')
        # else:
        #     return render_template('em_dashboard.html' )
     else:
        return redirect(url_for('login'))
     
@app.route('/full_payment', methods=["POST",'GET'])
def full_payment():
     if 'username' in session:
        username = session['username']
        user_id = session['user_id']
        user = db.registration.find_one({'_id': ObjectId(user_id)})
        print(user_id)
     return render_template('full_payment.html', user=user)

# Endpoint to create a payment order
@app.route('/course_payment', methods=['POST'])
def course_payment():
    amount = request.json.get('amount')
# id 
# emaild
# datef boirth
# save in sessin obejct 
    payment_data = {
        'amount': amount,
        'currency': 'INR',
        'receipt': 'receipt_order_74394',
        'payment_capture': '1'
    }

    try:
        print('Before the formation of the payment ID', flush=True)
        order = razorpayClient.order.create(data=payment_data)
        print('After the formation of the payment ID', order['id'], flush=True)
        return jsonify({'order_id': order['id']})
    except Exception as e:
        print('Error creating Razorpay order:', e, flush=True)
        return jsonify({'error': 'Failed to create payment order'}), 500



@app.route('/success_payment_course', methods=['POST', 'GET'])
@csrf.exempt
def success_payment_course():
    if 'username' in session:
        username = session['username']
        user_id = session['user_id']
        print(user_id)
        user = db.registration.find_one({'_id': ObjectId(user_id)})
    else:
        return redirect(url_for('login'))

    pid = request.form.get("razorpay_payment_id")
    ordid = request.form.get("razorpay_order_id")
    sign = request.form.get("razorpay_signature")

    try:
        payment_fetch_details = razorpayClient.payment.fetch(pid)
        payment_fetch_details['user_id'] = user['_id']
        payment_fetch_details['user_email'] = user['email']
        payment_fetch_details['Payment_type'] = 'Course Fee'
        params = {
            'razorpay_order_id': ordid,
            'razorpay_payment_id': pid,
            'razorpay_signature': sign
        }

        final = razorpayClient.utility.verify_payment_signature(params)

        if final:
            try:
                result = db.payments.insert_one(payment_fetch_details)
                if result.inserted_id:
                    return redirect(url_for('payment'))
            except Exception as e:
                return jsonify({'message': "Payment Successful. Database could not be updated. ordid: " + ordid, 'status': 'Failed'})
    except SignatureVerificationError:
        return jsonify({'message': "Signature Verification Failed", 'status': 'Failed'})
    except BadRequestError as e:
        return jsonify({'message': 'Bad request', 'status': 'Failed'})
    except Exception as e:
        return jsonify({'message': str(e), 'status': 'Failed'})

@app.route('/experiment', methods=["POST",'GET'])
def payment_exp():
    return render_template('experiment.html')




# @app.route('/make_payment', methods=["POST",'GET'])
# def make_payment():
#     # Get the payment data from the request
#     print('inside the make payment section')
#     payment_data = request.json
#     amount = payment_data.get("amount")
#     print("amount recieved: ", amount)
#     payment_dict = { "amount": amount , "currency": "INR", "receipt": "order_rcptid_11" }


#     # Assuming you have the client object ready for Razorpay
#     payment = razorpayClient.order.create(data=payment_dict)

#     session['payment_orderID'] = payment["id"]
#     # Assuming you want to return the payment ID to the client
#     return jsonify({"order_id": payment["id"]})



# ========================================

# Endpoint to create a payment order
@app.route('/make_payment', methods=['POST'])
def make_payment():
    amount = request.json.get('amount')
# id 
# emaild
# datef boirth
# save in sessin obejct 
    payment_data = {
        'amount': amount,
        'currency': 'INR',
        'receipt': 'receipt_order_74394',
        'payment_capture': '1'
    }

    try:
        print('Before the formation of the payment ID', flush=True)
        order = razorpayClient.order.create(data=payment_data)
        print('After the formation of the payment ID', order['id'], flush=True)
        return jsonify({'order_id': order['id']})
    except Exception as e:
        print('Error creating Razorpay order:', e, flush=True)
        return jsonify({'error': 'Failed to create payment order'}), 500



@app.route('/success_payment', methods=['POST', 'GET'])
@csrf.exempt
def success_payment():
    if 'username' in session:
        username = session['username']
        user_id = session['user_id']
        print(user_id)
        user = db.registration.find_one({'_id': ObjectId(user_id)})
         
    else:
        return redirect(url_for('login'))

    pid = request.form.get("razorpay_payment_id")
    ordid = request.form.get("razorpay_order_id")
    sign = request.form.get("razorpay_signature")

    try:
        payment_fetch_details = razorpayClient.payment.fetch(pid)
        payment_fetch_details['user_id'] = user['_id']
        payment_fetch_details['user_email'] = user['email']
        payment_fetch_details['payment_type'] = 'Registration Fee'
        params = {
            'razorpay_order_id': ordid,
            'razorpay_payment_id': pid,
            'razorpay_signature': sign
        }

        final = razorpayClient.utility.verify_payment_signature(params)

        if final:
            try:
                result = db.payments.insert_one(payment_fetch_details)
                if result.inserted_id:
                    flash('You are login and again come Your email and Your password and login then you come in this dashboard and you are change password', 'danger')
                    return  redirect(url_for('payment'))
                     
            except Exception as e:
                return jsonify({'message': "Payment Successful. Database could not be updated. ordid: " + ordid, 'status': 'Failed'})
    except SignatureVerificationError:
        return jsonify({'message': "Signature Verification Failed", 'status': 'Failed'})
    except BadRequestError as e:
        return jsonify({'message': 'Bad request', 'status': 'Failed'})
    except Exception as e:
        return jsonify({'message': str(e), 'status': 'Failed'})





@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = db.registration.find_one({'email': email})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['username'] = user['username']
            session['user_id'] = str(user['_id'])  # Store user ID in session
            return redirect(url_for('dashboard'))
        else: 
            flash('Invalid email or password!', 'error')
    response = make_response(render_template('login.html', form=form))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response
# dashboard


@app.route('/dashboard')
def dashboard():
     if 'username' in session:
        username = session['username']
        user_id = session['user_id']
        print(user_id)
        user = db.registration.find_one({'_id': ObjectId(user_id)})
        register_details = db.payments.find_one({'user_id':user['_id'], 'payment_type':"Registration Fee"})
        course_details = db.payments.find_one({'user_id':user['_id'], 'Payment_type':"Course Fee"})
         
        print(register_details)
        print(course_details)
         
        if register_details:
                if course_details:
                    return render_template('dashboard.html', user=user)
                     
                else:
                    return render_template('full_payment.html', user=user)
        else:
                return render_template('payment.html', user=user)
        
        # if user and user['role'] == "js":
        #     return render_template('dashboard.html')
        # else:
        #     return render_template('em_dashboard.html' )
     else:
        return redirect(url_for('login'))

#logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    response = redirect(url_for('index'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/program')
def program():
    return render_template('program.html')
 
@app.route('/change_password', methods=['GET', 'POST'])

def change_password():
    
    if 'username' not in session:
        return redirect(url_for('login'))
    
    form = LoginForm()
    user_id = session['user_id']
    user_data = db.registration.find_one({'_id': ObjectId(user_id)})
    
    if request.method == 'POST':
        change_password = request.form.get('change_password')
        Confirm_password = request.form.get('Confirm_password')
         
        if change_password == Confirm_password:
            hashed_password = bcrypt.hashpw(change_password.encode('utf-8'), bcrypt.gensalt())
            
            db.registration.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {
                    'password': hashed_password,
                }}
            )
            flash('Password changed successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Passwords do not match!', 'danger')

    return render_template('change_password.html', form=form,   user=user_data)
@app.route('/schedule')
def schedule():
      
    
    return render_template('schedule.html')     

@app.route('/change_pas_das', methods=['GET', 'POST'])

def change_pas_das():
    
    if 'username' not in session:
        return redirect(url_for('login'))
    
    form = LoginForm()
    user_id = session['user_id']
    user_data = db.registration.find_one({'_id': ObjectId(user_id)})
    
    if request.method == 'POST':
        change_password = request.form.get('change_password')
        Confirm_password = request.form.get('Confirm_password')
        print(change_password)
        print(Confirm_password)
        if change_password == Confirm_password:
            hashed_password = bcrypt.hashpw(change_password.encode('utf-8'), bcrypt.gensalt())
            
            db.registration.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {
                    'password': hashed_password,
                }}
            )
            flash('Password changed successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Passwords do not match!', 'danger')

    return render_template('change_pas_das.html', form=form,   user=user_data)
if __name__ == '__main__':
    app.run(debug=True)