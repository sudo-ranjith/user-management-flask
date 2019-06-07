from flask import Flask , jsonify , request  
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_simple import JWTManager, jwt_required, create_jwt, get_jwt_identity
import datetime 

app = Flask(__name__)
app.config['MONGO_DBNAME'] = 'putracare'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/putracare'
app.config['SECRET_KEY'] = 'a5ea0c77491f965420dfa379ddb6105adb0e3e88'
app.config['JWT_SECRET_KEY'] = 'super-secret' 
mongo = PyMongo(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)


#this is registration api
@app.route('/register', methods=['POST'])
def register():
    try:
        username = request.json.get('username')
        password = request.json.get('password')  
        email = request.json.get('email')
        nric = request.json.get('nric')
        passport_no = request.json.get('passport_no')
        gender = request.json.get('gender')
        kswp_epf_id = request.json.get('kswp_epf_id')
        staff_id = request.json.get('staff_id')
        date_of_birth = request.json.get('dob') 
        prefered_login_id = request.json.get('prefered_login_id')
        current_age = request.json.get('current_age')
        address = request.json.get('address')
        city = request.json.get('city')
        post_code = request.json.get('post_code')
        state = request.json.get('state')
        mobile_number = request.json.get('mobile')

        register_db = mongo.db.clinical_users
        registered_username = register_db.find_one({'username': username})
        print(registered_username)      
        if registered_username == None:
            pw_hash = bcrypt.generate_password_hash(password)
            #pw_hash=str(pw_hash)
            user_data = {'username': username ,
                         'password': pw_hash ,
                         'email': email,
                         'nric': nric,
                         'passport_no': passport_no,
                         'gender': gender,
                         'kswp_epf_id': kswp_epf_id,
                         'staff_id': staff_id,
                         'date_of_birth': date_of_birth,
                         'prefered_login_id': prefered_login_id,
                         'current_age': current_age,
                         'address' : address,
                         'city': city,
                         'post_code': post_code,
                         'state': state,
                         'mobile_no': mobile_number,
                         'date': datetime.datetime.utcnow()
                         }
            register_db.insert_one(user_data)
            result_msg = {'msg': 'registered succesfully','flag':1}
            return jsonify(result_msg)             
        else:
            result_msg = {'msg': 'already exists','flag':0}
            return jsonify(result_msg)
    except Exception as e:
        print(e)
        return jsonify({'message':'something went wrong'})

        

@app.route('/login',methods=['POST'])
def login():
    try:
        # login_credentials = request.json()
        # username = login_credentials['username']
        # password = login_credentials['password']
        # prefered_login_id = login_credentials['prefered_login_id']
        username = request.json.get('username')
        password = request.json.get('password')
        prefered_login_id = request.json.get('prefered_login_id')

        db_link = mongo.db.clinical_users
        query = {'username': username}
        check_user = db_link.find_one(query)
        print('check user: ', check_user)
        #getting encrypted password
        
        # print('encrypted password',enc_psw)
        # print('check user',check_user)
        if (check_user is None):
            return jsonify({'message': 'please enter valid user name'})
        else:
            valid_username = check_user['username']
            #valid_password = check_user['password']
            enc_psw = check_user['password']
            #decrypting the encrypted password -can see only boolean
            dec_psw = bcrypt.check_password_hash(enc_psw,password)
            valid_prefered_login_id = check_user['prefered_login_id']
            if (username==valid_username and dec_psw==True and prefered_login_id==valid_prefered_login_id):
                message = {'access token': create_jwt(username)}
                return jsonify(message)
            elif(dec_psw!=True):
                return jsonify({'message':'enter valid password'})
            elif(prefered_login_id!=valid_prefered_login_id):
                return jsonify({'message':'enter valid prefered login id'})
            return jsonify({'msg':'this is else part'})
            
    except Exception as e:
        print(e)
        return jsonify({'message':'something went wrong','flag': 0})

@app.route('/user_list',methods=['GET'])
@jwt_required
def user_list():
    try:
        db_link = mongo.db.clinical_users
        all_users = db_link.find({},{'username':1,"_id":0})
        user_data = []
        for user in all_users:
            user_data.append(user)
            print(user)
        return jsonify(user_data)
        
    except Exception as e:
        print(e)
        return jsonify({'message':'something went wrong','section':'in exception'})

@app.route('/roles_list',methods=['GET'])
@jwt_required
def get_roles():
    try:
        db_link = mongo.db.clinical_users
        roles_list = db_link.find({},{'prefered_login_id':1,"_id":0})
        role_collection=[]
        for role in roles_list:
            role_collection.append(role)
        return jsonify(role_collection)

    except Exception as e:
        print(e)
        return jsonify({'message':'something went wrong'})

@app.route('/doctor_list',methods=['GET'])
@jwt_required
def doctor_list():
    try:
        db_link = mongo.db.clinical_users
        query = {'prefered_login_id': 'doctor'}
        doctors_list =db_link.find(query,{'username':1,'prefered_login_id':1,"_id":0})
        doctors = []
        for doctor in doctors_list:
            doctors.append(doctor)
        return jsonify(doctors)
    except Exception as e:
        print(e)
        return jsonify({'message': 'something went wrong'})

@app.route('/delete_user',methods=['DELETE'])
@jwt_required
def remove_user():
    try:
        username = request.json.get('username')
        db_link = mongo.db.clinical_users
        check_user = db_link.find_one({'username': username})
        if check_user is None:
            return jsonify({'message': 'user is not in our database'})
        else:
            del_user = check_user['username']
            db_link.delete_one({'username': del_user})
            return jsonify({'message':'user deleted succesfully'})

    except Exception as e:
        print(e)
        return jsonify({'message':'something went wrong'})

if __name__ == '__main__':
    app.run(debug=True, port=8080)
