from flask import Flask , request , jsonify 
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_simple import JWTManager , jwt_required , get_jwt_identity , create_jwt , jwt_optional
#assigning variable(app) for the flask application
app = Flask(__name__)
#this is configuration part
app.config['MONGO_DBNAME'] = 'user_management_db'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/user_management_db'
app.config['SECRET_KEY'] = 'this is secret key it should be strong '
app.config['JWT_SECRET_KEY'] = 'this is jwt secret key'

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
#setting up for getuser api route with GET methodb this api has required json web token 
#through this api we can get the user details using access token
@app.route('/getuser', methods=['GET'])
@jwt_required
def getuser():
    print('this is get users api')
    #connection database using cursor
    db_link = mongo.db.user_collection
    #getting json web token's value and assing value in the current_user variable
    current_user = get_jwt_identity()
    #reading the json web token's detail using cursor then _id and password will not appear
    user_details = db_link.find_one({'username': current_user}, {'_id':0 , 'password':0})
    #it will return the user details 
    return jsonify(user_details)
#this api is used to register the user in our system
@app.route('/postuser', methods=['POST'])
def postuser():
    try:
        reg_user_name = request.json.get('username')
        reg_user_pass = request.json.get('password')
        reg_user_type = request.json.get('type')
        reg_user_email = request.json.get('email')
        #we are getting user credentials using request.get
        #in db_con variable we are assigning our mongodb along with collection
        db_con = mongo.db.user_collection       
        query = {'username': reg_user_name}
        #finding username as reg_user_name in our mongodb
        find_db_user = db_con.find_one(query)   
        print('find db user')
        print(find_db_user)
         #checking wheather the username has value like already exists in our database
        if find_db_user == None:       
            #here password will be encrpt using bcrypt library
            pw_hass = bcrypt.generate_password_hash(reg_user_pass)      
            add_user_query = {'username': reg_user_name , 'password': pw_hass , 'type': reg_user_type , 'email': reg_user_email}           
            adding_user = db_con.insert_one(add_user_query)
            """
             we have inserted the user entered username , password(encrypted) , type , email in our database (user_management_db) 
            """
            print(adding_user)
            #we are returning msg using jsonify
            return jsonify({'msg': 'user registered succesfully'})  
         #incase if condition didn't satisfy it will come to else condition which means username has some value like already exists in our database
        else:      
            un_reg_msg = {'msg': 'user already exists'}
            return jsonify(un_reg_msg)
            #if is there any exceptions occured this will be excecute
    except Exception as e:      
        print(e)
        err_msg = {'msg': 'exception occured'}
        return jsonify(err_msg)

 
#setting up route for fetchallusers with GET method
@app.route('/fetchallusers', methods=['GET'])
@jwt_required
def fetchallusers():
    try:
        #linking database and assigning to db_link variable
        db_link = mongo.db.user_collection
        #read all detail in the database except password and _id
        fetch_user_details = db_link.find({},{'password':0 , '_id':0})
        #creating an empty list(but for loop fillup this list as per database data)
        user_list = []
        #using for loop for filling what are all the data inside the fetch_user_details to user_list
        for x in fetch_user_details:
            #variable x will be insert data into the list using append
            user_list.append(x)
            print(user_list)
        return jsonify(user_list)
    except Exception as e:
        print(e)
        return jsonify({'msg':'there is some exception occers'})
#to getting only corporate users we are developing this api with GET method
@app.route('/corpusers' , methods=['GET'])
@jwt_required
def corpusers():
    try:
        db_link = mongo.db.user_collection
        #query for getting all users with type corporate from the configured database
        find_corp_users = db_link.find({'type': 'corporate'}, {'_id':0 , 'password':0})
        #first we set empty list but the for loop will fill this list
        list_corp_users = []
        # find_corp_users will bring all the users those who has type corporate  
        for y in find_corp_users:
            #it will append the corp user details in the list_corp_users
            list_corp_users.append(y)
        return jsonify(list_corp_users)
    except Exception as e:
        return jsonify({'msg': 'some exception occered' , 'exception': e})
#we are using this api for getting only individualuser details 
@app.route('/individualusers' , methods=['GET'])
@jwt_required
def individualusers():
    try:
        #database connection 
        db_link = mongo.db.user_collection
        #query for finding all the users has type individual 
        find_individual_users = db_link.find({'type': 'individual'}, {'_id':0 , 'password':0})
        #setting empty list for loop will fillup this one
        list_individual_user = []
        for z in find_individual_users:
            #it will be append in the list 
            list_individual_user.append(z)
        return jsonify(list_individual_user)
    except Exception:
        return jsonify({'msg': 'some exception occered'})
# in this api we will be login and get the access token and we are using POSt method here 
@app.route('/login' , methods=['POST'])
def login():
    try:
        #getting data from user request
        to_check_username = request.json.get('username')
        to_check_password = request.json.get('password')
        db_link = mongo.db.user_collection
        query = {'username': to_check_username}
        #query for checking user is already exist 
        check_user = db_link.find_one(query)
        print( 'this is check user value : ' ,check_user)
        #fetching only username and assigning check_username variable
        
        #check_password = check_user["password"]
        #existing_encrypted_password = db_link.find_one({'username': to_check_username}, {'password':1 , "_id":0})
        #existing_encrypted_password = existing_encrypted_password["password"]
        #print('this is decrypted password: ', decrypted_password)
        #print('this is existing encrypted password: ', existing_encrypted_password)

        #if the user is not exist in database this condition will be excecute 
        if check_user == None:            
            un_reg_msg = {'msg': 'it seems this user did not registered '}
            return jsonify(un_reg_msg)
            #if the user entered data is available in this database it will work
        else:
            #getting the  username and password
            check_username = check_user["username"]
            check_password = check_user["password"]
            #the encrypted password will be decrypting here 
            #checkpassword will be used for know whether decrypted password is true or not
            decrypted_password = bcrypt.check_password_hash(check_password, to_check_password)
            if to_check_username == check_username and decrypted_password == True:
                #token will generate if the username and password is same
                access_token ={'access token': create_jwt(to_check_username)}
                return jsonify(access_token),200
                #it will excecute if the user entered password is not correct 
            elif to_check_username == check_username and decrypted_password == False:
                print('this is elif statement')
                return jsonify({'msg': 'you have entered wrong password'})
            #if is there any type error it will be excecute
    except TypeError:
        return jsonify({'msg': 'this is type error'})
        #if is there any exception it will be excecute
    except Exception as d:
        print(d)
        excep_msg = {'exception message': 'there is some exception occers'}
        return jsonify(excep_msg)
#to delete user document we are using this api.
@app.route('/delete', methods=['DELETE'])
@jwt_required
def delete():
    try:
        #getting data from user request
        to_remove_email = request.json.get('email')
        db_link = mongo.db.user_collection
        #query for finding the user already exist or not in the database and it wont return id and password
        existing_email = db_link.find_one({'email': to_remove_email}, {'_id':0 ,'password':0})
        #if user sending data is none(not available in database) below if will send response user not found
        if existing_email==None:
            return jsonify({'msg':'User is not found in the database'})
        else:
            #will segregate the email type (we have two types like corporate and individual)
            existing_email_type = existing_email['type']
            #if existing mail is equal to corporate will be work
            if existing_email_type=='corporate':
                return jsonify({'msg': 'we cannot remove corporate users'})
                #will work if existing mail equals to individual 
            elif existing_email_type=='individual':
                #query for removing data in mongodb
                db_link.remove({'email': to_remove_email})
                return jsonify({'msg': 'user removed succesfully'})
    #if try fails except will be work
    except Exception:
        return jsonify({'msg': 'there are some error occured'})
# if our flask application name called only it will be   __main__ which means when we import this it wont work
if __name__ == "__main__":
    #for debugging enabling we are using debug = true
    app.run(debug=True)