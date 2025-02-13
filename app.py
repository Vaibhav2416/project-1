# Authentication and Authorization

# Authentication

# Authentication is the process of verifying user identity
# This will check whether user is authenticated to visit website or not
# Inside authentication following steps are included
# 1. SignUp
# 2. Login
# 3. password hashing
# 4. Session Management

# Authorization
# Authorization is the process of granting access to user
    # for particular routes according to their role

# pip install flask Flask-SQLAlchemy flask-bcrypt

#  123 ---> $%45#)()..^& ---> bcrypt library --> werkzeug security


# Session Management

# It will allow user to visit multiple pages without login



from flask import Flask,render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash , check_password_hash
from flask_login import LoginManager,login_user,logout_user,UserMixin,login_required, current_user


app=Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"]="sqlite:///database.db"
app.config["SECRET_KEY"]="welcome" 

# We will create application where user can signup, login and can visit any page after
# login only
db=SQLAlchemy(app)

# flask-login ---> session
# Flask login library is used for better session management

login_manager=LoginManager()
login_manager.init_app(app)  #we are linking our app with flask-manager
login_manager.login_view='login'  #if user is not logged in then he will redirect to this path

@app.route("/")
def home():
    return render_template("base.html")

# UserMixin will provide you some additional methods like is_authenticated(), is_active(),get_id()

# is_authenticated() --> will return True if user is logged in 
# is_active() --> will return True when user is in session
# get_id() ---> this will return user_id

class User(db.Model,UserMixin):
    __tablename__="users"
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(100))
    email=db.Column(db.String(100))
    password_hash=db.Column(db.String(200))
    role=db.Column(db.String(100), default="user")

    # for saving hash password  # 123
    def save_hash_password(self,password):
        self.password_hash=generate_password_hash(password) 
        #we are generating encrypted password here
    
    def check_hash_password(self,password):
        return check_password_hash(self.password_hash, password)
        # this will return true or false according to user credentials


@app.route("/register",methods=["GET","POST"])
def register():
    if request.method=="POST":
        username=request.form.get("username")
        email=request.form.get("email")
        password=request.form.get("password")

        if User.query.filter_by(email=email).first():
            flash("User Already exists")
            return redirect(url_for("home"))
        
        user_data=User(username=username,email=email)
        user_data.save_hash_password(password)
        db.session.add(user_data)
        db.session.commit()
        flash("User registered successfully")
        return redirect(url_for("login"))


    return render_template("signup.html")

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        email=request.form.get("email")
        password=request.form.get("password") #123

        user_data=User.query.filter_by(email=email).first()
        # hashed password == orignal_database_hash_password

        if user_data and user_data.check_hash_password(password):
            login_user(user_data) # storing user object in the session
            flash("User Logged in Successfully")
            return redirect(url_for("dashboard"))

    return render_template("login.html")

# user loader function to fetch current user data from database

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User,int(user_id))  # this will fetch user_id from session and retrive 
                                    # current object from the database


# Authorization
# Authorization is the process of granting access to specific routes according 
# to role of user




@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")

@app.route("/logout")
def logout():
    logout_user()
    flash("User logged out successfully")
    return redirect(url_for("home"))





def role_required(role): # we are passing role here
    def decorator(func): #here I am passing admin view function
        def wrap(*args,**kwargs):  #arguments of view function
            if current_user.role!=role:  #admin
                flash("Unauthorized Access")
                return redirect(url_for("login"))
            return func(*args,**kwargs)
        return wrap
    return decorator

@app.route("/admin")
@login_required
@role_required("admin")
def admin():
    return render_template("admin.html")

with app.app_context():
    db.create_all()

    if not User.query.filter_by(role="admin").first():
        admin=User(username="admin",email="admin@gmail.com",role="admin")
        admin.save_hash_password("admin")

        db.session.add(admin)
        db.session.commit()
    


if __name__=="__main__":
    app.run(debug=True)

