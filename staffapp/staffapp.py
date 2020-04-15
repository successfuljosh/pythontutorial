from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


class StaticAttr:
	LoggedUser=[]
	message = ''

class Admin(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	firstName = db.Column(db.String(120), nullable=False)
	lastName = db.Column(db.String(120), nullable = False)	
	email = db.Column(db.String(120), unique=True, nullable=False)
	password = db.Column(db.String(120), nullable = False)
	staffs = db.relationship('Staff', backref = 'author', lazy = True)

	def __repr__(self):
		return f"Admin ('{self.firstName}', '{self.lastName}', '{self.email}')"


class Staff(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	firstName = db.Column(db.String(120), nullable=False)
	lastName = db.Column(db.String(120), nullable = False)
	email = db.Column(db.String(120), unique=True, nullable=False)
	password = db.Column(db.String(20), nullable = False)
	function = db.Column(db.Text, nullable = False)
	admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
	
	def __repr__(self):
		return f"Student ('{self.firstName}', '{self.lastName}', '{self.email}')"	



@app.route('/register', methods=['GET','POST'])
def register():
	try:
		if request.method == 'POST':
			first = request.form['first_name']
			last = request.form['last_name']
			email = request.form['email']
			password = request.form['password']
			hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
			if email_exist(email) == False:
				admin = Admin(firstName = first, lastName = last, email= email, password = hashed_password)
				db.session.add(admin)
				db.session.commit()
				StaticAttr.message = 'Your account has been created!, Login to continue'
				return redirect(url_for('login'))
			StaticAttr.message = 'Email already exists'
	except:
		db.session.remove()
		StaticAttr.message = 'An error occured'
	return render_template('register.html', title = 'Registration', message = StaticAttr.message)



@app.route('/')
@app.route('/login', methods=['GET','POST'])
def login():
	try:
		if request.method == 'POST':
			email = request.form['email']
			password = request.form['password']
			admin = Admin.query.filter_by(email = email).first()
			if admin:
				if bcrypt.check_password_hash(admin.password,password):
					# staffs = admin.staffs
					StaticAttr.LoggedUser = admin
					print('login level: ', StaticAttr.LoggedUser)
					return redirect(url_for('home'))
				else:
					StaticAttr.message = 'Invalid password'
			else:
				StaticAttr.message = 'Invalid email address'
	except:
		StaticAttr.message = 'An error occured'
	return render_template('login.html', title = 'Login', message = StaticAttr.message)

@app.route('/logout')
def logout():
	StaticAttr.LoggedUser=[]
	StaticAttr.message = 'Logout successful'
	return redirect(url_for('login'))
	



@app.route('/home')
def home():
	try:
		admin = StaticAttr.LoggedUser
		print(admin)
		if is_loggedin():

			print('logged_in_admin: ', StaticAttr.LoggedUser)
			# all_staffs = Staff.query.filter_by(author = admin)
			staffs = Staff.query.filter_by(admin_id = admin.id)
			print(admin, staffs)
			StaticAttr.message=""
			return render_template('home.html', title = 'Home', admin = admin, staffs = staffs , message = StaticAttr.message)
		else:
			StaticAttr.message = 'Login to continue'
	except:
		StaticAttr.message = 'An error occured'
	return redirect(url_for('login'))



@app.route('/addstaff',  methods=['GET','POST'])
def addstaff():
	try:
		admin = StaticAttr.LoggedUser
		print(admin.id)
		if is_loggedin():
			if request.method == 'POST':
				first = request.form['first_name']
				last = request.form['last_name']
				email = request.form['email']
				password = request.form['password']
				hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
				function = request.form['function']
				if email_exist(email) == False:
					staff = Staff(firstName = first, lastName = last, email= email, password = hashed_password,
								 function = function, admin_id = admin.id)
					db.session.add(staff)
					db.session.commit()
					StaticAttr.message = 'Staff account is created!'
				else:
					StaticAttr.message = 'Email already exists'
				return  redirect(url_for('home'))
		else:
			StaticAttr.message = 'Login to continue'
			return redirect(url_for('login'))
	except:
		StaticAttr.message = 'An error occured'
		db.session.remove()
		db.session.commit()

	return render_template('addstaff.html', admin = admin, message=	StaticAttr.message)

@app.route('/addstaff/<int:id>',  methods=['GET','POST'])
def update(id):
	try:
		admin = StaticAttr.LoggedUser
		print(admin)
		if is_loggedin():
			staffold = Staff.query.get_or_404(id)
			if request.method == 'POST':
				first = request.form['first_name']
				last = request.form['last_name']
				email = request.form['email']
				password = request.form['password']
				hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
				function = request.form['function']
				if email_exist(email) == False:
					staffold.firstName = first
					staffold.lastName = last
					staffold.email= email
					staffold.password = hashed_password
					staffold.function = function
					db.session.commit()
					StaticAttr.message = 'Staff account is updated!'
				else:
					StaticAttr.message = 'Email already exists'
				return  redirect(url_for('home'))
		else:
			StaticAttr.message = 'Login to continue'
			return redirect(url_for('login'))
	except:
		StaticAttr.message = 'An error occured'
	return render_template('update.html', admin = admin, staff=staffold, message=	StaticAttr.message)

@app.route('/viewstaff/<int:id>')
def viewstaff(id):
	try:
		admin =StaticAttr.LoggedUser
		if is_loggedin:
			staff = Staff.query.get_or_404(id)
			print(staff)
			return render_template('viewstaff.html', admin=admin, staff = staff)
		else:
			message = 'Login to continue'
	except:
		StaticAttr.message = 'An error occured'
	return redirect(url_for('login'))

@app.route('/delete/<int:id>')
def delete(id):
	try:
		admin = StaticAttr.LoggedUser
		print(admin)
		if is_loggedin():
			staffold = Staff.query.get_or_404(id)
			db.session.delete(staffold)
			db.session.commit()
			return redirect(url_for('home'))
		else:
			StaticAttr.message = 'Login to continue'
			return redirect(url_for('login'))
	except:
		StaticAttr.message = 'An error occured'
	return render_template('home.html', admin = admin, staff=admin.staffs, message=	StaticAttr.message)

def email_exist(email):
	ad = Admin.query.filter_by(email=email).first()
	st = Staff.query.filter_by(email=email).first()
	if ad or st:
		return True
	return False

def is_loggedin():
	if StaticAttr.LoggedUser == []:
		return False
	return True

if __name__ == '__main__':
	app.run(debug=True)