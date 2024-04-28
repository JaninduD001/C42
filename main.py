import flask

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SECRET_KEY"] = "1234"
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

def hash_password(password):
    salt = "randomsaltvalue"
    hashed_password = hashlib.sha256(password.encode('utf-8') + salt.encode('utf-8')).hexdigest()
    return hashed_password

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = hash_password(password)
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == hash_password(password):
            session['username'] = username
            user.last_login = datetime.now()
            db.session.commit()
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        return render_template('dashboard.html', user=user)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)