from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from functools import wraps
from passlib.hash import pbkdf2_sha256

app = Flask(__name__)
app.debug=True

app.config['MYSQL_HOST']='127.0.0.1'
app.config['MYSQL_USER']='root'
app.config['MYSQL_PASSWORD']='1234'
app.config['MYSQL_DB']='loginapp'
app.config['MYSQL_CURSORCLASS']='DictCursor'

mysql = MySQL(app)

class RegisterForm(Form):
    name=StringField('Name', [validators.Length(min=1, max=50)])
    email=StringField('Email', [validators.Length(min=4, max=25)])
    username=StringField('Username', [validators.Length(min=4, max=25)])
    password=PasswordField('Password', [validators.DataRequired(),
    validators.EqualTo('confirm', message='passwords do not match')])
    confirm=PasswordField('Confirm password')

@app.route('/')
def main():
    return render_template('main.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data 
        username = form.username.data
        password = pbkdf2_sha256.hash(str(form.password.data))

        cur = mysql.connection.cursor()
        
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

        mysql.connection.commit()

        cur.close()

        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor()

        result = cur.execute('SELECT * FROM users WHERE username=%s', [username])

        if result>0:
            user = cur.fetchall()
            pw = user[0]['password']

            if pbkdf2_sha256.verify(password, pw):
                return redirect(url_for('main'))

            else:
                return "Password is wrong"

        else:
            return "User is not founded"

        cur.close()

    return render_template('login.html')

if __name__ == '__main__':
    app.run()