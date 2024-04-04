from flask import Flask,render_template,redirect,url_for,request,flash,session,jsonify
from mysql.connector.pooling import MySQLConnectionPool
from flask_bcrypt import Bcrypt
import os
from key import *
from tokens import *
from sendmail import *
app=Flask(__name__)
app.config['SECRET_KEY'] = secret_key
app.config['SESSION_TYPE'] = 'Filesystem'
db=os.environ['RDS_DB_NAME']
user=os.environ['RDS_USERNAME']
password=os.environ['RDS_PASSWORD']
host=os.environ['RDS_HOSTNAME']
port=os.environ['RDS_PORT']
bcrypt=Bcrypt(app)

#conn=MySQLConnectionPool(host='localhost',user='root',password='CHsrinu@506',db='master',pool_name='login',pool_size=3,pool_reset_session=True)
conn=MySQLConnectionPool(host=host,user=user,password=password,db=db,pool_name='login',pool_size=3,pool_reset_session=True)
try:
    mydb=conn.get_connection()
    cursor=mydb.cursor(buffered=True)
    cursor.execute('create table if not exists student(sid int primary key auto_increment,name varchar(50) not null,rollnumber varchar(10) unique not null,email varchar(60) unique not null,password varchar(100) not null)auto_increment=20240301')
    cursor.execute('create table if not exists report(rid int primary key auto_increment,subject varchar(30),total int not null default 5,score int,rollnumber varchar(10) not null,foreign key(rollnumber) references student(rollnumber))')
    cursor.execute('create table if not exists discussion(rollnumber varchar(20),subject varchar(50),message varchar(200))')
    cursor.execute('create table if not exists reply(rollnumber varchar(20),subject varchar(50),message varchar(200),reply varchar(200))')

    mydb.commit()
    cursor.close()
except Exception as e:
    print(e)
finally:
    if mydb.is_connected():
        mydb.close()
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup',methods=['GET','POST'])
def signup():
    if request.method=='POST':
        name=request.form['name']
        roll=request.form['roll']
        email=request.form['email']
        password=request.form['password']
        password=bcrypt.generate_password_hash(password).decode('utf-8')
        otp=generate_otp()
        data={'name':name,'roll':roll,'email':email,'password':password,'otp':otp}
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(*) from student where email=%s',(data['email'],))
            email_count=cursor.fetchone()[0]
            cursor.execute('select count(*) from student where rollnumber=%s',(data['roll'],))
            roll_count=cursor.fetchone()[0]
            if email_count==1:
                flash('Email ID already exists')
                return render_template('signup.html')
            elif roll_count==1:
                flash('Roll Number already exists')
                return render_template('signup.html')
            else:
                subject='Email Confirmation'
                body=f'''
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>OTP Validation Email</title>
                </head>
                <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                    <table style="max-width: 600px; margin: 0 auto; background-color: #fff; padding: 20px; border-radius: 10px; box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);">
                        <tr>
                            <td>
                                <h2 style="text-align: center; color: #333; margin-bottom: 30px;">OTP Validation</h2>
                                <p style="color: #555;">Hello,</p>
                                <p style="color: #555;">Your OTP for Email validation is: <strong style="color: #333;">{otp}</strong></p>
                                <p style="color: #555;">Please use this OTP to complete the validation process. This OTP will expire in 10 minutes.</p>
                                <p style="color: #555;">If you did not request this OTP, please ignore this email.</p>
                                <p style="color: #555;">Regards,<br>Your Company</p>
                            </td>
                        </tr>
                    </table>
                </body>
                </html>
                '''
                sendmail(data['email'],subject,body)
                flash('Mail sended successfully!')
                return redirect(url_for('otp',token=create_token(data,salt=salt)))     
        except Exception as e:
            print(e)
        finally:
            if mydb.is_connected():
                mydb.close()
    else:
        return render_template('signup.html')

@app.route('/otp/<token>',methods=['GET','POST'])
def otp(token):
    data=verify_token(token,salt=salt,expiration=600)
    if request.method=='POST':
        user_otp=request.form['otp']
        if data:
            if data['otp']==user_otp:
                try:
                    mydb=conn.get_connection()
                    cursor=mydb.cursor(buffered=True)
                    cursor.execute('select count(*) from student where email=%s',(data['email'],))
                    email_count=cursor.fetchone()[0]
                    cursor.execute('select count(*) from student where rollnumber=%s',(data['roll'],))
                    roll_count=cursor.fetchone()[0]
                    if email_count==1:
                        flash('User Already Registered! Please Login into Continue.')
                        return redirect(url_for('login'))
                    elif roll_count==1:
                        flash('User Already Registered! Please Login into Continue.')
                        return redirect(url_for('login'))
                    else:
                        cursor.execute('insert into student (name,rollnumber,email,password) values(%s,%s,%s,%s)',(data['name'],data['roll'],data['email'],data['password']))
                        cursor.close()
                        mydb.commit()
                        flash('Email verification completed please login to continue')
                        return redirect(url_for('login'))
                except Exception as e:
                    print(e)
                finally:
                    if mydb.is_connected():
                        mydb.close()
            else:
                flash('OTP Invalid try again')
                return render_template('otp.html')
        else:
            flash('OTP Expired')
            return redirect(url_for('signup'))
    else:
        return render_template('otp.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        roll=request.form['roll']
        password=request.form['password']
        data={'roll':roll,'password':password}
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(*),password,name from student where rollnumber=%s',(data['roll'],))
            cursor.close()
            roll_count,password,name=cursor.fetchone()
            if roll_count==1:
                if bcrypt.check_password_hash(password,data['password']):
                    session['user'] = name
                    session['roll'] = data['roll']
                    return redirect(url_for('student_dashboard'))
                else:
                    flash('Password mismatched')
                    return render_template('login.html')
            else:
                flash('Roll Number not exist')
                return render_template('login.html')
        except Exception as e:
                print(e)
        finally:
            if mydb.is_connected():
                mydb.close()
    return render_template('login.html')

@app.route('/student_logout')
def student_logout():
    if session.get('user'):
        session.pop('user')
        return redirect(url_for('login'))

    else:
        flash('Please Login to continue')
        return redirect(url_for('login'))

@app.route('/admin_logout')
def admin_logout():
    if session.get('admin'):
        session.pop('admin')
        return redirect(url_for('admin'))

    else:
        flash('Please Login to continue')
        return redirect(url_for('admin'))

@app.route('/forgot',methods=['GET','POST'])
def forgot():
    if request.method=='POST':
        email=request.form['email']
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(*) from student where email=%s',(email,))
            email_count=cursor.fetchone()[0]
            cursor.close()
            if email_count==1:
                token_url=url_for('verify',token=create_token(data=email,salt=salt2),_external=True)
                subject='Forget password link '
                body=f'this is your link \n {token_url}'
                sendmail(rmail=email,subject=subject,body=body)
                flash('Verification link sent to your mail')
                return redirect(url_for('login'))
            else:
                flash('Email Id not exist')
                return render_template('forget.html')
        except Exception as e:
                print(e)
        finally:
            if mydb.is_connected():
                mydb.close()        
    return render_template('forgot.html')

@app.route('/verify/<token>',methods=['GET','POST'])
def verify(token):
    email=verify_token(token=token,salt=salt2,expiration=600)
    if email:
        if request.method=='POST':
            npass=request.form['npass']
            cpass=request.form['cpass']
            if npass==cpass:
                try:
                    mydb=conn.get_connection()
                    cursor=mydb.cursor(buffered=True)
                    hashpass=bcrypt.generate_password_hash(npass).decode('utf-8')
                    cursor.execute('update student set password=%s where email=%s',(hashpass,email))
                    flash('password updated successfully')
                    return redirect(url_for('login'))
                except Exception as e:
                    print(e)
                finally:
                    if mydb.is_connected():
                        cursor.close()
                        mydb.commit() 
            else:
                flash('password not matched')
                return render_template('verify.html')
        else:
            return render_template('verify.html',token=token)
    else:
        flash('Link Expired')
        return redirect(url_for('forgot'))

@app.route('/adminlogin',methods=['GET','POST'])
def admin():
    if request.method=='POST':  
        username=request.form['username'] #quizadmin@gec
        password=request.form['password'] #gec@2024
        if username=='quizadmin@gec' and password=='gec@2024':
            session['admin']=username
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password')
            return render_template('adminlogin.html')
    return render_template('adminlogin.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if session.get('admin'):
        return render_template('admin_dashboard.html')
    else:
        flash('Please login to continue')
        return redirect(url_for('adminlogin'))
    
@app.route('/student_dashboard')
def student_dashboard():
    if session.get('user'):
        return render_template('student_dashboard.html')
    else:
        flash('Please Login to continue')
        return redirect(url_for('login'))
    
@app.route('/I_subjects')
def I_subjects():
    return render_template('I_subjects.html')
@app.route('/II_subjects')
def II_subjects():
    return render_template('II_subjects.html')
@app.route('/III_subjects')
def III_subjects():
    return render_template('III_subjects.html')
@app.route('/IV_subjects')
def IV_subjects():
    return render_template('IV_subjects.html')

@app.route('/quiz_reports')
def quiz_reports():
    if session.get('roll'):
        roll= session.get('roll')
        try:
            mydb = conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("Select subject,score from report where rollnumber=%s order by rid desc",(roll,))
            data = cursor.fetchall()
            if data:
                return render_template('quiz_reports.html',data=data)
            else:
                flash('No quiz Attempted')
                return redirect(url_for('student_dashboard'))
        except Exception as e:
            print(e)
            return "Something Happened"
        finally:
            if mydb.is_connected():
                cursor.close()
                mydb.close()
    else:
        return redirect(url_for('login'))

#I year Subjects
@app.route('/cprogram',methods=['POST','GET'])
def cprogram():
    if session.get('roll'):
        roll = session.get('roll')
        subject = 'C Programming Quiz'
        try:
            mydb = conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("Select count(*) from report where rollnumber=%s and subject=%s",(roll,subject))
            count = cursor.fetchone()[0]
            if count==1:
                flash("Exam Already Attempted")
                return redirect(url_for('student_dashboard'))
            else:
                return render_template('cprogram.html')
        except Exception as e:
            print(e)
            return"Something Happened! Error."
        finally:
            if mydb.is_connected():
                cursor.close()
                mydb.close()
    else:
        return redirect(url_for('login'))
@app.route('/english')
def english():
    if session.get('roll'):
        roll = session.get('roll')
        subject = 'English Quiz'
        try:
            mydb = conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("Select count(*) from report where rollnumber=%s and subject=%s",(roll,subject))
            count = cursor.fetchone()[0]
            if count==1:
                flash("Exam Already Attempted")
                return redirect(url_for('student_dashboard'))
            else:
                return render_template('english.html')
        except Exception as e:
            print(e)
            return"Something Happened! Error."
        finally:
            if mydb.is_connected():
                cursor.close()
                mydb.close()
    else:
        return redirect(url_for('login'))
    
#II year Subjects
@app.route('/python')
def python():
    if session.get('roll'):
        roll = session.get('roll')
        subject = 'Python Quiz'
        try:
            mydb = conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("Select count(*) from report where rollnumber=%s and subject=%s",(roll,subject))
            count = cursor.fetchone()[0]
            if count==1:
                flash("Exam Already Attempted")
                return redirect(url_for('student_dashboard'))
            else:
                return render_template('python.html')
        except Exception as e:
            print(e)
            return"Something Happened! Error."
        finally:
            if mydb.is_connected():
                cursor.close()
                mydb.close()
    else:
        return redirect(url_for('login'))
@app.route('/os')
def os():
    if session.get('roll'):
        roll = session.get('roll')
        subject = 'Operating System Quiz'
        try:
            mydb = conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("Select count(*) from report where rollnumber=%s and subject=%s",(roll,subject))
            count = cursor.fetchone()[0]
            if count==1:
                flash("Exam Already Attempted")
                return redirect(url_for('student_dashboard'))
            else:
                return render_template('os.html')
        except Exception as e:
            print(e)
            return"Something Happened! Error."
        finally:
            if mydb.is_connected():
                cursor.close()
                mydb.close()
    else:
        return redirect(url_for('login'))

#III year Subjects
@app.route('/java')
def java():
    if session.get('roll'):
        roll = session.get('roll')
        subject = 'Java Quiz'
        try:
            mydb = conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("Select count(*) from report where rollnumber=%s and subject=%s",(roll,subject))
            count = cursor.fetchone()[0]
            if count==1:
                flash("Exam Already Attempted")
                return redirect(url_for('student_dashboard'))
            else:
                return render_template('java.html')
        except Exception as e:
            print(e)
            return"Something Happened! Error."
        finally:
            if mydb.is_connected():
                cursor.close()
                mydb.close()
    else:
        return redirect(url_for('login'))
@app.route('/cn')
def cn():
    if session.get('roll'):
        roll = session.get('roll')
        subject = 'Computer Networks Quiz'
        try:
            mydb = conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("Select count(*) from report where rollnumber=%s and subject=%s",(roll,subject))
            count = cursor.fetchone()[0]
            if count==1:
                flash("Exam Already Attempted")
                return redirect(url_for('student_dashboard'))
            else:
                return render_template('cn.html')
        except Exception as e:
            print(e)
            return"Something Happened! Error."
        finally:
            if mydb.is_connected():
                cursor.close()
                mydb.close()
    else:
        return redirect(url_for('login'))
 
#IV year Subjects
@app.route('/dl')
def dl():
    if session.get('roll'):
        roll = session.get('roll')
        subject = 'Deep Learning Quiz'
        try:
            mydb = conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("Select count(*) from report where rollnumber=%s and subject=%s",(roll,subject))
            count = cursor.fetchone()[0]
            if count==1:
                flash("Exam Already Attempted")
                return redirect(url_for('student_dashboard'))
            else:
                return render_template('dl.html')
        except Exception as e:
            print(e)
            return"Something Happened! Error."
        finally:
            if mydb.is_connected():
                cursor.close()
                mydb.close()
    else:
        return redirect(url_for('login'))
@app.route('/cc')
def cc():
    if session.get('roll'):
        roll = session.get('roll')
        subject = 'Cloud Computing Quiz'
        try:
            mydb = conn.get_connection()
            cursor = mydb.cursor(buffered=True)
            cursor.execute("Select count(*) from report where rollnumber=%s and subject=%s",(roll,subject))
            count = cursor.fetchone()[0]
            if count==1:
                flash("Exam Already Attempted")
                return redirect(url_for('student_dashboard'))
            else:
                return render_template('cc.html')
        except Exception as e:
            print(e)
            return"Something Happened! Error."
        finally:
            if mydb.is_connected():
                cursor.close()
                mydb.close()
    else:
        return redirect(url_for('login'))

@app.route('/submitQuiz', methods=['POST'])
def submit_quiz():
    if session.get('roll'):
        roll = session.get('roll')
        data = request.get_json()  # Get JSON data from the request body
        score = data.get('score')  # Get the 'score' value from the JSON data
        subject = data.get('subject')  # Get the 'subject' value from the JSON data
        if score is not None and subject is not None:
            #print('Received quiz score:', score, 'for subject:', subject)
            try:
                mydb = conn.get_connection()
                cursor = mydb.cursor(buffered=True)
                cursor.execute("Insert into report(subject,score,rollnumber) values(%s,%s,%s)",(subject,score,roll))
                mydb.commit()
            except Exception as e:
                print(e)
                return"Something Happened! Error."
            finally:
                if mydb.is_connected():
                    cursor.close()
                    mydb.close()
            return jsonify({'message': 'Quiz submitted successfully!'}), 200
            
        else:
            return jsonify({'message': 'Invalid request. Score or subject not provided.'}), 400
    else:
        return redirect(url_for('login'))


@app.route('/discussion/<subject>',methods=['GET','POST'])
def discussion(subject):
    if session.get('user'):
        roll = session.get('roll')
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(*) from discussion where subject=%s',(subject,))
            count_sub=cursor.fetchone()[0]
            if count_sub==1:
                flash('You are already submitted the Discussion form\n Go to see in discussion forms')
                return redirect(url_for('forums'))
            else:
                if request.method=='POST':
                    message=request.form['message']
                    cursor.execute('insert into discussion(rollnumber,subject,message) values(%s,%s,%s)',(roll,subject,message))
                    cursor.close()
                    mydb.commit()
                    return redirect(url_for('forums'))
                else:
                    return render_template('discussionform.html',subject=subject,roll=roll)
        except Exception as e:
            print(e)
        finally:
            if mydb.is_connected():
                mydb.close()     
    else:
        flash('Please login to continue')
        return redirect(url_for('login'))

@app.route('/forums',methods=['GET','POST'])
def forums():
    if session.get('user'):
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select *from discussion')
            data = cursor.fetchall()
            if data:
                return render_template('reply.html',data=data)
            else:
                flash('No forms are found')
                return redirect(url_for('student_dashboard'))
        except Exception as e:
            print(e)
        finally:
            if mydb.is_connected():
                mydb.close()
                cursor.close()
    else:
        flash('Please login to continue')
        return redirect(url_for('login'))

@app.route('/admin_reports')
def admin_reports():
    if session.get('admin'):
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True,dictionary=True)
            cursor.execute('select * from report order by rollnumber')
            data = cursor.fetchall()
            if data:
                return render_template('admin_reports.html',data=data)
            else:
                flash('No reports are found')
                return redirect(url_for('student_dashboard'))
        except Exception as e:
            print(e)
        finally:
            if mydb.is_connected():
                mydb.close()
                cursor.close()
    else:
        flash('Please login to continue')
        return redirect(url_for('adminlogin'))
  
@app.route('/admin_forums',methods=['GET','POST'])
def admin_forums():
    if session.get('admin'):
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True,dictionary=True)
            cursor.execute('select *from discussion')
            data = cursor.fetchall()
            if data:
                return render_template('admin_forums.html',data=data)
            else:
                flash('No forums are found')
                return redirect(url_for('student_dashboard'))
        except Exception as e:
            print(e)
        finally:
            if mydb.is_connected():
                mydb.close()
                cursor.close()
    else:
        flash('Please login to continue')
        return redirect(url_for('adminlogin'))

@app.route('/student_details')
def student_details():
    if session.get('admin'):
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True,dictionary=True)
            cursor.execute('select *from student')
            data = cursor.fetchall()
            if data:
                return render_template('student_details.html',data=data)
            else:
                flash('No students are found')
                return redirect(url_for('student_dashboard'))
        except Exception as e:
            print(e)
        finally:
            if mydb.is_connected():
                mydb.close()
                cursor.close()

@app.route('/viewpost/<subject>/<message>',methods=['GET','POST'])
def viewpost(subject,message):
    if session.get('user'):
        roll=session.get('roll')
        if request.method=='POST':
            reply=request.form['reply']
            try:
                mydb=conn.get_connection()
                cursor=mydb.cursor(buffered=True,dictionary=True)
                cursor.execute('insert into reply values(%s,%s,%s,%s)',(roll,subject,message,reply))
                mydb.commit()
                cursor.execute('select *from reply')
                data=cursor.fetchall()
                return render_template('viewpost.html',data=data)
            except Exception as e:
                print(e)
            finally:
                if mydb.is_connected():
                    mydb.close()
                    cursor.close()
        else:
            return render_template('reply.html')
    else:
        flash('Please login to continue')
        return redirect(url_for('login'))

@app.route('/postview',methods=['GET','POST'])
def postview():
    if session.get('user') or session.get('admin'):
        try:
            mydb=conn.get_connection()
            cursor=mydb.cursor(buffered=True,dictionary=True)
            cursor.execute('select *from reply')
            data=cursor.fetchall()
            return render_template('viewpost.html',data=data)
        except Exception as e:
            print(e)
        finally:
            if mydb.is_connected():
                mydb.close()
                cursor.close()
    else:
        flash('Please login to continue')
        return redirect(url_for('login'))





if __name__=='__main__':
    app.run(debug=True,use_reloader=True)
