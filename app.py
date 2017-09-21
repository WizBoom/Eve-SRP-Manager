import logging
import json
import os
import sys
from datetime import datetime
from flask import Flask, flash, redirect, render_template, request, url_for,session
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from preston.esi import Preston
import praw
import re
import requests


# config setup
with open('config.json') as f:
    config = json.load(f)

#Flask app setup
app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = config['SQLALCHEMY_DATABASE_URI']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.urandom(24)

#Login manager
login_manager = LoginManager()
login_manager.login_message = "You're not logged in!"
login_manager.login_view = 'index'
login_manager.init_app(app)

#logging setup
app.logger.setLevel(config['LOGGING']['LEVEL']['ALL'])
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(style='{', fmt='{asctime} [{levelname}] {message}', datefmt='%Y-%m-%d %H:%M:%S')
handler.setFormatter(formatter)
handler.setLevel(config['LOGGING']['LEVEL']['CONSOLE'])
app.logger.addHandler(handler)
handler = logging.FileHandler(config['LOGGING']['FILE'])
handler.setFormatter(formatter)
handler.setLevel(config['LOGGING']['LEVEL']['FILE'])
app.logger.addHandler(handler)

#Create sqlalchemy object
db = SQLAlchemy(app)

from models import *

user_agent = 'GETIN SRP App ({})'.format(config['MAINTAINER'])
# EVE CREST API connection
preston = Preston(
	user_agent=user_agent,
	client_id=config['EVE_CLIENT_ID'],
	client_secret=config['EVE_CLIENT_SECRET'],
	callback_url=config['EVE_CALLBACK_URI']
)

# Get reddit instance
reddit = praw.Reddit('srp_manager')
subreddit = reddit.subreddit(config["SUBREDDIT"])

app.logger.info('Initialization complete')

@login_manager.user_loader
def load_user(user_id):
	return Character.query.filter_by(id=int(user_id)).first()

@app.route('/')
def index():
	return render_template('index.html',url=preston.get_authorize_url())

@app.route('/eve/callback')
def eve_oauth_callback():
	if 'error' in request.path:
		app.logger.error('Error in EVE SSO callback: ' + request.url)
		flash('There was an error in EVE\'s response', 'error')
		return redirect(url_for('login'))
	try:
		auth = preston.authenticate(request.args['code'])
	except Exception as e:
		app.logger.error('ESI signing error: ' + str(e))
		flash('There was an authentication error signing you in.', 'error')
		return redirect(url_for('login'))
	character_info = auth.whoami()
	character = Character.query.filter(Character.character_id == character_info['CharacterID']).first()
	if character:
		login_user(character)
		session['roles'] = [role.role_name for role in current_user.roles.all()]
		app.logger.debug('{} logged in with EVE SSO'.format(current_user.character_name))
		flash('Logged in as {}'.format(current_user.character_name), 'success')
		return redirect(url_for('index'))

	flash('Your character is not in Wormbro! If you are in Wormbro, it is possible your API is still updating. If it has been several hours, contact a mentor.','error')
	return redirect(url_for('index'))

@app.route('/logout/')
def logout():
    app.logger.debug('{} logged out'.format(current_user.character_name if not current_user.is_anonymous else 'unknown user'))
    logout_user()
    session.clear()
    return redirect(url_for('index'))


@app.route('/my_info/')
@login_required
def my_info():
	return render_template("my_info.html")

@app.route('/new_fight/',methods=['GET', 'POST'])
@login_required
def new_fight():
	if "Mentor" in session['roles'] or "Director" in session['roles'] or "Admin" in session['roles']:
		if request.method == 'POST':
			try:
				date = datetime.strptime(request.form['date'],'%Y/%m/%d %H:%M')
			except Exception as e:
				app.logger.error('Exception in new_fight() date conversion by ' + current_user.character_name + ': ' + str(e))
				flash("I don't know how you did it, but you fucked up the date. Use the datapicker please.",'error')
				return redirect(url_for('new_fight'))

			submission = None
			try:
				redditTitle = request.form['title'] + " - " + request.form['date']
				redditContent = "CONTENT TEST"
				submission = subreddit.submit(redditTitle,redditContent)
			except praw.exceptions.APIException as e:
					app.logger.error(str(e))
					flash("We've hit the Reddit post ratelimit! Try again in 10 minutes.",'error')
					return redirect(url_for('new_fight'))
			except Exception as e:
				app.logger.error(str(e))
				flash("An error occurred trying to post to reddit!",'error')
				return redirect(url_for('index'))

			url = None
			if submission:
				url = submission.url

			fight = FleetFight(date,request.form['title'],request.form['FC'],current_user.character_name, url)
			db.session.add(fight)
			db.session.commit()
			app.logger.info("Created " + str(fight))
			return redirect(url_for('view_fight', id=fight.id))

		data = Character.query.order_by(Character.character_name.asc()).all()
		return render_template("new_fight.html", members=data)

	return redirect(url_for('index'))

@app.route('/view_fight/<int:id>',methods=['GET', 'POST'])
@login_required
def view_fight(id):
	fight = FleetFight.query.filter_by(id=id).first()
	if request.method == 'POST':
		if 'type' in request.form:
			if request.form['type'] == 'fc':
				#Do FC app
				zkillLink = request.form['zkill']
				kIdList = re.findall('\d+',zkillLink)
				if len(kIdList) != 1:
					flash('Zkillboard link provided not valid!','error')
					return redirect(url_for('view_fight', id=id)) 

				kId = kIdList[0]

				#Check id
				if SRPRequest.query.filter_by(killId=kId).count() > 0:
					flash('Lossmail has already been used in an SRP request','error')
					return redirect(url_for('view_fight', id=id)) 

				#Calculate percentage
				percentage = 0.5
				options = ["FC"]
				if request.form.get('recording') is not None:
					percentage += 0.25
					options.append("RECORDING")

				if request.form.get('after-action-report') is not None:
					percentage += 0.25
					options.append("AAR")

				#Make zkill request
				request_url = 'https://zkillboard.com/api/killID/' + str(kId) + "/"
				app.logger.info('Making killboard request to {}'.format(request_url))
				r = requests.get(request_url, headers={
					'Accept-Encoding': 'gzip',
					'User-Agent': 'Maintainer: ' + config['ZKILL_USER_AGENT']
				})
				if r.status_code != 200:
					app.logger.error('Got status code {} from {}'.format(r.status_code, request_url))
					flash("Error in zkillboard",'error')
					return redirect(url_for('view_fight', id=id)) 
				data = r.json()
				if not data:
					app.logger.error('{} kill not found'.format(str(kId)))
					flash("Error in zkillboard: kill not found",'error')
					return redirect(url_for('view_fight', id=id)) 

				#Check if user is user on lossmail
				if current_user.character_name != data[0]['victim']['characterName']:
					flash("Zkillboard loss provided isn't the logged in character {}, but is from character {}!".format(current_user.character_name,data[0]['victim']['characterName']),'error')
					return redirect(url_for('view_fight', id=id)) 

				#Calculate payout
				payout = data[0]['zkb']['totalValue'] * percentage
				if payout >= config['MAX_SRP']:
					payout = config['MAX_SRP']

				#Commit SRP
				SRP = SRPRequest(current_user.character_name,kId,data[0]['zkb']['totalValue'],price,",".join(options),request.form['reddit'])
				db.session.add(SRP)
				fight.requests.append(SRP)
				db.session.commit()
				return redirect(url_for('my_info'))
			elif request.form['type'] == 'logi':
				#Do logi app
				zkillLink = request.form['zkill']
				kIdList = re.findall('\d+',zkillLink)
				if len(kIdList) != 1:
					flash('Zkillboard link provided not valid!','error')
					return redirect(url_for('view_fight', id=id)) 

				kId = kIdList[0]

				#Check id
				if SRPRequest.query.filter_by(killId=kId).count() > 0:
					flash('Lossmail has already been used in an SRP request','error')
					return redirect(url_for('view_fight', id=id)) 

				#Calculate percentage
				percentage = 0.5
				options = ["logi"]
				if request.form.get('recording') is not None:
					percentage += 0.25
					options.append("RECORDING")

				#Make zkill request
				request_url = 'https://zkillboard.com/api/killID/' + str(kId) + "/"
				app.logger.info('Making killboard request to {}'.format(request_url))
				r = requests.get(request_url, headers={
					'Accept-Encoding': 'gzip',
					'User-Agent': 'Maintainer: ' + config['ZKILL_USER_AGENT']
				})
				if r.status_code != 200:
					app.logger.error('Got status code {} from {}'.format(r.status_code, request_url))
					flash("Error in zkillboard",'error')
					return redirect(url_for('view_fight', id=id)) 
				data = r.json()
				if not data:
					app.logger.error('{} kill not found'.format(str(kId)))
					flash("Error in zkillboard: kill not found",'error')
					return redirect(url_for('view_fight', id=id)) 

				#Check if user is user on lossmail
				if current_user.character_name != data[0]['victim']['characterName']:
					flash("Zkillboard loss provided isn't the logged in character {}, but is from character {}!".format(current_user.character_name,data[0]['victim']['characterName']),'error')
					return redirect(url_for('view_fight', id=id)) 

				#Calculate payout
				payout = data[0]['zkb']['totalValue'] * percentage
				if payout >= config['MAX_SRP']:
					payout = config['MAX_SRP']

				#Commit SRP
				SRP = SRPRequest(current_user.character_name,kId,data[0]['zkb']['totalValue'],payout,",".join(options),request.form['reddit'])
				db.session.add(SRP)
				fight.requests.append(SRP)
				db.session.commit()
				return redirect(url_for('my_info'))
		elif 'accepted' in request.form:
			# Look for specific request
			srpRequest = SRPRequest.query.filter_by(id=int(request.form['accepted'])).first()
			srpRequest.approved = True
			db.session.commit()
		elif 'rejected' in request.form:
			# Look for specific request
			srpRequest = SRPRequest.query.filter_by(id=int(request.form['accepted'])).first()
			srpRequest.approved = False
			db.session.commit()
	return render_template('view_fight.html',fight=fight)

@app.route('/dancefloor/')
def dancefloor():
	db.drop_all()
	db.create_all()
	char1 = Character('Alex Kommorov',92399833)
	char2 = Character('Corporate Kommorov',96639141)
	char3 = Character('Ilya Kommorov',92351650)
	role1 = Role('Mentor')
	role2 = Role('Admin')
	role3 = Role('Director')
	fight1 = FleetFight(datetime.utcnow(),"Fight 1","Alex Kommorov","Alex Kommorov")
	fight2 = FleetFight(datetime.utcnow(),"Fight 2","Bishop 5","Alex Kommorov")
	db.session.add(char1)
	db.session.add(char2)
	db.session.add(char3)
	db.session.add(role1)
	db.session.add(role2)
	db.session.add(role3)
	db.session.add(fight1)
	db.session.add(fight2)
	db.session.commit()
	char1.roles.append(role1)
	char1.roles.append(role2)
	char1.roles.append(role3)
	char2.roles.append(role1)
	db.session.commit()
	return redirect(url_for('index'))

@app.route('/sand/')
def sand():
	char = Character.query.filter(Character.id == 1).first()
	db.session.delete(char)
	fight = FleetFight.query.filter(FleetFight.id == 1).first()
	db.session.delete(fight)
	db.session.commit()
	return redirect(url_for('index'))

#Run app
if __name__ == '__main__':
	app.run()