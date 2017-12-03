import logging
import json
import os
import sys
from datetime import datetime, timedelta
import time
from flask import Flask, flash, redirect, render_template, request, url_for,session
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from preston.esi import Preston
import praw
import re
import requests
import base64
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

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

#Scheduler
scheduler = BackgroundScheduler()
scheduler.start()

from models import *

user_agent = 'GETIN SRP App ({})'.format(config['MAINTAINER'])
# EVE  API connection
preston = Preston(
	user_agent=user_agent,
	client_id=config['EVE_CLIENT_ID'],
	client_secret=config['EVE_CLIENT_SECRET'],
	callback_url=config["BASE_URL"] + config['EVE_CALLBACK_URI']
)

prestonCorp = Preston(
	user_agent=user_agent,
	client_id=config["CORP_CLIENT_ID"],
	client_secret=config["CORP_CLIENT_SECRET"],
	callback_url=config["BASE_URL"] + config["CORP_CALLBACK_URI"],
	scope="esi-corporations.read_corporation_membership.v1 esi-wallet.read_corporation_wallets.v1"
)

# Get reddit instance
reddit = praw.Reddit('srp_manager')
subreddit = reddit.subreddit(config["SUBREDDIT"])

app.logger.info('Initialization complete')

def get_current_roles():
	if current_user.is_authenticated:
		return [role.role_name for role in current_user.roles.all()]
	else:
		return None

app.jinja_env.globals.update(get_current_roles=get_current_roles)

@login_manager.user_loader
def load_user(user_id):
	return Character.query.filter_by(id=int(user_id)).first()

@app.route('/')
def index():
	date = datetime.utcnow() - timedelta(days=config['OPEN_DAYS'])
	fights = None
	requests = None
	transactions= None
	balance = None
	if current_user.is_authenticated:
		fights = FleetFight.query.filter(FleetFight.timestamp >= date).all()
		transactions = Transaction.query.order_by(Transaction.date.desc()).limit(config['HOMEPAGE_LOG_AMOUNT']).all()
		if transactions:
			balance = Transaction.query.order_by(Transaction.date.desc()).first().balance
		else:
			balance = 0
		dbRequest = current_user.srp_requests.order_by(SRPRequest.timestamp.desc()).all()
		requests = []
		for r in dbRequest:
			if r.approved is None or (r.approved == True and r.paid == False):
				requests.append(r)

	return render_template('index.html',url=preston.get_authorize_url(), fights=fights, requests=requests, transactions=transactions, balance=balance)

@app.route('/transactions')
@login_required
def transaction_logs():
	transactions = Transaction.query.order_by(Transaction.date.desc()).all()
	return render_template('transaction_log.html',transactions=transactions)

@app.route('/eve/callback')
def eve_oauth_callback():
	if 'error' in request.path:
		app.logger.error('Error in EVE SSO callback: ' + request.url)
		flash('There was an error in EVE\'s response', 'error')
		return redirect(url_for('index'))
	try:
		auth = preston.authenticate(request.args['code'])
	except Exception as e:
		app.logger.error('ESI signing error: ' + str(e))
		flash('There was an authentication error signing you in.', 'error')
		return redirect(url_for('index'))
	character_info = auth.whoami()
	character = Character.query.filter(Character.character_id == character_info['CharacterID']).first()
	if character and character.in_corp:
		login_user(character)
		#session['roles'] = [role.role_name for role in current_user.roles.all()]

		app.logger.debug('{} logged in with EVE SSO'.format(current_user.character_name))
		flash('Logged in as {}'.format(current_user.character_name), 'success')
		return redirect(url_for('index'))

	flash('Your character is not in Wormbro! If you are in Wormbro, it is possible your API is still updating. If it has been several hours, contact a mentor.','error')
	return redirect(url_for('index'))

@app.route('/eve/corp/callback')
def eve_oauth_corp_wallback():
	if 'Admin' not in get_current_roles():
		return redirect(url_for('index'))

	if 'error' in request.path:
		app.logger.error('Error in EVE SSO callback: ' + request.url)
		flash('There was an error in EVE\'s response', 'error')
		return redirect(url_for('index'))
	try:
		auth = prestonCorp.authenticate(request.args['code'])
		if ESICode.query.count() == 0:
			#Make the new entry
			code = ESICode(auth.access_token, auth.refresh_token)
			app.logger.info("{} succesfully added ESI code with access token {} and refresh token {}".format(current_user.character_name,str(auth.access_token),str(auth.refresh_token)))
			db.session.add(code)
			db.session.commit()
		else:
			#Update existing entry
			code = ESICode.query.first()
			code.access_token = auth.access_token
			code.refresh_token = auth.refresh_token
			app.logger.info("{} succesfully updated ESI code with access token {} and refresh token {}".format(current_user.character_name,str(auth.access_token),str(auth.refresh_token)))
			db.session.commit()

		return redirect(url_for('admin'))
	except Exception as e:
		app.logger.error('ESI signing error: ' + str(e))
		flash('There was an authentication error signing you in.', 'error')
		return redirect(url_for('index'))

	flash(code,'error')
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
	r = current_user.srp_requests.order_by(SRPRequest.timestamp.desc()).all()
	return render_template("my_info.html", requests=r,base_url=config['BASE_URL'])

@app.route('/admin/', methods=['GET', 'POST'])
@login_required
def admin():
	roles = get_current_roles()
	if "Admin" not in roles and "Director" not in roles:
		app.logger.info('Admin / Director access denied to {}'.format(current_user.character_name))
		return redirect(url_for('index'))

	if request.method == 'POST':
		app.logger.debug('POST on admin by {}'.format(current_user.character_name))
		character_table_id = request.form['character_table_id']
		role_table_id = request.form['role_table_id']
		character = Character.query.filter(Character.id == character_table_id).first()
		if character is None or character.in_corp == False:
			app.logger.info('Character with ID {} does not exist  or is not in corp'.format(str(character_table_id)))
			flash('Character with ID {} does not exist  or is not in corp'.format(str(character_table_id)),'error')
			return redirect(url_for('admin'))

		role = Role.query.filter(Role.id == role_table_id).first()
		if role is None:
			app.logger.info('Role with ID {} does not exist'.format(str(role_table_id)))
			flash('Role with ID {} does not exist'.format(str(role_table_id)),'error')
			return redirect(url_for('admin'))

		if role in character.roles:
			app.logger.info('{} already had the role {}'.format(character.character_name, role.role_name))
			flash('{} already had the role {}'.format(character.character_name, role.role_name),'error')
			return redirect(url_for('admin'))

		character.roles.append(role)
		app.logger.info('Gave {} the role {}'.format(character.character_name, role.role_name))
		flash('Gave {} the role {}'.format(character.character_name, role.role_name),'success')
		db.session.commit()
		return redirect(url_for('admin'))

	#Get roles
	roles = Role.query.order_by(Role.role_name.asc()).all()
	characters = Character.query.order_by(Character.character_name.asc()).all()
	return render_template("admin.html", roles=roles,base_url=config['BASE_URL'],characters=characters)	

@app.route('/history/')
@login_required
def history():
	roles = get_current_roles()
	if "Admin" not in roles and "Director" not in roles and "Mentor" not in roles:
		app.logger.info('Admin / Director / Mentor access denied to {}'.format(current_user.character_name))
		return redirect(url_for('index'))

	fights = FleetFight.query.order_by(FleetFight.date.desc()).all()
	return render_template("history.html", fights=fights)	

@app.route('/admin/revoke/<character_table_id>/<role_id>')
@login_required
def revoke_access(character_table_id, role_id):
	roles = get_current_roles()
	if "Admin" not in roles and "Director" not in roles:
		app.logger.info('Admin / Director access denied to {}'.format(current_user.character_name))
		return redirect(url_for('index'))

	character = Character.query.filter_by(id=character_table_id).first()
	if not character:
		flash('Unknown member name', 'error')
		return redirect(url_for('admin'))

	for role in character.roles:
		if str(role.id) == role_id:
			app.logger.info('Removed {} from {}'.format(character.character_name,role.role_name))
			flash('Removed {} from {}'.format(character.character_name,role.role_name),'success')
			character.roles.remove(role)
			break
	db.session.commit()

	return redirect(url_for('admin'))

@app.route('/sync/')
@login_required
def sync():
	roles = get_current_roles()
	if "Admin" not in roles and "Director" not in roles:
		app.logger.info('Admin / Director access denied to {}'.format(current_user.character_name))
		return redirect(url_for('index'))

	if sync_transactions() == False:
		return redirect(url_for('admin'))

	if sync_corp_members() == False:
		return redirect(url_for('admin'))

	flash('Successfully synced transactions and corp members','success')
	return redirect(url_for('admin'))

@app.route('/authorize/')
@login_required
def authorize_corp():
	roles = get_current_roles()
	if "Admin" not in roles and "Director" not in roles:
		return redirect(url_for('index'))
	return redirect(prestonCorp.get_authorize_url())

@app.route('/new_fight/',methods=['GET', 'POST'])
@login_required
def new_fight():
	roles = get_current_roles()
	if "Mentor" in roles or "Director" in roles or "Admin" in roles:
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

				submission = subreddit.submit(redditTitle,selftext="")
				submission.mod.flair(config['FLAIR_TEXT'],config['FLAIR_CSS'])
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
			app.logger.info(current_user.character_name +" created fight in the database:" + str(fight))
			redditContent = """
**Date:** {}\n
**FC:** {}\n
**Mentor:** {}\n
[SRP Link]({})\n

*If you lost a ship during this fight, apply on the SRP link. If you'd like a bigger percentage, provide a link to your reddit comment made in this thread*
				""".format(fight.date.strftime('%Y/%m/%d %H:%M'),fight.fc,fight.mentor,config['BASE_URL'] +"/view_fight/" + str(fight.id))
			submission.edit(redditContent)

			return redirect(url_for('view_fight', id=fight.id))

		data = Character.query.order_by(Character.character_name.asc()).all()
		return render_template("new_fight.html", members=data)

	return redirect(url_for('index'))

@app.route('/view_fight/<int:id>',methods=['GET', 'POST'])
@login_required
def view_fight(id):
	fight = FleetFight.query.filter_by(id=id).first()
	closeDate = fight.timestamp + timedelta(days=config['OPEN_DAYS'])

	if fight is None:
		flash("Fight with id {} does not exist!".format(str(id)),'error')
		return redirect(url_for('index'))

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
				if current_user.character_id != data[0]['victim']['character_id']:
					flash("Zkillboard loss provided isn't the logged in character {}!".format(current_user.character_name),'error')
					return redirect(url_for('view_fight', id=id)) 

				#Calculate payout
				payout = data[0]['zkb']['totalValue'] * percentage
				if payout >= config['MAX_SRP']:
					payout = config['MAX_SRP']

				#Commit SRP
				SRP = SRPRequest(kId,data[0]['zkb']['totalValue'],payout,",".join(options),request.form['reddit'])
				#db.session.add(SRP)
				current_user.srp_requests.append(SRP)
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
				if current_user.character_id != data[0]['victim']['character_id']:
					flash("Zkillboard loss provided isn't the logged in character {}!".format(current_user.character_name),'error')
					return redirect(url_for('view_fight', id=id)) 

				#Calculate payout
				payout = data[0]['zkb']['totalValue'] * percentage
				if payout >= config['MAX_SRP']:
					payout = config['MAX_SRP']

				#Commit SRP
				SRP = SRPRequest(kId,data[0]['zkb']['totalValue'],payout,",".join(options),request.form['reddit'])
				current_user.srp_requests.append(SRP)
				fight.requests.append(SRP)
				db.session.commit()
				return redirect(url_for('my_info'))

		elif 'accepted' in request.form:
			# Look for specific request
			srpRequest = SRPRequest.query.filter_by(id=int(request.form['accepted'])).first()
			srpRequest.approved = True
			srpRequest.rejectionReason = ""
			db.session.commit()
		elif 'rejected' in request.form:
			# Look for specific request
			srpRequest = SRPRequest.query.filter_by(id=int(request.form['rejected'])).first()
			if srpRequest is None:
				flash("There is no SRP Request with that ID",'error')
				return render_template('view_fight.html',fight=fight)
			srpRequest.approved = False
			srpRequest.rejectionReason = request.form['rejReason']
			db.session.commit()
		elif 'pay' in request.form:
			#Look for specific request
			srpRequest = SRPRequest.query.filter_by(id=int(request.form['pay'])).first()
			srpRequest.paid = True
			db.session.commit()
		elif 'unpay' in request.form:
			#Look for specific request
			srpRequest = SRPRequest.query.filter_by(id=int(request.form['unpay'])).first()
			srpRequest.paid = False
			db.session.commit()

	return render_template('view_fight.html',fight=fight, closeDate=closeDate,closed=datetime.utcnow() > closeDate)


@app.route('/remove_fight/<int:id>')
@login_required
def remove_fight(id):
	roles = get_current_roles()
	fight = FleetFight.query.filter(FleetFight.id == id).first()
	if fight is None:
		flash("Fight with id {} does not exist!".format(str(id)),'error')
		return redirect(url_for('index'))

	if ("Mentor" in roles and current_user.character_name == fight.mentor) or "Director" in roles or "Admin" in roles:
		app.logger.info("{} is deleting fight {}".format(current_user.character_name, fight.title))

		#Remove reddit post
		app.logger.info("Removing reddit post with link {}.".format(fight.redditLink))
		reddit.submission(url=fight.redditLink).delete()

		#Removing database entry
		app.logger.info("{} removed fight ({}) out of the database with timestamp {}".format(current_user.character_name,fight.title, fight.timestamp))
		db.session.delete(fight)
		db.session.commit()

		flash("Removed {} and it's reddit thread".format(fight.title),'success')
	else:
		app.logger.error("{} tried to remove a fight {}".format(current_user.character_name,fight.title))
		flash("Cannot delete the fight",'error')

	return redirect(url_for('index'))

@app.route('/remove_request/<int:id>')
@login_required
def remove_request(id):
	roles = get_current_roles()
	request = SRPRequest.query.filter(SRPRequest.id == id).first()
	fight = FleetFight.query.filter(FleetFight.id == request.fightId).first()
	if request is None or fight is None:
		flash("Request with id {} does not exist!".format(str(id)),'error')
		return redirect(url_for('index'))

	#Only be able to remove the request if you're the creator of the fight, the creator of the request, admin or director
	if current_user.character_id == request.characterId or current_user.character_name == fight.mentor or "Director" in roles or "Admin" in roles:
		db.session.delete(request)
		db.session.commit()
		flash("Succesfully removed request",'success')
		app.logger.info("{} removed SRP request: {}".format(current_user.character_name, request))
	else:
		flash("Can't do that booboo",'error')

	return redirect(url_for('index'))

def sync_corp_members():
	#Get access token
	token = ESICode.query.first()
	if token is None:
		app.logger.error("ESI authorization was not provided!")
		#flash("ESI Authorization was not provided! Contact an admin to fix this problem!","error")
		return False

	app.logger.info("Making ESI request to https://esi.tech.ccp.is/latest/corporations/{}/members/?datasource=tranquility&token={}".format(str(config['CORP_ID']),token.access_token))
	allianceRequest = requests.get("https://esi.tech.ccp.is/latest/corporations/{}/members/?datasource=tranquility&token={}".format(str(config['CORP_ID']),token.access_token), headers={
		'User-Agent': 'Maintainer: '+ config['MAINTAINER']
		})

	#If token was invalid, use refresh token
	if 'sso_status' in allianceRequest.json() and allianceRequest.json()['sso_status'] == 400:
		app.logger.info("Corp access token expired, requesting a new one")
		auth = prestonCorp.use_refresh_token(token.refresh_token)
		token.access_token = auth.access_token
		app.logger.info("New access token provided, updating database")
		db.session.commit()
		#my_info()
	elif 'sso_status' not in allianceRequest.json():
		#Query all characters in the database
		databaseList = [row[0] for row in db.session.query(Character.character_id).all()]
		memberList = [row['character_id'] for row in allianceRequest.json()]

		#Loop over all members in corp
		for member in memberList:
			if member not in databaseList:
				#Make ESI request
				app.logger.info("Making ESI request to https://esi.tech.ccp.is/latest/characters/{}/?datasource=tranquility".format(str(member)))
				memberRequest = requests.get("https://esi.tech.ccp.is/latest/characters/{}/?datasource=tranquility".format(str(member)), headers={
					'User-Agent': 'Maintainer: '+ config['MAINTAINER']
					})
				#If there is an error, continue to next person
				if 'error' in memberRequest.json():
					app.logger.error("Character with ID {} does not exist! Moving on ...".format(str(member)))
					continue

				#Add character to database
				character = Character(memberRequest.json()['name'],member,True)
				db.session.add(character)
				db.session.commit()
				app.logger.info("Character {} joined corp, and was added to the database".format(memberRequest.json()['name']))

		#Loop over all members in database
		for dbMember in databaseList:
			character = Character.query.filter(Character.character_id == dbMember).first()
			if character.in_corp and dbMember not in memberList:
				character.in_corp = False
				app.logger.info("Character {} left corp, and was marked as such in the database".format(character.character_name))

		db.session.commit()
		return True

def sync_transactions():
	#Get access token
	token = ESICode.query.first()
	if token is None:
		app.logger.error("ESI authorization was not provided!")
		return False

	#Get last token
	lastTransaction = Transaction.query.order_by(Transaction.date.asc()).first()
	lastId = None
	lastIdString = "" 
	if lastTransaction:
		lastId = lastTransaction.ref_id
		lastIdString = "&from_id={}".format(str(lastTransaction.ref_id)) 

	app.logger.info("Making ESI request to https://esi.tech.ccp.is/latest/corporations/{}/wallets/{}/journal/?datasource=tranquility{}&token={}".format(
		str(config['CORP_ID']),str(config['CORP_WALLET_DIVISION']),lastIdString,token.access_token))
	transactionRequest = requests.get("https://esi.tech.ccp.is/latest/corporations/{}/wallets/{}/journal/?datasource=tranquility{}&token={}".format(
		str(config['CORP_ID']),str(config['CORP_WALLET_DIVISION']),lastIdString,token.access_token), headers={
		'User-Agent': 'Maintainer: '+ config['MAINTAINER']
		})

	#If token was invalid, use refresh token
	if 'sso_status' in transactionRequest.json() and transactionRequest.json()['sso_status'] == 400:
		app.logger.info("Corp access token expired, requesting a new one")
		auth = prestonCorp.use_refresh_token(token.refresh_token)
		token.access_token = auth.access_token
		app.logger.info("New access token provided, updating database")
		db.session.commit()
		my_info()
	elif 'sso_status' not in transactionRequest.json():
		#Get JSON
		jsonTransaction = transactionRequest.json()
		for jsonRow in jsonTransaction:
			#Check if it was the requested id
			if jsonRow['ref_id'] == lastId:
				continue

			#Convert date to datetime
			dateObject = datetime.strptime(jsonRow['date'], '%Y-%m-%dT%H:%M:%SZ')

			#Check first party data
			fp_id = None
			fp_type = None
			fp_name = None
			if 'first_party_id' in jsonRow and 'first_party_type' in jsonRow:
				fp_id = jsonRow['first_party_id']
				fp_type = jsonRow['first_party_type']
				#Name search
				if fp_type == "character":
					characterRequest = requests.get("https://esi.tech.ccp.is/latest/characters/{}/?datasource=tranquility".format(str(fp_id)), headers={
							'User-Agent': 'Maintainer: '+ config['MAINTAINER']
							})
					if 'error' in characterRequest.json():
						fp_name = "Unknown"
					else:
						fp_name = characterRequest.json()['name'] 
				elif fp_type == "corporation":
					corpRequest = requests.get("https://esi.tech.ccp.is/latest/corporations/{}/?datasource=tranquility".format(str(fp_id)), headers={
						'User-Agent': 'Maintainer: '+ config['MAINTAINER']
						})
					if 'error' in corpRequest.json():
						fp_name = "Unknown"
					else:
						fp_name = corpRequest.json()['corporation_name']  
				else:
					fp_name = "Unknown Type"

			#Check second party data
			sp_id = None
			sp_type = None
			sp_name = None
			if 'second_party_id' in jsonRow and 'second_party_type' in jsonRow:
				sp_id = jsonRow['second_party_id']
				sp_type = jsonRow['second_party_type']
				#Name search
				if sp_type == "character":
					characterRequest = requests.get("https://esi.tech.ccp.is/latest/characters/{}/?datasource=tranquility".format(str(sp_id)), headers={
							'User-Agent': 'Maintainer: '+ config['MAINTAINER']
							})
					if 'error' in characterRequest.json():
						sp_name = "Unknown"
					else:
						sp_name = characterRequest.json()['name'] 
				elif sp_type == "corporation":
					corpRequest = requests.get("https://esi.tech.ccp.is/latest/corporations/{}/?datasource=tranquility".format(str(sp_id)), headers={
						'User-Agent': 'Maintainer: '+ config['MAINTAINER']
						})
					if 'error' in corpRequest.json():
						sp_name = "Unknown"
					else:
						sp_name = corpRequest.json()['corporation_name']  
				else:
					sp_name = "Unknown Type"

			#Check reason data
			reason = None
			if 'reason'  in jsonRow:
				reason = jsonRow['reason']

			dbTrans = Transaction(dateObject, jsonRow['ref_id'],jsonRow['ref_type'],fp_id,fp_type,fp_name,sp_id,sp_type,sp_name,jsonRow['amount'],jsonRow['balance'], reason)
			db.session.add(dbTrans)
			db.session.commit()

		db.session.commit()
		return True

def corp_update_task():
	app.logger.info("Starting scheduled sync...")
	sync_transactions()
	sync_corp_members()
	app.logger.info("Scheduled sync completed.")

scheduler.add_job(
    func=corp_update_task,
    trigger=IntervalTrigger(seconds=config['CORP_UPDATE_TIME']),
    id='syncing_job',
    name='Sync the members',
    replace_existing=True)
# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

#Run app
if __name__ == '__main__':
	app.run()