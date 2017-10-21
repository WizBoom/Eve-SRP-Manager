from app import db
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from time import strftime

roleConn = db.Table('RoleConnections',
	db.Column('character_id', db.Integer, db.ForeignKey('Characters.id')),
	db.Column('role_id', db.Integer, db.ForeignKey('Roles.id'))
	)

class Character(db.Model):
	__tablename__ = 'Characters'
	id = db.Column(db.Integer,primary_key=True)
	character_name = db.Column(db.String)
	character_id = db.Column(db.Integer)
	in_corp = db.Column(db.Boolean)
	srp_requests = db.relationship('SRPRequest', backref='Characters',lazy='dynamic', cascade="all,delete-orphan")

	def __init__(self, character_name, character_id, in_corp):
		self.character_name = character_name
		self.character_id = character_id
		self.in_corp = in_corp

	def __repr__(self):
		return 'Character {} with id {}'.format(self.character_name, self.character_id)

	@property
	def is_authenticated(self):
		return self.in_corp

	@property
	def is_active(self):
		return True

	@property
	def is_anonymous(self):
		return False

	def get_id(self):
		return str(self.id)

class Role(db.Model):
	__tablename__ = 'Roles'
	id = db.Column(db.Integer,primary_key=True)
	role_name = db.Column(db.String)
	characters = db.relationship('Character', secondary=roleConn, backref=db.backref('roles',lazy='dynamic'))

	def __init__(self, role_name):
		self.role_name = role_name

	def __repr__(self):
	 	return self.role_name

class FleetFight(db.Model):
	__tablename__ = 'FleetFights'
	id = db.Column(db.Integer,primary_key=True)
	timestamp = db.Column(db.DateTime)
	date = db.Column(db.DateTime)
	title = db.Column(db.String)
	fc = db.Column(db.String)
	mentor = db.Column(db.String)
	redditLink = db.Column(db.String)
	requests = db.relationship('SRPRequest', backref='FleetFights',lazy='dynamic', cascade="all,delete-orphan")

	def __init__(self,date,title,fc,mentor,redditLink=None):
		self.timestamp = datetime.utcnow()
		self.date = date
		self.title = title
		self.fc = fc
		self.mentor = mentor
		self.redditLink = redditLink

	def __repr__(self):
		return "Fight '{}' ({}), created at {}, FC'd by {}, overseen by {}, with the following reddit post {}".format(
			self.title, self.date.strftime('%Y/%m/%d %H:%M'), self.timestamp.strftime('%Y/%m/%d %H:%M'),self.fc,self.mentor,str(self.redditLink))

class SRPRequest(db.Model):
	__tablename__ = 'SRPRequests'
	id = db.Column(db.Integer,primary_key=True)
	timestamp = db.Column(db.DateTime)
	killId = db.Column(db.String)
	price = db.Column(db.Float(precision=2))
	payout = db.Column(db.Float(precision=2))
	percentageOptions = db.Column(db.String)
	redditLink = db.Column(db.String)
	approved = db.Column(db.Boolean)
	rejectionReason = db.Column(db.String)
	paid = db.Column(db.Boolean)
	characterId = db.Column(db.Integer, db.ForeignKey('Characters.character_id'))
	fightId = db.Column(db.Integer, db.ForeignKey('FleetFights.id'))

	def __init__(self,killId,price,payout,percentageOptions,redditLink,approved=None,rejectionReason="",paid=False):
		self.timestamp = datetime.utcnow()
		self.killId = killId
		self.price = price
		self.payout = payout
		self.percentageOptions = percentageOptions
		self.redditLink = redditLink
		self.approved = approved
		self.rejectionReason = rejectionReason
		self.paid = paid

	def __repr__(self):
		return "SRP application {} with killId {} ({} ISK)".format(self.id,self.killId,str(self.price))

class ESICode(db.Model):
	__tablename__ = 'ESICode'
	id = db.Column(db.Integer,primary_key=True)
	access_token = db.Column(db.String)
	refresh_token = db.Column(db.String)

	def __init__(self,access_token,refresh_token):
		self.access_token = access_token
		self.refresh_token = refresh_token

class Transaction(db.Model):
	__tablename__ = 'Transactions' 
	id = db.Column(db.Integer,primary_key=True)
	date = db.Column(db.DateTime)
	ref_id = db.Column(db.Integer)
	ref_type = db.Column(db.String)
	first_party_id = db.Column(db.Integer)
	first_party_type = db.Column(db.String)
	first_party_name = db.Column(db.String)
	second_party_id = db.Column(db.Integer)
	second_party_type = db.Column(db.String)
	second_party_name = db.Column(db.String)
	amount = db.Column(db.Float(precision=2))
	balance = db.Column(db.Float(precision=2))
	reason = db.Column(db.String)

	def __init__(self, date, ref_id, ref_type, first_party_id, first_party_type, first_party_name, second_party_id, second_party_type, second_party_name, amount, balance, reason):
		self.date = date
		self.ref_id = ref_id
		self.ref_type = ref_type
		self.first_party_id = first_party_id
		self.first_party_type = first_party_type
		self.first_party_name = first_party_name
		self.second_party_id = second_party_id
		self.second_party_type = second_party_type
		self.second_party_name = second_party_name
		self.amount = amount
		self.balance = balance
		self.reason = reason