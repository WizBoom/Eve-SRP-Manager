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

	def __init__(self, character_name, character_id):
		self.character_name = character_name
		self.character_id = character_id

	def __repr__(self):
		return 'Character {} with id {}'.format(self.character_name, self.character_id)

	@property
	def is_authenticated(self):
		return True

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
	characterName = db.Column(db.String)
	killId = db.Column(db.String)
	price = db.Column(db.Float(precision=2))
	payout = db.Column(db.Float(precision=2))
	percentageOptions = db.Column(db.String)
	redditLink = db.Column(db.String)
	approved = db.Column(db.Boolean)
	rejectionReason = db.Column(db.String)
	paid = db.Column(db.Boolean)
	fightId = db.Column(db.Integer, db.ForeignKey('FleetFights.id'))

	def __init__(self,characterName,killId,price,payout,percentageOptions,redditLink,approved=None,rejectionReason="",paid=False):
		self.timestamp = datetime.utcnow()
		self.characterName = characterName
		self.killId = killId
		self.price = price
		self.payout = payout
		self.percentageOptions = percentageOptions
		self.redditLink = redditLink
		self.approved = approved
		self.rejectionReason = rejectionReason
		self.paid = paid

	def __repr__(self):
		return "SRP application by {} with killId {} ({} ISK)".format(self.characterName,self.killId,str(self.price))
