#!/usr/bin/env python
from app import db
from models import *

#Drop all
db.drop_all()

#Create the database
db.create_all()

#Make admin
admin = Character('Alex Kommorov',92399833,True)
db.session.add(admin)

#Roles
adminRole = Role('Admin')
directorRole = Role('Director')
mentorRole = Role('Mentor')
db.session.add(adminRole)
db.session.add(directorRole)
db.session.add(mentorRole)

#Give admin role
admin.roles.append(adminRole)

#Commit
db.session.commit()
