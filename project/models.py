from project import database

import secrets
from datetime import datetime, timedelta

from werkzeug.security import check_password_hash, generate_password_hash

class Entry(database.Model):
	"""Class that represents a journal entry."""
	__tablename__ = 'entries'
	
	id = database.Column(database.Integer, primary_key=True)
	entry = database.Column(database.String, nullable=False)
	
	def __init__(self, entry: str):
		self.entry = entry
		
	def update(self, entry: str):
		self.entry = entry
		
	def __repr__(self):
		return f'<Entry: {self.entry}>'
		
class User(database.Model):
		__tablename__ = 'users'
		
		id = database.Column(database.Integer, primary_key=True)
		email = database.Column(database.String, unique=True, nullable=False)
		password_hashed = database.Column(database.String(128), nullable=False)
		entries = database.relationship('Entry', backref='user', lazy='dynamic')
		auth_token = database.Column(database.String(64), index=True)
		auth_token_expiration = database.Column(database.DateTime)
		
		def __init__(self, email: str, password_plaintext: str):
			"""Create a new User object."""
			self.email = email
			self.password_hashed = self._generate_password_hash(password_plaintext)
		
		def is_password_correct(self, password_plaintext: str):
			return check_password_hash(self.password_hashed, password_plaintext)
		
		def set_password(self, password_plaintext: str):
			self.password_hashed = self._generate_password_hash(password_plaintext)
		
		@staticmethod
		def _generate_password_hash(password_plaintext):
			return generate_password_hash(password_plaintext)
		
		def generate_auth_token(self):
			self.auth_token = secrets.token_urlsafe()
			self.auth_token_expiration = datetime.utcnow() + timedelta(minutes=60)
			return self.auth_token

