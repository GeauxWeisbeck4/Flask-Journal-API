"""
Welcome to the documentation for the Flask Journal API!

## Introduction

The Flask Journal API is an API (Application Programming Interface) for creating a **daily journal** that documents events that happen each day.

## Key Functionality

The Flask Journal API has the following functionality:

1. Work with journal entries:
  * Create a new journal entry
  * Update a journal entry
  * Delete a journal entry
  * View all journal entries
2. <More to come!>

## Key Modules

This project is written using Python 3.10.1.

The project utilizes the following modules:

* **Flask**: micro-framework for web application development which includes the following dependencies:
  * **click**: package for creating command-line interfaces (CLI)
  * **itsdangerous**: cryptographically sign data
  * **Jinja2**: templating engine
  * **MarkupSafe**: escapes characters so text is safe to use in HTML and XML
  * **Werkzeug**: set of utilities for creating a Python application that can talk to a WSGI server
* **APIFairy**: API framework for Flask which includes the following dependencies:
  * **Flask-Marshmallow** - Flask extension for using Marshmallow (object serialization/deserialization library)
  * **Flask-HTTPAuth** - Flask extension for HTTP authentication
  * **apispec** - API specification generator that supports the OpenAPI specification
* **pytest**: framework for testing Python projects
"""
import os

from apifairy import APIFairy
from flask import Flask, json
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth  # NEW!!
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
from werkzeug.exceptions import HTTPException


# -------------
# Configuration
# -------------

# Create the instances of the Flask extensions in the global scope,
# but without any arguments passed in. These instances are not
# attached to the Flask application at this point.
apifairy = APIFairy()
ma = Marshmallow()
database = SQLAlchemy()
basic_auth = HTTPBasicAuth()  # NEW!!
token_auth = HTTPTokenAuth()  # NEW!!

#-----------------------------
# Application Factory Function
#-----------------------------

def create_app():
# Create the Flask application
	app = Flask(__name__)
	
	# Configure the API documentation
	app.config['APIFAIRY_TITLE'] = 'Flask Journal API'
	app.config['APIFAIRY_VERSION'] = '0.1'
	app.config['APIFAIRY_UI'] = 'elements'
	
	# Configure the SQLite database (intended for development only!)
	app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(os.getcwd(), 'instance', 'app.db')}"
	app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
	
	initialize_extensions(app)
	register_blueprints(app)
	register_error_handlers(app)  # NEW!!
	
	return app
	
#-----------------
# Helper Functions
#-----------------

def initialize_extensions(app):
	# Since the application instance is now created, pass it to each Flask
	# extension instance to bind it to the Flask application instance (app)
	apifairy.init_app(app)
	ma.init_app(app)
	database.init_app(app)
	
def register_blueprints(app):
	# Import the blueprints
	from project.journal_api import journal_api_blueprint
	
	# Since the application instance is now created, register each Blueprint
	# with the Flask application instance (app)
	app.register_blueprint(journal_api_blueprint, url_prefix='/journal')
	
def register_error_handlers(app):
	@app.errorhandler(HTTPException)
	def handle_http_exception(e):
		"""Return JSON instead of HTML for HTTP errors."""
		# Start with the correct headers and status code from the error
		response = e.get_response()
		# Replace the body with JSON
		response.data = json.dumps({
			'code': e.code,
			'name': e.name,
			'description': e.description,
		})
		response.content_type = 'application/json'
		return response