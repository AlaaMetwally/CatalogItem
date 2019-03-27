Running Project:-
to run the project go to the terminal
export FLASK_APP=run.py
export FLASK_DEBUG=1
python run.py
from the browser you have to write https://localhost:5000/ and
-->install ssl certificate
  Select Advanced.
  Select the Encryption tab.
  Click View Certificates. The browser displays the Certificate Manager dialog.
  Navigate to where you stored the certificate and click Open.
  Click Import. The Downloading Certificate dialog displays.

About:-
1-This project provides a list of items within certain categories
2-User login and registration
3-there is also third party OAuth
4-authenticated and authorized users have the ability to create, edit, delete items
5-authenticated and authorized users have the ability to create category

Packages Used:-
1-flask Bootstrap for UI
2-Jsonify for JSON endpoints
3-SQLAlchemy used for CRUD operations
4-Flash used for displaying messages
