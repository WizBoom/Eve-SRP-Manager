# Eve-SRP-Manager
An application to handle SRP management.

## Installation
Download, install the Python prerequisites, and copy / edit the config example files:

```bash
$ git clone https://github.com/WizBoom/Eve-SRP-Manager.git
$ cd Eve-SRP-Manager
$ virtualenv -p python3.6 env
$ . env/bin/activate
$ pip install -r requirements.txt
$ cp config.json.example config.json
$ cp praw.ini.example praw.ini
```

Edit config.json and praw.ini file.

## Database.
If you do not have the correct database yet:

```bash
$ python create_database.py
```