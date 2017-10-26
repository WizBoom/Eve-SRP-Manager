# Eve-SRP-Manager
An application to make handling SRP management a lot less convoluted.

## Installation
Download, install all of the Python prerequisites, and copy / edit the config example files:

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
If you do not have the correct database set up yet:

```bash
$ python create_database.py
```
