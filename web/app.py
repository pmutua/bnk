from flask import Flask, jsonify, request
from flask_restful import APi, Resource 
from pymongo import MongoClient 
import bcrypt 
import requests
import subprocess 
import json

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.ImageRecognition
users = db["Users"]

def UserExists(username):
    if users.find({"Username": username}).count() == 0:
        return False
    else:
        return True

class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        if UserExists(username):
            retJson = {
                "status": 301,
                "msg": "Invalid Username"   
            }
            return jsonify(retJson)

        hashed_pw = bcrypt.hashpwd(password.encode("utf8"),bcrypt.gensalt())

        users.insert({
            "Username": username,
            "Password": hashed_pw,
            "Own":0,
            "Debt": 0
        })

        retJson = {
            "status": 200,
            "msg": "You successfully signed up for this API"
        }
        return jsonify(retJson)

def verifyPw(username,password):
    if not UserExists(username):
        return False
    
    hashed_pw = users.find({
        "Username":username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pwd) == hashed_pw:
        return True

    else:
        return False

def casWithUser(username):
    cash = users.find({
        "Username":username
    })[0]["Own"]
    return cash

def debtWithUser(username):
    debt = users.find({
        "Username":username
    })[0]["Debt"]
    return debt

def generateReturnDictionary(status,msg):
    retJson = {
        "status": status,
        "msg": msg
    }
    return retJson


def verifyCredentials(username, password):
    if not UserExists(username):
        return generateReturnDictionary(301,"Invalid Username"), True

    correct_pw = verifyPw(username,password)

    if not correct_pw:
        return generateReturnDictionary(302, "Incorrect Password"), True

    return None, False


def updateAccount(username,balance):
    users.update({
        "Username": username
    },{
        "$set":{
            "Own": balance
        }
    })

def updateDebt(username,balance):
    users.update({
        "Username": username
    },{
        "$set":{
            "Debt": balance
        }
    })