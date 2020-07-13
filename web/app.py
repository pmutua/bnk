from flask import Flask, jsonify, request
from flask_restful import Api, Resource 
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


class Add(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        amount = postedData["amount"]


        retJson , error = verifyCredentials(username,password)

        if error:
            return jsonify(retJson)

        if money==0:
            return jsonify(generateReturnDictionary(304,"The money amount entered must be greater than 0"))

        cash = casWithUser(username)
        # deduct transaction fee
        money-=1
        bank_cash = casWithUser("BANK")
        # get transaction fee
        updateAccount("BANK",bank_cash+1)
        updateAccount(username,cash+money)

        return jsonify(generateReturnDictionary(200,"Amount added successfully to Account."))

class Transfer(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        to = postedData["to"]
        money = postedData["amount"]


        returnJson, error = verifyCredentials(username,password)

        if error:
            return jsonify(returnJson)

        cash = casWithUser(username)
        if cash<=0:
            return jsonify(generateReturnDictionary(304,"You are out of money, please add or take a loan"))
        
        if not UserExists(to):
            return jsonify(generateReturnDictionary(301, "Receiver username is invalid"))


        cash_from = casWithUser(username)

        cash_to = casWithUser(to)
        bank_cash = casWithUser("BANK")

        updateAccount("BANK",bank_cash+1)

        updateAccount(to,cash_to+money-1)

        updateAccount(username,cash_from-money)

        return jsonify(generateReturnDictionary(200, "Amount transfered succesfully"))

class Balance(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData['password']

        retJson, error = verifyCredentials(username,password)

        if error:
            return jsonify(retJson)

        # omit fields password and id
        retJson = users.find({
            "Username": username
        },{
            "Password":0,
            "_id":0
        })[0]

        return jsonify(retJson)


class TakeLoan(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData['password']
        money = postedData['amount']


        retJson, error = verifyCredentials(username,password)

        if error:
            return jsonify(retJson)

        cash = casWithUser(username)

        debt = debtWithUser(username)

        updateAccount(username,cash+money)
        updateDebt(username,debt+money)

        return jsonify(generateReturnDictionary(200,"Loan added to your Account"))

      

class PayLoan(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData['password']
        money = postedData['amount']


        retJson, error = verifyCredentials(username,password)

        if error:
            return jsonify(retJson)

        cash = casWithUser(username)

        debt = debtWithUser(username)

        updateAccount(username,cash-money)
        updateDebt(username,debt-money)

        return jsonify(generateReturnDictionary(200,"Loan added to your Account"))
