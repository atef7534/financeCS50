import os
from datetime import datetime


from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    trades = db.execute("SELECT * FROM trades WHERE id = ?", session["user_id"])
    user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    return render_template("index.html", trades=trades, cash=int(user[0]["cash"]))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    cash = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    cash = cash[0]["cash"]

    if request.method == "GET":
        return render_template("buy.html", cash=int(cash))

    symbol = request.form.get("symbol")
    if not symbol:
        return apology("Missing Symbol!")


    shares = request.form.get("shares")
    if not shares:
        return apology("Missing Shares!")

    try:
        shares = int(shares)
        if shares < 0:
            return apology("Positive my friend!")
    except:
        return apology("Number my friend!")

    try:
        symbol_price = lookup(symbol)["price"]
    except:
        return apology("Valid stock my friend!")

    if int(shares) * symbol_price > int(cash):
        return apology("You don't have enough money!")

    trades = db.execute("SELECT * FROM trades WHERE symbol = ?", symbol.upper())
    if not trades:
        db.execute("INSERT INTO trades (id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                   session["user_id"], symbol.upper(), int(shares), symbol_price)
    else:
        db.execute("UPDATE trades SET shares = ? WHERE symbol = ?",
                   int(trades[0]["shares"]) + int(shares), symbol.upper())
    db.execute("UPDATE users SET cash = ? WHERE id = ?", float(
        cash) - (float(shares) * float(symbol_price)), session["user_id"])
    now = datetime.now()
    now = now.strftime('%Y-%m-%d %H:%M:%S')
    db.execute("INSERT INTO transactions (id, symbol, shares, price, transacted) VALUES (?, ?, ?, ?, ?)",
               session["user_id"], symbol, int(shares), symbol_price, now)

    return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE id = ?", session["user_id"])
    if request.method == "GET":
        return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "GET":
        return render_template("quote.html")

    symbol = request.form.get("symbol")
    if not symbol:
        return apology("Missing Symbol")

    stock_quote = lookup(symbol)
    if not stock_quote:
        return apology("Missing Symbol")

    return render_template("quoted.html", symbol=stock_quote)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # if the user enters the registeration page using get method
    if request.method == "GET":
        return render_template("register.html")

    # check mistakes in username [textfield]
    username = request.form.get("username")
    userExist = db.execute("SELECT * FROM users WHERE username = ?", username)
    if not username or len(userExist):
        return apology("Register with another name!")

    # check mistakes in password and cofirmed password
    password = request.form.get("password")
    samepass = request.form.get("confirmation")
    if not password or not samepass or password != samepass:
        return apology("Register with another password or check confirmation password!")

    # insertion : insert user with username, and hash
    db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
               username, generate_password_hash(password))

    # get the user row from the data base
    rows = db.execute("SELECT * FROM users WHERE username = ?", username)

    # log the user in
    session["user_id"] = rows[0]["id"]

    flash("Registered!")
    return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    symbols = db.execute("SELECT * FROM trades")
    if request.method == "GET":
        return render_template("sell.html", symbols=symbols)

    symbol = request.form.get("symbol")
    if not symbol:
        return apology("Missing Symbol")

    shares = request.form.get("shares")
    if not shares:
        return apology("Missing Shares")

    data = db.execute("SELECT * FROM trades WHERE symbol = ? AND id = ?",
                      symbol, session["user_id"])
    if int(data[0]["shares"]) < int(shares):
        return apology("Many Shares!")

    db.execute("UPDATE trades SET shares = ? WHERE symbol = ?",
               int(data[0]["shares"]) - int(shares), symbol)
    db.execute("DELETE FROM trades WHERE shares = 0")

    user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    db.execute("UPDATE users SET cash = ? WHERE id = ?", int(
        user[0]["cash"]) + int(shares) * float(data[0]["price"]), session["user_id"])

    now = datetime.now()
    now = now.strftime('%Y-%m-%d %H:%M:%S')
    db.execute("INSERT INTO transactions (id, symbol, shares, price, transacted) VALUES (?, ?, ?, ?, ?)",
               session["user_id"], symbol, (-1.00 * int(shares)), data[0]["price"], now)

    flash("Sold!")
    return redirect("/")
