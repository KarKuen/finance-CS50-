import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


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
    purchases = db.execute("SELECT * FROM purchases WHERE id = ?", session["user_id"])

    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

    try:
        total = cash + db.execute("SELECT SUM(total) FROM purchases")[0]["SUM(total)"]
    except TypeError:
        total = cash

    dicts = db.execute("SELECT symbol FROM purchases WHERE id = ?", session["user_id"])
    symbols = []
    names = {}

    for dict in dicts:
        symbols.extend(list(dict.values()))

    for symbol in symbols:
        names[symbol] = lookup(symbol)["name"]

    return render_template("index.html", purchases=purchases, names=names, cash=cash, total=total)
    # (QUESTION) name is wrong, it is only recording first name


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("missing symbol")

        if lookup(request.form.get("symbol")) == None:
            return apology("invalid symbol")

        try:
            shares = int(request.form.get("shares"))
            if not isinstance(shares, int) or int(shares) < 0:
                return apology("invalid integer")

        except ValueError:
            return apology("invalid integer")
        # (QUESTION) prevent negatigve integers or provide apology pop up

        quote = lookup(request.form.get("symbol"))
        price = quote["price"]
        symbol = quote["symbol"]
        shares = request.form.get("shares")
        cash = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        total = price * float(shares)
        transacted = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # (QUESTION) how to know which id to look for?

        if float(cash) < total:
            return apology("insufficient cash")

        try:
            symbols = db.execute("SELECT symbol FROM purchases WHERE id = ?", session["user_id"])[0]
            if symbol in list(symbols.values()):
                # (QUESTION) how to turn this list of dictionaries to a list?
                currentshares = db.execute("SELECT shares FROM purchases WHERE id = ? AND symbol = ?",
                                           session["user_id"], symbol)[0]["shares"]
                totalshares = int(currentshares) + int(shares)
                db.execute("UPDATE purchases SET shares = ?, total = ?", totalshares, price * float(totalshares))
                remainder = cash - total
                db.execute("UPDATE users SET cash = ? WHERE id = ?", remainder, session["user_id"])

                db.execute("INSERT INTO transactions (id, symbol, shares, transacted) VALUES(?, ?, ?, ?)",
                           session["user_id"], symbol, shares, transacted)

                return redirect("/")

            db.execute("INSERT INTO purchases (id, symbol, price, shares, total) VALUES(?, ?, ?, ?, ?)",
                       session["user_id"], symbol, price, shares, total)
            remainder = cash - total
            db.execute("UPDATE users SET cash = ? WHERE id = ?", remainder, session["user_id"])

            db.execute("INSERT INTO transactions (id, symbol, shares, transacted) VALUES(?, ?, ?, ?)",
                       session["user_id"], symbol, shares, transacted)

            return redirect("/")

        except IndexError:
            db.execute("INSERT INTO purchases (id, symbol, price, shares, total) VALUES(?, ?, ?, ?, ?)",
                       session["user_id"], symbol, price, shares, total)
            remainder = cash - total
            db.execute("UPDATE users SET cash = ? WHERE id = ?", remainder, session["user_id"])

            db.execute("INSERT INTO transactions (id, symbol, shares, transacted) VALUES(?, ?, ?, ?)",
                       session["user_id"], symbol, shares, transacted)

            return redirect("/")
        # (QUESTION) whats the difference between render_template and redirect

    return render_template("buy.html")
    # (QUESTION) will this be the homepage


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE id = ?", session["user_id"])

    try:
        dicts = db.execute("SELECT symbol FROM transactions WHERE id = ?", session["user_id"])
        symbols = []
        price = {}
        # (QUESTION) should use a dictionary instead of a list
        for dict in dicts:
            symbols.extend(list(dict.values()))

        for symbol in symbols:
            price[symbol] = (lookup(symbol)["price"])

        return render_template("history.html", transactions=transactions, price=price)
    except IndexError:
        return render_template("history.html")


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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

    if lookup(request.form.get("symbol")) == None:
        return apology("invalid symbol")

    quote = lookup(request.form.get("symbol"))
    return render_template("quoted.html", name=quote["name"], symbol=quote["symbol"], price=quote["price"])


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        # if username is empty
        if not request.form.get("username"):
            return apology("missing username")

        # if password is blank
        if not request.form.get("password"):
            return apology("missing password")

        # if confirmation is blank
        if not request.form.get("confirmation"):
            return apology("missing confirmation")

        # if password and confirmation doesn't match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation don't match")
        # (QUESTION) do i have to use strcompare?

        # if username already exists
        if len(db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))) != 0:
            return apology("username already exists")
        # (QUESTION) what type of value does this return?

        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", request.form.get("username"),
                   generate_password_hash(request.form.get("password")))
        # (QUESTION) do i need to remember sessions?
        """Register user"""
        return redirect("/")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("missing stock")

        dicts = db.execute("SELECT symbol FROM purchases WHERE id = ?", session["user_id"])
        symbols = []
        for dict in dicts:
            symbols.extend(list(dict.values()))

        if lookup(request.form.get("symbol"))["symbol"] not in symbols:
            return apology("invalid stock")
        # (QUESTION) Only choosing the first symbol. List of dictionaries where each dictionary has 1 key:value pair

        if int(request.form.get("shares")) < 0:
            return apology("shares must be positive integer")

        if int(request.form.get("shares")) > int(db.execute("SELECT shares FROM purchases WHERE symbol = ?",
                                                            lookup(request.form.get("symbol"))["symbol"])[0]["shares"]):
            return apology("invalid shares")
        # (QUESTION) there could be multiple entries for the same share i.e. buying the same symbol multiple times

        symbol = lookup(request.form.get("symbol"))["symbol"]
        currentshares = db.execute("SELECT shares FROM purchases WHERE id = ? AND symbol = ?",
                                   session["user_id"], symbol)[0]["shares"]
        shares = request.form.get("shares")
        finalshares = int(currentshares) - int(shares)
        price = lookup(symbol)["price"]
        total = finalshares * price
        finaltotal = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"] + int(shares) * float(price)
        transacted = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if finalshares == 0:
            db.execute("DELETE FROM purchases WHERE id = ? AND symbol = ?", session["user_id"], symbol)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", finaltotal, session["user_id"])

            db.execute("INSERT INTO transactions (id, symbol, shares, transacted) VALUES(?, ?, ?, ?)",
                       session["user_id"], symbol, "-" + shares, transacted)

            return redirect("/")

        db.execute("UPDATE purchases SET shares = ?, total = ? WHERE id = ? AND symbol = ?",
                   finalshares, total, session["user_id"], symbol)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", finaltotal, session["user_id"])

        db.execute("INSERT INTO transactions (id, symbol, shares, transacted) VALUES(?, ?, ?, ?)",
                   session["user_id"], symbol, "-" + shares, transacted)

        return redirect("/")

    return render_template("sell.html")


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":

        if not request.form.get("New Password"):
            return apology("missing Password")

        # if password is blank
        if not request.form.get("Confirm Password"):
            return apology("missing confirmation password")

        # if password and confirmation doesn't match
        if request.form.get("New Password") != request.form.get("Confirm Password"):
            return apology("password and confirmation don't match")
        # (QUESTION) do i have to use strcompare?

        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(request.form.get("New Password")),
                   session["user_id"])
        """Register user"""
        return redirect("/logout")

    return render_template("account.html")

