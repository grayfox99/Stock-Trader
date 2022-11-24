import os
import sys

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():

    users_id = session["user_id"]

    # generate select statements to plug into HTML page for shares and share quanities data for logged in user
    share_quantity_selection = db.execute("SELECT stock, owned FROM user_log WHERE user_id = ? ", users_id)
    cash_selection = db.execute("SELECT cash FROM users WHERE id = ?", users_id)
    cash = cash_selection[0]["cash"]

    # create variable to use in for loop for number of items brought back in the dict above
    dictItems = len(share_quantity_selection)

    # Initialize list variables with size of items in dict
    shares = [None] * dictItems
    quantities = [None] * dictItems
    shareValue = [None] * dictItems
    totalValue = [None] * dictItems

    # for loop to assign value subsequent lists that will be plugged in HTML page to display logged in user's portfolio
    for i in range(0, dictItems):

        shares[i] = share_quantity_selection[i]["stock"]
        quantities[i] = share_quantity_selection[i]["owned"]
        shareValue[i] = float("{:.2f}".format(lookup(shares[i]).get("price")))
        totalValue[i] = shareValue[i] * quantities[i]

    grandSum = sum(totalValue) + cash

    # render page again with flash message in case only cash deposit button is used
    return render_template("index.html", type=type, items=zip(shares, quantities, shareValue, totalValue), cash=cash, grandSum=grandSum)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():

    if request.method == "GET":
        return render_template("buy.html")

    else:

        users_id = session["user_id"]
        # if field is entered empty
        if not request.form.get("symbol"):

            if not request.form.get("cash"):

                return apology("Please enter a Ticker or Deposit amount", 400)

            elif not int(request.form.get("cash")) > 0:

                return apology("Please enter a number greater than 0", 400)

            elif int(request.form.get("cash")) > 0:

                deposit = request.form.get("cash")
                db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", deposit, users_id)
                flash("Deposit succesful", "success")
                return render_template("buy.html")

            else:

                return apology("Please enter a Ticker", 400)

        else:

            # store return value of lookup request
            quoteValues = lookup(request.form.get("symbol"))
            share = request.form.get("shares")
            sharecheck = share.isnumeric()

            # if null is returned for ticker lookup
            if not quoteValues:
                return apology("Stock ticker does not exist", 400)

            # error checking for Quantity field
            elif not request.form.get("shares"):
                return apology("You MUST enter a number of 1 or more")

            elif sharecheck == False:
                return apology("You MUST enter a number")

            shareQuantity = float(request.form.get("shares"))
            fractionalCheck = (shareQuantity).is_integer()

            if not shareQuantity > 0:
                return apology("You MUST enter a number of 1 or more")

            elif fractionalCheck == False:
                return apology("You MUST enter a whole number")

            else:

                row = db.execute("SELECT username FROM users WHERE id =?", users_id)
                username = row[0]["username"]
                shareQuantity = "{:.2f}".format(shareQuantity)
                price = quoteValues["price"]
                stockPrice ="{:.2f}".format(price)
                ticker = quoteValues["symbol"]
                transact = 'BUY'

                # store total cash available for logged in user
                cash_query = db.execute("SELECT cash FROM users WHERE id = ?", users_id)
                cash_available = cash_query[0]["cash"]

                # store total cost price of shares to buy
                shares_price = float(shareQuantity) * float(stockPrice)

                if shares_price > cash_available:
                    return apology("Insufficient cash avaialable for transaction", 400)

                else:
                    db.execute("INSERT INTO transactions (username, stock, stock_price, transact_type, quantity) VALUES (?,?,?,?,?)",
                               username, ticker, stockPrice, transact, shareQuantity)

                    row1 = db.execute("SELECT id FROM users where id =?", users_id)
                    SQLUserId = row1[0]["id"]

                    # query to find if log table already has stock listed for logged in user or not
                    rows = db.execute("SELECT *FROM user_log where user_id=? and stock =?", users_id, ticker)

                    # if it has then we will update the record to reflect the new amount of shares of the particular ticker for the logged in user
                    if len(rows) == 1:

                        db.execute("UPDATE user_log SET owned = owned + ? WHERE user_id=? and stock =?",
                                   shareQuantity, SQLUserId, ticker)

                    # if not then we will create a new record to reflect the shares just bought for the logged in user
                    else:

                        db.execute("INSERT into user_log (stock, user_id, owned) VALUES (?,?,?)", ticker, SQLUserId, shareQuantity)

                    # finally, subtract the amount of cash the user spent on the stock purchase from their cash reserve in the users table
                    db.execute("UPDATE users SET cash = cash - ? WHERE id =?", shares_price, users_id)

                    if not request.form.get("cash"):

                        flash("Stock purchase succesful", "success")

                    elif not int(request.form.get("cash")) > 0:

                        return apology("Please enter a number greater than 0", 400)

                    elif int(request.form.get("cash")) > 0:

                        deposit = request.form.get("cash")
                        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", deposit, users_id)
                        flash("Deposit and ", "success")
                        flash("Stock purchase succesful", "success")

                return redirect("/")


@app.route("/history")
@login_required
def history():

    usernameSelect = db.execute("SELECT username from users where id =?", session["user_id"])
    username = usernameSelect[0].get("username")

    # generate select statements to plug into HTML page for shares and share quanities data for logged in user
    historySelect = db.execute(
        "SELECT TIMESTAMP, stock, stock_price, transact_type, quantity from transactions WHERE username = ? ", username)

    # create variable to use in for loop for number of items brought back in the dict above
    dictItems = len(historySelect)

    # Initialize list variables with size of items in dict
    timestamp = [None] * dictItems
    stock = [None] * dictItems
    stock_price = [None] * dictItems
    transact_type = [None] * dictItems
    quantity = [None] * dictItems

    # for loop to assign value subsequent lists that will be plugged in HTML page to display logged in user's history
    for i in range(0, dictItems):

        timestamp[i] = historySelect[i]["TIMESTAMP"]
        stock[i] = historySelect[i]["stock"]
        stock_price[i] = historySelect[i]["stock_price"]
        transact_type[i] = historySelect[i]["transact_type"]
        quantity[i] = historySelect[i]["quantity"]

    # zip used to send multiple lists to HTML page for use with jinja for loop
    return render_template("history.html", type=type, items=zip(timestamp, stock, stock_price, transact_type, quantity))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id, but maintain flashed message if present
    if session.get("_flashes"):
        flashes = session.get("_flashes")
        session.clear()
        session["_flashes"] = flashes
    else:
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
    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("quote.html")

    else:

        quoteValues = lookup(request.form.get("symbol"))

        if not quoteValues:
            return apology("Stock ticker does not exist", 400)

        else:

            price = "{0:.2f}".format(quoteValues["price"])
            return render_template("quoted.html", tickerInfo=quoteValues, price=price)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide a username", 400)

        # Ensure username is not already taken
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(rows) >= 1:
            return apology("username is already taken", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide a password", 400)

        # Ensure password was submitted
        elif not request.form.get("confirmation"):
            return apology("must re-enter your password", 400)

        # Ensure passwoords match
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("your passwords do not match", 400)

        passHash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

        db.execute("INSERT into users (username, hash) VALUES (?,?)", request.form.get("username"), passHash)

        flash("Registration successful", "success")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():

    if request.method == "GET":

        # selection of all stocks the users owns
        tickerSelection = db.execute("SELECT stock FROM user_log WHERE user_id = ?", session["user_id"])

        if not tickerSelection:

            return apology("You have not purchased any shares", 400)

        else:

            tLen = len(tickerSelection)
            tickers = [None] * tLen

            for i in range(0, tLen):

                tickers[i] = tickerSelection[i]["stock"]

            return render_template("sell.html", tickers=tickers)

    else:

        # error checking for Quantity field

        shares = request.form.get("shares")
        sharecheck = shares.isnumeric()

        if not request.form.get("shares") or sharecheck == False:
            return apology("You MUST enter a number")

        elif not int(request.form.get("shares")) > 0:
            return apology("You MUST enter a number of 1 or more")

        shareQuantity = float(request.form.get("shares"))
        fractionalCheck = (shareQuantity).is_integer()

        if fractionalCheck == False:

            return apology("You MUST enter a number")

        else:

            users_id = session["user_id"]
            row = db.execute("SELECT username FROM users WHERE id =?", users_id)
            username = row[0]["username"]
            shareQuantity = int(request.form.get("shares"))

            ticker = str(request.form.get("symbol"))

            quoteInfo = lookup(ticker)
            stockPrice = quoteInfo["price"]
            transact = 'SELL'

            # store stock quantity available for logged in user
            stock_query = db.execute("SELECT owned FROM user_log WHERE user_id =? AND stock =?", users_id, ticker)
            stock_available = stock_query[0]["owned"]

            if shareQuantity > stock_available:
                return apology("Insufficient quantity of stocks avaialable for transaction", 400)

            else:
                db.execute("INSERT INTO transactions (username, stock, stock_price, transact_type, quantity) VALUES (?,?,?,?,?)",
                           username, ticker, stockPrice, transact, shareQuantity)

                row1 = db.execute("SELECT id FROM users where id =?", users_id)
                SQLUserId = row1[0]["id"]

                # First we will check if the user is selling all his shares of the stock selected and then delete the record if true
                if shareQuantity == stock_available:

                    db.execute("DELETE FROM user_log WHERE user_id=? and stock =?", SQLUserId, ticker)

                # if not then we will just reduce the stock quantity from their portfolio
                else:

                    db.execute("UPDATE user_log SET owned = owned - ? WHERE user_id=? and stock =?", shareQuantity, SQLUserId, ticker)

        flash("Stock sell succesful", "success")
        return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
