import os
import datetime

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
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


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get all transactions by user
    transactions = db.execute("SELECT * FROM transactions WHERE user_id=:user_id", user_id=session.get("user_id"))

    # Initialise dictionary to store all owned symbols and quantities
    portfolio = {}
    # Get 2d array to pass into template
    table=[[], [], [], [], []]
    # Get variable to store total holdings
    total=0

    # For every transaction
    for transaction in transactions:

        # Check if the symbol has an entry in portfolio, make one if not
        if transaction["symbol"] not in portfolio:
            portfolio[transaction["symbol"]] = 0

        # Update total
        # Buy
        if transaction["type"] == 'buy':
            portfolio[transaction["symbol"]] += transaction["quantity"]
        # Sell
        else:
            portfolio[transaction["symbol"]] -= transaction["quantity"]

    # Transfer data from portfolio dict into separate lists to pass into template
    for symbol, shares in portfolio.items():
        # Don't add if user has no shares
        if shares != 0:
            # Symbol
            table[0].append(symbol)
            # Name
            table[1].append(lookup(symbol)["name"])
            # Shares
            table[2].append(shares)
            # Price
            table[3].append(usd(lookup(symbol)["price"]))
            # Totals
            total += (int(shares) * lookup(symbol)["price"])
            table[4].append(usd(int(shares) * lookup(symbol)["price"]))

    # Add cash row to bottom of table and add to total
    table[0].append("CASH")
    cash = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session.get("user_id"))[0]["cash"]
    table[4].append(usd(cash))
    total += cash

    # Convert total to usd
    total=usd(total)

    # Load index page
    return render_template("index.html", table=table, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # Check user has inputted symbol
        if not request.form.get("symbol"):
            return apology("must enter symbol", 403)

        # Check user has inputted valid quantity
        if not request.form.get("quantity").isnumeric():
            return apology("invalid quantity", 403)

        # Get stock details
        stock=lookup(request.form.get("symbol"))

        # Check symbol is valid
        if stock == None:
            return apology("invalid symbol", 403)

        # Get price of stock and cost of transaction
        price=stock["price"]
        cost=price*int(request.form.get("quantity"))

        # Get current cash user has in account
        cash = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session.get("user_id"))[0]["cash"]

        # Check if user has enough cash to buy the stock
        if cost > cash:
            return apology("Insufficient cash to complete transaction. Transaction cancelled.", 403)
        # Buy stocks
        else:
            # Remove cash from user's account
            db.execute("UPDATE users SET cash=:newamount WHERE id=:user_id", newamount=(cash-cost), user_id=session.get("user_id"))

            # Add transaction to database
            db.execute("INSERT INTO transactions (user_id, type, quantity, symbol, price, datetime) VALUES (:user_id, 'buy', :quantity, :symbol, :price, :datetime)",
            user_id=session.get("user_id"), quantity=request.form.get("quantity"), symbol=stock["symbol"], price=price, datetime=datetime.datetime.now())

            # Go back to index page
            return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Get all transactions by user
    transactions=db.execute("SELECT * FROM transactions WHERE user_id=:user_id", user_id=session.get("user_id"))

    # Convert prices to usd and make types uppercase
    for transaction in transactions:
        transaction["price"] = usd(transaction["price"])
        transaction["type"] = transaction["type"].upper()

    # Return history
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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
    if request.method == "POST":

        # Lookup function
        stock=lookup(request.form.get("symbol"))

        # Check if symbol is valid
        if stock == None:
            return apology("invalid symbol", 403)

        # Else render html with embedded variables from the lookup
        else:
            return render_template("quoted.html", symbol=stock["symbol"], name=stock["name"], price=usd(stock["price"]))

    else:
        return render_template("quote.html")


@app.route("/findsymbol", methods=["POST"])
@login_required
def findsymbol():
    """Get symbol of company"""

    # Get name of company submitted
    name=request.form.get("name")

    # Search symbols.db for any company names like the name submitted
    matches=db.execute("SELECT * FROM symbols WHERE name LIKE :name", name="%" + name + "%")

    return render_template("symbol.html", matches=matches)

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensure Username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure Passwords match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 403)

        # Check if username already exists in database
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # If username doesn't exist, add to database
        if len(rows) != 1:
            username = request.form.get("username")
            password = request.form.get("password")
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)", username=username, password=generate_password_hash(password))
            return redirect("/")

        # Else return apology
        else:
            return apology("username already exists", 403)

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        # Check user has inputted symbol
        if not request.form.get("symbol"):
            return apology("must enter symbol", 403)

        # Check user has inputted valid quantity
        if not request.form.get("quantity").isnumeric():
            return apology("invalid quantity", 403)

        # Get stock details
        stock=lookup(request.form.get("symbol"))

        # Check symbol is valid
        if stock == None:
            return apology("invalid symbol", 403)

        # Get all transactions by user for selected symbol
        transactions = db.execute("SELECT * FROM transactions WHERE user_id=:user_id AND symbol=:symbol", user_id=session.get("user_id"), symbol=(request.form.get("symbol")).upper())

        # Keep count of shares
        ownedshares=0

        # Check if user has enough shares to sell
        for transaction in transactions:
            #Buy
            if transaction["type"] == "buy":
                ownedshares+=transaction["quantity"]
            # Sell
            else:
                ownedshares-=transaction["quantity"]

        # Check if user has enough shares to sell
        if int(ownedshares) < int(request.form.get("quantity")):
            return apology("Not enough shares to sell.", 403)
        else:

            # Add transaction to database
            db.execute("INSERT INTO transactions (user_id, type, quantity, symbol, price, datetime) VALUES (:user_id, 'sell', :quantity, :symbol, :price, :datetime)",
            user_id=session.get("user_id"), quantity=int(request.form.get("quantity")), symbol=stock["symbol"], price=stock["price"], datetime=datetime.datetime.now())

            # Get current cash user has in account
            cash = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session.get("user_id"))[0]["cash"]

            # Add cash to user's account
            db.execute("UPDATE users SET cash=:newamount WHERE id=:user_id", newamount=(cash + (stock["price"] * int(request.form.get("quantity")))), user_id=session.get("user_id"))

        # Return to index page
        return redirect("/")

    else:
        # Load owned shares first
        # Get all transactions by user
        transactions = db.execute("SELECT * FROM transactions WHERE user_id=:user_id", user_id=session.get("user_id"))

        # Initialise dictionary to store all owned symbols and quantities
        portfolio = {}

        # For every transaction
        for transaction in transactions:

            # Check if the symbol has an entry in portfolio, make one if not
            if transaction["symbol"] not in portfolio:
                portfolio[transaction["symbol"]] = 0

            # Update total
            # Buy
            if transaction["type"] == 'buy':
                portfolio[transaction["symbol"]] += transaction["quantity"]
            # Sell
            else:
                portfolio[transaction["symbol"]] -= transaction["quantity"]

        # Return sell page, inputting portfolio for select box
        return render_template("sell.html", portfolio=portfolio)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
