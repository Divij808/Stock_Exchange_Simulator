import os
import sqlite3
import yfinance
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)


def price_is_valid(price):
    try:
        price = float(price)
        return true if price >= 0 else false
    except (ValueError, TypeError):
        return False


# Database Connection Helper
def load_database():
    connection = sqlite3.connect('sim.db')
    connection.row_factory = sqlite3.Row
    return connection


# Prototype 1: Database Initialization Logic
def init_database():
    with load_database() as database:
        database.execute('''CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            symbol TEXT NOT NULL,
            shares INTEGER NOT NULL,
            price REAL NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')

        database.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            cash REAL DEFAULT 10000.00,
            theme TEXT DEFAULT 'light'
        )''')

    print("Database has been made")


@app.context_processor
def inject_user_theme():
    if 'user_id' in session:
        database = load_database()
        user = database.execute('SELECT theme FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        return dict(current_theme=user['theme'] if user else 'light')
    return dict(current_theme='light')


# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        database = load_database()
        password_created = generate_password_hash(request.form['password_created'])
        username_created = request.form['username_created']
        try:
            database.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                             (username_created, password_created))
            database.commit()
            flash("Account created! Please login.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists.")
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        database = load_database()
        user_fetched_information = database.execute('SELECT * FROM users WHERE username = ?',
                                                    (request.form['username_entered'],)).fetchone()
        if user_fetched_information and check_password_hash(user_fetched_information['password'],
                                                            request.form['password_entered']):
            session['user_id'] = user_fetched_information['id']
            session['username_entered'] = user_fetched_information['username']
            return redirect(url_for('portfolio'))
        flash("Invalid credentials.")
    return render_template('login.html')


@app.route('/research', methods=['GET', 'POST'])
def research():
    data, news = None, []
    if request.method == 'POST':
        symbol = request.form.get('symbol').upper()
        ticker = yfinance.Ticker(symbol)
        try:
            info = ticker.info
            data = {
                'symbol': symbol,
                'name': info.get('longName', 'N/A'),
                'price': info.get('currentPrice') or info.get('regularMarketPrice')
            }
            news = ticker.news[:5]
            if not data['price']: flash("Stock not found.")
        except:
            flash("Error fetching data.")
    return render_template('research.html', data=data, news=news)


@app.route('/trade', methods=['GET', 'POST'])
def trade():

    if request.method == 'POST':
        trade_action = request.form.get('trade_action')
        symbol_entered = request.form.get('symbol').upper()
        try:

            if trade_action == 'buy':

                shares_entered = int(request.form.get('shares'))
                price_found = float(yfinance.Ticker(symbol_entered).info.get('currentPrice'))

                total_checkout_price = float(price_found * shares_entered)
                database = load_database()

                user_fetched_data = database.execute('SELECT cash FROM users WHERE id = ?',
                                                     (session['user_id'],)).fetchone()
                account_cash = float(user_fetched_data['cash'])
                flash(f"Info: account_cash={account_cash}, total_checkout_price={total_checkout_price})")

                if account_cash >= total_checkout_price:
                    flash("Proceeding with purchase.")
                    database.execute('INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)',
                                     (session['user_id'], symbol_entered, shares_entered, price_found))
                    database.execute('UPDATE users SET cash = cash - ? WHERE id = ?',
                                     (total_checkout_price, session['user_id']))

                    database.commit()
                    flash(f"Success! Bought {shares_entered} of {symbol_entered}.")

                elif not is_valid_price(price_found):
                    flash(
                        "Invalid stock symbol. If you are 100% sure you symbol is valid! There may be a technical issue on our side. Try after a minute again")
                else:
                    insufficient_funds_error_message = " " + "Insufficient funds." + "You have $" + str(
                        account_cash) + " available, but the total cost is $" + str(
                        total_checkout_price) + "."
                    flash(insufficient_funds_error_message)
            elif trade_action == 'sell':
                shares_entered = int(request.form.get('shares'))
                price_found = yfinance.Ticker(symbol_entered).info.get('currentPrice')

                database = load_database()
                owned_shares_data = database.execute(
                    'SELECT shares as total FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol',
                    (session['user_id'], symbol_entered.upper())).fetchone()
                owned_shares = owned_shares_data['total'] if owned_shares_data else 0
                if owned_shares >= shares_entered > 0:
                    total_sale_value = price_found * shares_entered
                    database.execute('INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)',
                                     (session['user_id'], symbol_entered, -shares_entered, price_found))
                    database.execute('UPDATE users SET cash = cash + ? WHERE id = ?',
                                     (total_sale_value, session['user_id']))

                    database.commit()
                    flash(f"Success! Sold {shares_entered} of {symbol_entered}.")

                elif shares_entered <= 0:
                    flash("Enter a valid number of shares.")
                elif not is_valid_price(price_found):
                    flash(
                        "Invalid stock symbol. If you are 100% sure you symbol is valid! There may be a technical issue on our side. Try after a minute again")
                else:
                    flash(f"You do not own enough shares to sell. You own {owned_shares} shares of {symbol_entered}.")

        except (ValueError, TypeError):
                flash("Invalid input. Please try again.")
        except Exception:
                flash("Transaction failed.")
    return render_template('trade.html')


@app.route('/portfolio')
def portfolio():

    database = load_database()
    rows = database.execute(
        'SELECT symbol, SUM(shares) as total FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total > 0',
        (session['user_id'],)).fetchall()
    stocks = []
    for r in rows:
        p = yfinance.Ticker(r['symbol']).info.get('currentPrice', 0)
        stocks.append({'symbol': r['symbol'], 'shares': r['total'], 'price': p, 'val': p * r['total']})
    user = database.execute('SELECT cash FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return render_template('portfolio.html', stocks=stocks, cash=user['cash'])


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        database = load_database()
        username = request.form.get('username_entered')
        password_changed = generate_password_hash(request.form.get('password_entered'))
        user = database.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            database.execute('UPDATE users SET password = ? WHERE username = ?', (password_changed, username))
            database.commit()
            flash("Password reset successful. Please login.")
            return redirect(url_for('login'))
        else:
            flash("Username not found.")
    return render_template('forgot_password.html')





@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for('index'))


@app.route('/rules')
def rules():
    return render_template('rules.html')


if __name__ == '__main__':
    init_database()
    app.run(debug=True)
