# CS50-PSET8-Finance
My solution for CS50x2020 problem set 8 - finance.

A web app to manage a portfolio of stocks, using real time data and virtual buying and selling.  
Uses the IEX API to get stock data in real time.  

Users are able to login with a username and password once registered. Passwords are not directly stored in the 'users' database, instead an encrypted hash of the password is stored for security.

Once logged in, users can see their portfolio of stocks and cash, get a quote for a stock, buy or sell stocks (if they have the cash or stocks necessary), and see their history of transactions. My personal addition was to add a lookup for stock symbols based on the company name.
