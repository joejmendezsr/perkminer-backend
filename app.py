@app.route("/")
def home():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
        <title>PerkMiner Homepage</title>
    </head>
    <body class="container py-5">
        <nav class="navbar navbar-expand navbar-light bg-light mb-4">
            <a class="navbar-brand" href="/">PerkMiner</a>
            <div class="navbar-nav">
                <a class="nav-link" href="{{ url_for('login') }}">Login</a>
                <a class="nav-link" href="{{ url_for('register') }}">Register</a>
                <a class="nav-link" href="{{ url_for('business_register') }}">Advertise with Us</a>
            </div>
        </nav>
        <div class="jumbotron">
            <h1 class="display-4">Welcome to PerkMiner!</h1>
            <p class="lead">Your secure, custom site is now live.</p>
            <hr class="my-4">
            <p>Build more features, connect your domain, and make it yours.</p>
        </div>
    </body>
    </html>
    """)