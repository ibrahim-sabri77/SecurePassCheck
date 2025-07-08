from flask import Flask, render_template, request
import hashlib
import requests

app = Flask(__name__)

def check_pwned_password(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)
    
    if res.status_code != 200:
        raise RuntimeError("Error fetching data from API.")
    
    hashes = (line.split(':') for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
    return 0

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        password = request.form['password']
        count = check_pwned_password(password)
        if count:
            result = f"⚠️ This password has been found {count} times in data breaches."
        else:
            result = "✅ This password has not been found in any known data breaches."
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
