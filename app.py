from flask import Flask, request, jsonify, send_from_directory
import pandas as pd
import bcrypt
import os
import configparser

app = Flask(__name__)

# Load configuration from the .conf file
config = configparser.ConfigParser()
config_file_path = os.path.join(os.path.dirname(__file__), 'config.conf')
if not os.path.exists(config_file_path):
    raise FileNotFoundError(f"Configuration file not found: {config_file_path}")

config.read(config_file_path)
if 'settings' not in config:
    raise configparser.NoSectionError('settings')

CSV_FILE = config.get('settings', 'csv_file')

def read_csv():
    if os.path.exists(CSV_FILE):
        df = pd.read_csv(CSV_FILE, index_col='username')
        return df
    else:
        return pd.DataFrame(columns=['password', 'name', 'phone'], index=pd.Index([], name='username'))

def write_csv(df):
    df.to_csv(CSV_FILE)

def encrypt_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))

@app.route('/')
def index():
    return send_from_directory('', 'index.html')

@app.route('/index', methods=['POST'])
def user():
    data = request.json
    action = data.get('action')
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirm_password', None)
    name = data.get('name', None)
    phone = data.get('phone', None)

    try:
        df = read_csv()

        if action == 'register':
            if not username or not password or not confirm_password:
                return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400

            if password != confirm_password:
                return jsonify({'status': 'error', 'message': 'Passwords do not match'}), 400

            if username in df.index:
                return jsonify({'status': 'error', 'message': 'Username already exists'}), 400

            hashed_password = encrypt_password(password)
            new_user = pd.DataFrame({
                'password': [hashed_password],
                'name': [name],
                'phone': [phone]
            }, index=[username])

            df = pd.concat([df, new_user])
            df.index.name = 'username'
            write_csv(df)

            return jsonify({'status': 'success', 'message': 'Registration successful'}), 200

        elif action == 'login':
            if not username or not password:
                return jsonify({'status': 'error', 'message': 'Missing username or password'}), 400

            if username not in df.index:
                return jsonify({'status': 'error', 'message': 'Invalid username or password'}), 404

            stored_password = df.at[username, 'password']
            if not check_password(stored_password, password):
                return jsonify({'status': 'error', 'message': 'Invalid username or password'}), 404

            return jsonify({'status': 'success', 'message': 'Login successful'}), 200

        else:
            return jsonify({'status': 'error', 'message': 'Invalid action'}), 400

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
