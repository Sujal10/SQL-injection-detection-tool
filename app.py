from flask import Flask, request, jsonify
from detector import detect_sql_injection, log_attack

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search():
    """Search endpoint that checks for SQL injection."""
    query = request.args.get('q', '')  # Get 'q' parameter from the URL
    ip_address = request.remote_addr   # Get the user's IP address

    # Check for SQL injection
    if detect_sql_injection(query):
        log_attack(ip_address, query)  # Log the attack
        return jsonify({"message": "SQL Injection detected!"}), 403

    # If no SQL injection, return a success message
    return jsonify({"message": "Search successful", "query": query}), 200

if __name__ == '__main__':
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5001)
