import re

def detect_sql_injection(query):
    """Detects if the input query contains SQL injection patterns."""
    # List of common SQL injection keywords and patterns
    sql_patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",    # ' or -- or #
        r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|JOIN|WHERE|OR)\b",  # SQL keywords
        r"OR\s+1\s*=\s*1",  # OR '1'='1'
        r"\'\s*OR\s*\'",  # ' OR '
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            return True  # SQL injection detected
    return False

def log_attack(ip_address, query):
    """Logs detected SQL injection attacks to a file."""
    with open("attack_log.txt", "a") as f:
        f.write(f"Attack detected from IP: {ip_address}\n")
        f.write(f"Query: {query}\n\n")
