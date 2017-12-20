import re

regexes = {
    #"Internal subdomain": re.compile('([a-z0-9]+[.]*supersecretinternal[.]com)'),
    # "Slack Token": re.compile('(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})'),
    # "RSA private key": re.compile('-----BEGIN RSA PRIVATE KEY-----'),
    # "SSH (OPENSSH) private key": re.compile('-----BEGIN OPENSSH PRIVATE KEY-----'),
    # "SSH (DSA) private key": re.compile('-----BEGIN DSA PRIVATE KEY-----'),
    # "SSH (EC) private key": re.compile('-----BEGIN EC PRIVATE KEY-----'),
    # "PGP private key block": re.compile('-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    # "Facebook Oauth": re.compile('[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[\'|"][0-9a-f]{32}[\'|"]'),
    # "Twitter Oauth": re.compile('[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[\'|"][0-9a-zA-Z]{35,44}[\'|"]'),
    # "GitHub": re.compile('[g|G][i|I][t|T][h|H][u|U][b|B].*[[\'|"]0-9a-zA-Z]{35,40}[\'|"]'),
    # "Google Oauth": re.compile('("client_secret":"[a-zA-Z0-9-_]{24}")'),
    # "AWS API Key": re.compile('AKIA[0-9A-Z]{16}'),
    # "Heroku API Key": re.compile('[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'),
    # "Generic Secret": re.compile('[s|S][e|E][c|C][r|R][e|E][t|T].*[\'|"][0-9a-zA-Z]{32,45}[\'|"]'),
    # Fixed
    "Slack Token": re.compile(r'(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})'),
    "RSA private key": re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
    "SSH (OPENSSH) private key": re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
    "SSH (DSA) private key": re.compile(r'-----BEGIN DSA PRIVATE KEY-----'),
    "SSH (EC) private key": re.compile(r'-----BEGIN EC PRIVATE KEY-----'),
    "PGP private key block": re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    "Facebook Oauth": re.compile(r'(?i)(facebook).*[\'"][0-9a-f]{32}[\'"]'),
    "Twitter Oauth": re.compile(r'twitter.*[\'"][a-z0-9]{35,44}[\'"]', re.I),
    "GitHub": re.compile(r'github.*[\'"][A-Z0-9]{35,40}[\'"]', re.I),
    "Google Oauth": re.compile(r'"client_secret"\s*:\s*"[\w\-]{24}"'),
    "AWS API Key": re.compile(r'AKIA[0-9A-Z]{16}'),  # [aA][wW][sS].*AKIA[0-9A-Z]{16}'),
    "Heroku API Key": re.compile(r'(?i)(heroku).*[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}'),
    # "test": re.compile(r'(?:[a-z]+)[a-z]', re.I)
}
