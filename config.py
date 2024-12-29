class Config:
    # Google Maps API key
    GOOGLE_MAPS_API_KEY = 'AIzaSyCnAvUZK7wRq-c_7z_xP1UmBXVTf7IEtc4'
    
    # Flask app configuration
    SECRET_KEY = 'dev-secret-key-12345'  # Change this in production!
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Server configuration
    SERVER_NAME = None  # Let the server determine this
    PREFERRED_URL_SCHEME = 'http'  # Changed to http for development
    APPLICATION_ROOT = '/'
    
    # Session configuration
    SESSION_COOKIE_SECURE = False  # Set to True only if using HTTPS
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    
    # Flask-Login configuration
    LOGIN_DISABLED = False
    LOGIN_VIEW = 'login'
