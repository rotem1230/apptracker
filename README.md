# Tracker App

אפליקציה למעקב אחר מיקום בזמן אמת המאפשרת:
- רישום והתחברות משתמשים
- יצירת קודי QR למכשירים
- מעקב אחר מיקום בזמן אמת
- הגדרת אזורים בטוחים

## התקנה
1. התקן את הדרישות:
```bash
pip install -r requirements.txt
```

2. הגדר את משתני הסביבה:
- `GOOGLE_MAPS_API_KEY`: מפתח API של Google Maps
- `SECRET_KEY`: מפתח סודי של Flask

3. הרץ את השרת:
```bash
python app.py
```
