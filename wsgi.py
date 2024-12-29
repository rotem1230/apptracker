import os
import sys

# Add your project directory to the sys.path
project_home = '/home/rotem121/trackerapp'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Import your application
from app import app as application
