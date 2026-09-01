import os
from pathlib import Path
from dotenv import load_dotenv
import openai

# Load .env from project root
load_dotenv(Path(__file__).parent.parent.parent / '.env')
key = os.environ.get('OPENAI_API_KEY', '')
print('Using key present:', bool(key))
try:
    client = openai.OpenAI(api_key=key)
    models = client.models.list()
    print('models_count', len(models.data) if hasattr(models, 'data') else 'unknown')
except Exception as e:
    print('openai_error', type(e).__name__, str(e))
