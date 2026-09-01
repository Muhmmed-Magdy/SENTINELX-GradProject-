from dotenv import load_dotenv
from pathlib import Path
import os
load_dotenv(Path(__file__).parent.parent.parent / '.env')
import openai
key = os.environ.get('OPENAI_API_KEY')
print('key present', bool(key))
try:
    client = openai.OpenAI(api_key=key)
    resp = client.chat.completions.create(
        model=os.environ.get('OPENAI_MODEL','gpt-4o-mini'),
        messages=[{'role':'user','content':'Say hello in one short sentence.'}],
        temperature=0.2, max_tokens=50
    )
    print('resp_type', type(resp))
    try:
        print('choices', resp.choices)
        print('message content', resp.choices[0].message.content)
    except Exception as e:
        print('accessing resp fields failed', e)
    print('raw', resp)
except Exception as e:
    print('openai chat error', type(e).__name__, str(e))
