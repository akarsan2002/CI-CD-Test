import os
import requests
from openai import OpenAI
from langchain_openai import ChatOpenAI
# import anthropic   <- commented out, should NOT be reported

# FAKE key for testing the scanner only
client = OpenAI(api_key="sk-FAKEFAKEFAKEFAKEFAKEFAKE1234")

def ask(prompt):
    # model name in a normal string
    return client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": prompt}])

def ask_raw(prompt):
    return requests.post("https://api.anthropic.com/v1/messages",
                         json={"model": "claude-3-5-sonnet-20241022", "messages": []})
