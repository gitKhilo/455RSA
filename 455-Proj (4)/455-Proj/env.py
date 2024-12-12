from dotenv import load_dotenv
import os
load_dotenv()
api_key= os.getenv("GROQ_API_KEY") 
print(f"Your API key is: {api_key}")
