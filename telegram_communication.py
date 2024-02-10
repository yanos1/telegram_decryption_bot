
# this file is used by the main program to communicate with the telegram bot.

import requests


BOT_TOKEN = "6895682367:AAGmtpDzoAqPZem2y4Th87DUGFLOTTcn6Fs/"
BASE_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"
SEND_MESSAGE = "sendMessage"
GET_MESSAGES = "getUpdates"
SEND_DOCUMENT = "sendDocument"

def download_file_here(file_id):
    file_object = requests.get(f"{BASE_URL}getFile?file_id={file_id}").json()
    get_file_api_url = f"{BASE_URL}getFile?file_id={file_id}"
    get_file_content_api_url = f"https://api.telegram.org/file/bot{BOT_TOKEN}{file_object['result']['file_path']}"
    requests.post(url=get_file_api_url)
    response = requests.get(get_file_content_api_url)
    return response.content


def send_general_message(chat_id):
    parameters = {
        "chat_id": chat_id,
        "text": "I am not very good at messaging! but i am ok at cracking open file passwords!"
    }
    url = BASE_URL + SEND_MESSAGE
    requests.get(url, data=parameters)


def send_telegram_message(chat_id, message):
    params = {
        'chat_id': chat_id,
        'text': message
    }
    response = requests.post(BASE_URL + SEND_MESSAGE, params=params)
    if response.status_code != 200:
        print(f"Failed to send message to Telegram: {response.text}")


def send_telegram_document(chat_id, path):
    parameters = {
        "chat_id": chat_id
    }
    files = {
        "document": open(path, "rb")
    }
    requests.get(BASE_URL + SEND_DOCUMENT, data=parameters, files=files)