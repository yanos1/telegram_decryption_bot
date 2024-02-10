import string
from pymongo import MongoClient
import py7zr
import PyPDF2
import threading
import zipfile
import requests
import time
import sys
from functools import partial
from concurrent.futures import ThreadPoolExecutor

from telegram_communication import download_file_here, send_general_message, send_telegram_message, \
    send_telegram_document

MIN_PASSWORD_LEN_OF_ZIP = 1
MIN_PASSWORD_LEN_OF_PDF = 6

MD5_PASSWORD_LENGTH = 32
BOT_TOKEN = "6895682367:AAGmtpDzoAqPZem2y4Th87DUGFLOTTcn6Fs/"
BASE_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"
GET_MESSAGES = "getUpdates"

offset = [292486590]  # offset number is used to get the latest messages from telegram api.
# it is increased by 1 for each message sent.
# i will set it to the last message i personally send.
# putting this value in a data base is imperative but i decided not to for time reasons.


# My local computer mongoDB, My computer must be on in order to use the app properly.
client = MongoClient('mongodb://localhost:27017/')
db = client['MD5RainbowTable']
collection = db['RainbowTable']


###########################
# Password Generators

def all_password_combinations(min_passord_len):
    characters = string.ascii_lowercase + string.digits
    for i in range(min_passord_len, 9):
        for combination in combinations_of_len_k(characters, i):
            yield combination


def combinations_of_len_k(n, k):
    if k == 0:
        yield ''
    elif n:
        for i in range(len(n)):
            for combination in combinations_of_len_k(n, k - 1):
                yield n[i] + combination


###########################


###########################
# MD5 Decryption functions
def is_file_hashed(file_name):
    """
    This function will determine if a .txt file is hashed using MD5 or not.
    :param file_name: the file name we are dealing with
    :return: return True if the content is hashed by MD5, and also return the file content for further use.
             else False and also file content
    """
    hashed = True
    with open(file_name, "r") as f:
        parsed_file_content = [line.strip() for line in f.readlines() if line.strip()]

        for line in parsed_file_content:
            if len(line) != MD5_PASSWORD_LENGTH:
                hashed = False  # all md5 hashes return a 32 digit hash.

        return hashed, parsed_file_content


def remove_hash_with_rainbow_table(parsed_file_content, file_name, chat_id):
    """
    Given a MD5 hashed file, this function unhashes the file content using a precomputed Rainbow Table
    :param parsed_file_content: hashed list of file_name data
    :param file_name: the name of the file
    :param chat_id: telegram chat_id (it is used to communicate to the right telegram chat)
    :return: we will send to the user the unhashed file content and also the unhashed file. return None
    """
    with open(file_name, "w") as f:
        for line in parsed_file_content:
            result = collection.find_one({line: {"$exists": True}})
            if result:
                f.write(result[line])
                f.write(" ")
            else:
                f.write("NA")
        send_telegram_message(chat_id, "I have unhashed the file. Here is the content of it:")

    # Rewind the file pointer to the beginning of the file
    with open(file_name, "r") as f:
        for line in f.readlines():
            send_telegram_message(chat_id, line)
        send_telegram_document(chat_id, file_name)


###########################


###########################
# File decoders
def decode_file(file_id, file_name, chat_id):
    """
    This function determines the file type (supported types for encrypted files: PDF,ZIP,7ZIP,
    supported types for hashed files: TXT),
    then sends the data to the right function of decryption fitting the file type.
    :param file_id: the file id is the telegram id given to the file.
    :param file_name: file name.
    :param chat_id: the chat id is the telegram id for the chatBot.
    :return: return None, but will send a telegram message with the results of the decryption attempts.
    """
    file_extension = file_name.split(".")[1]
    file_content = download_file_here(file_id)  # we download the file so we can use it. (not sure this was a good idea)

    with open(file_name, "wb") as f:
        f.write(file_content)

    send_telegram_message(chat_id, "Recieved a file...")

    if file_extension.lower() == "txt":  # we support MD5 decryption for txt files only.
        send_telegram_message(chat_id, "Trying to unhash the file..")
        is_hashed, parsed_file_content = is_file_hashed(file_name)
        if is_hashed:
            remove_hash_with_rainbow_table(parsed_file_content, file_name, chat_id)
        else:
            send_telegram_message(chat_id, "The file is NOT hashed.")
            send_telegram_document(chat_id, file_name)
        return
    send_telegram_message(chat_id, "Trying to extract password..")

    if file_extension.lower() == "pdf":
        content, was_decrypted = decrypt_pdf(file_name)
        if content and was_decrypted:  # the file was decrypted, we send the results back to the user
            send_telegram_message(chat_id, f"Password found: {content}")
            send_telegram_document(chat_id, file_name)
            return
        elif content and not was_decrypted:  # the file was NOT decrypted.
            send_telegram_message(chat_id, f"No password detected")
            send_telegram_message(chat_id, "File content:")
            send_telegram_message(chat_id, content)
            return

    elif file_extension.lower() == 'zip':
        decrypt_zip(file_name, chat_id)
    elif file_extension.lower() == "7z":
        decrypt_7zip(file_name, chat_id)  # currently not working.
    else:  # if we get here we cannot support the given file.
        send_telegram_message(chat_id, "Unsupported file type.")


# THIS FUNCTION IS BUGGY. DONT TRY TO DECRYPT WITH IT.
def decrypt_7zip(file_name, chat_id):
    """
    This function is decrypting a 7zip file using Brute Force and 1 thread.
    :param file_name: fine name
    :param chat_id: telegram chat_id
    :return: will send a telegram message with the password
    """
    for password in all_password_combinations(MIN_PASSWORD_LEN_OF_ZIP):
        try:
            # Open the 7zip archive with the current password
            with py7zr.SevenZipFile(file_name, mode='r', password=password) as f:
                f.extractall()
                send_telegram_message(chat_id, f"Found password: {password}")
                send_telegram_document(chat_id, file_name)
            return
        except Exception:
            # If the password is incorrect, continue to the next password
            pass


# DISCLAIMER: I am not sure why, but the threadpool i created here doesnt seem to speed up the password cracking proccess.
# I couldn't figure it out in time.

def password_decrypter(password_checker_function):
    """
    This function is utilizing a ThreadPool to execute concurrent password cracking of files.
     The pdf decryption is the only current decryption using this decrypter.
     i didn't update zip and 7zip to use this ThreadPool since the ThreadPool
      wasn't found useful in terms of speeding up the process for a reason i do not know
    :param password_checker_function: This is the function that checks if a password opens the file or not.
     (makes this decrypter able to work with multiple files).
    :return: the password found and if the file was decrypted to begin with (boolean) as a tuple.
    """
    output_password = None
    num_workers = int(sys.argv[1])  # number of threads.
    workers_list = [None] * num_workers  # initiating a list of workers.
    flag = False  # this will turn true when a password is found
    with ThreadPoolExecutor(max_workers=num_workers) as my_pool:
        for i, password in enumerate(all_password_combinations(MIN_PASSWORD_LEN_OF_PDF)):
            # NOTICE - the min password of the general function should be 1.
            # I changed it to MIN_PASSWORD_OF_PDF since only PDF file are currently supported using the ThreadPool
            if workers_list[i % num_workers] is None:
                workers_list[i % num_workers] = my_pool.submit(password_checker_function, password)
            else:
                internal_flag = True
                while internal_flag:
                    for worker in workers_list:
                        if worker.done():
                            internal_flag = False
                            if worker.result()[1]:  # password found!
                                print("FOUND!")
                                flag = True
                                output_password = worker.result()[0]
                            else:
                                workers_list[i % num_workers] = my_pool.submit(password_checker_function, password)
                            break
            if flag:
                break
    return output_password, output_password is not None


def decrypt_pdf(file_name):
    """
    Decrypting PDF file function.
     it calls "password decrypter" which utilizes a thread pool to execute password checking faster.
    :param file_name:
    :return:
    """

    def password_checker(reader, password):
        if reader.decrypt(password) > 0:
            return password, True
        else:
            return None, False

    try:
        with open(file_name, "rb") as f:
            pdf_reader = PyPDF2.PdfReader(f)
            if pdf_reader.is_encrypted:  # file has a password !
                return password_decrypter(partial(password_checker,
                            pdf_reader))  # partial returns a function that includes pdf reader as its firs argument !
            else:  # file has no password !
                text = ""
                for page_num in range(len(pdf_reader.pages)):
                    text += pdf_reader.pages[page_num].extract_text()
                return text, False
    except Exception:
        print("FAILED TO OPEN FILE.")

# DISCLAIMER: password protected zip files were not tested.
# my windows on my machine cant have password protected zip files, for some reason.
def decrypt_zip(path, chat_id):
    """
    Using single threaded brute force to open password protected zip files.
    :param path: file path
    :param chat_id: telegram chat_id
    :return: None.
    """
    with zipfile.ZipFile(path, 'r') as zip_file:
        try:
            zip_file.extractall()
            send_telegram_message(chat_id, f"The {zip_file.filename} file is not protected by a password")
            send_telegram_document(chat_id, path)
        except RuntimeError as e:
            for password in all_password_combinations(MIN_PASSWORD_LEN_OF_ZIP):
                try:
                    zip_file.extractall(pwd=password.encode('utf-8'))
                    send_telegram_message(chat_id, f"Password found: {password}")
                    send_telegram_document(chat_id, path)
                except Exception as e:
                    pass


###########################
# Function to handle incoming messages
def read_telegram_message(offset):
    """
    This function parses the message type from the user and acts accordinly.
    :param offset: the messege id to start checking messages from (we only want messages we haven't read.)
    :return: None
    """
    try:
        url = BASE_URL + GET_MESSAGES
        parameters = {
            "offset": offset[0]
        }
        data = requests.get(url, data=parameters).json()
        for message in data["result"]:
            offset[0] = message[
                            "update_id"] + 1  # updating the counter so we only return new messages with each api call
            if 'document' in message["message"]:
                file_info = message["message"]['document']
                file_name = file_info['file_name']
                file_id = message["message"]['document']['file_id']
                threading.Thread(target=decode_file,
                                 args=(file_id, file_name, message["message"]["chat"]["id"])).start()

            else:  # we are dealing with a message.
                send_general_message(message["message"]["chat"]["id"])
    except Exception as e:
        print("Error processing the data:", str(e))


def main():
    """
    The first function to run. it validates user valid input of number threads
     and initializes the communication with the bot.
    :return: None
    """
    if len(sys.argv) != 2:
        raise ValueError("Wrong number of arguments. please enter 1 argument as the number of threads to use.")
    if not sys.argv[1].isdigit() or int(sys.argv[1]) <= 0:
        raise ValueError("Please only enter a POSITIVE INTEGER. You have entered something else.")

    while True:
        time.sleep(3)  # we check for new messages every 3 seconds
        read_telegram_message(offset)


if __name__ == "__main__":
    main()