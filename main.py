from cryptography.fernet import Fernet
from prettytable import PrettyTable
import threading
import time


def generate_key(): #One use only function to define the cryptography of the master password.
   key = Fernet.generate_key()
   with open("key.key", "wb") as f:
       f.write(key)
   print("Key generated and saved in 'key.key'")


def load_key(): #Function that tries to load the cryptographed master password.
   with open("key.key", "rb") as file:
       key = file.read()
   return key


def add(filename, fer):
   user_code = input("\nEnter the new username: ")
   password_code = input("Enter the password: ")
   site = input("Enter the local where this data is going to be used: ")


   site = site.capitalize()
 
   encrypted_password = fer.encrypt(password_code.encode()) # Encrypts the password chosen by the user
 
   with open(filename, "r") as f: # Checks if already exists a register for the same username and site
       lines = f.readlines()
     
       for line in lines:
           line = line.strip()
           if '|' in line:
               existing_user, existing_pwd_site = line.split("|", 1)
             
               if '|' in existing_pwd_site:
                   existing_pwd, existing_site = existing_pwd_site.split("|", 1)
                 
                   if existing_user == user_code and existing_site == site: # Checks if already exists the same username to the same place of login
                       print(f"Error. There is already an instance of {user_code} being used in {site}...\n")
                       return  # Exits the function without adding the register


   with open(filename, "a") as f: # Add the new user if there are no duplicates
       f.write(f"{user_code}|{encrypted_password.decode()}|{site}\n")
       print(f"{user_code} added successfully to {site}.")


def view(filename, fer): #Function that allows the view of each username|password present in the file using a table.
   try:
       table = PrettyTable(['Usernames', 'Passwords', 'Login-in'])
     
       with open(filename, "r") as f:
           lines = f.readlines()
           if not lines:
               print("\nThe file is empty! Add data to view.")
               return
           print("\nThe file contains the following data:\n")
         
           for line in lines:
               data = line.strip()
             
               if '|' in data: #Separates the '|' in between the username, password and place of login.
                   user, pwd = data.split("|", 1)


                   if '|' in pwd:
                       pwd, site = pwd.split("|", 1)


                   try:
                       decrypted_password = fer.decrypt(pwd.encode()).decode() #Decrypts the password chosen by the user.
                     
                       table.add_row([user, decrypted_password, site])
                   except Exception as e:
                       print(f"Error decrypting the password for {user}: {e}")
               else:
                   print(f"Line with incorrect format: {data}")
           print(table)


   except FileNotFoundError:
       print("\nThe file does not exist. Add an user and password to create the file.")
   except Exception as e:
       print(f"Error reading the file: {e}")


def search(filename, fer):
   try:
       with open(filename, "r") as f:
           lines = f.readlines()
           if not lines:
               print("\nThe file is empty! Add data to search.")
               return
   except FileNotFoundError:
       print("\nThe file does not exist. Add a user and password to create the file.")
       return
 
   searchUPL = input("\nEnter your search type ('username', 'password', 'log-in'): ")


   searchUPL = searchUPL.capitalize()


   while True:
       match searchUPL:
           case "Username":
               searchU = input("\nEnter the username to search for: ")
               table = PrettyTable(['Username', 'Password', 'Login Location'])


               found = False  #Flag to track if a match is found


               for line in lines:
                   data = line.strip()
                   if '|' in data:
                       parts = data.split("|")
                       if len(parts) == 3:
                           user, encrypted_pwd, site = parts


                           try:
                               decrypted_password = fer.decrypt(encrypted_pwd.encode()).decode()
                           except Exception as e:
                               print(f"Error decrypting password for {user}: {e}")
                               continue


                           if user == searchU:  #If user corresponds to the search
                               table.add_row([user, decrypted_password, site])
                               found = True


               if found:
                   print(table)
               else:
                   print(f"No matches found for username: {searchU}")
               return  #Ends the function
           case "Password":
               searchP = input("\nEnter the password to search for: ")
               table = PrettyTable(['Username', 'Password', 'Login Location'])


               found = False


               for line in lines:
                   data = line.strip()
                   if '|' in data:
                       parts = data.split("|")
                       if len(parts) == 3:
                           user, encrypted_pwd, site = parts
                           try:
                               decrypted_password = fer.decrypt(encrypted_pwd.encode()).decode()
                           except Exception as e:
                               print(f"Error decrypting password for {user}: {e}")
                               continue


                           if decrypted_password == searchP:
                               table.add_row([user, decrypted_password, site])
                               found = True


               if found:
                   print(table)
               else:
                   print(f"No matches found for password: {searchP}")
               return
           case "Log-in":
               searchL = input("\nEnter the login location to search for: ")
               table = PrettyTable(['Username', 'Password', 'Login Location'])


               found = False


               for line in lines:
                   data = line.strip()
                   if '|' in data:
                       parts = data.split("|")
                       if len(parts) == 3:
                           user, encrypted_pwd, site = parts
                           try:
                               decrypted_password = fer.decrypt(encrypted_pwd.encode()).decode()
                           except Exception as e:
                               print(f"Error decrypting password for {user}: {e}")
                               continue


                           if site == searchL:
                               table.add_row([user, decrypted_password, site])
                               found = True


               if found:
                   print(table)
               else:
                   print(f"No matches found for login location: {searchL}")
               return
           case _:
               print("Invalid entry. Please enter 'username', 'password', or 'log-in'.")
               searchUPL = input("\nEnter your search type ('username', 'password', 'log-in'): ")


def remove(filename, fer):
    user_code = input("\nEnter the username to be removed: ")
    password_code = input("Enter the password to be removed: ")
    site = input("Enter the local to be removed: ")


    site = site.capitalize()  # Capitalizes the Log-in.


    try:
        with open(filename, "r") as f:
            lines = f.readlines()


        with open(filename, "w") as f:
            removed = False  # Flag to check if anything was removed
            for line in lines:
                data = line.strip()
                if '|' in data:
                    parts = data.split("|")
                    if len(parts) == 3:
                        user, encrypted_pwd, stored_site = parts
                        try:
                            decrypted_password = fer.decrypt(encrypted_pwd.encode()).decode()
                        except Exception as e:
                            print(f"Error decrypting password for {user}: {e}")
                            continue


                        if user == user_code and decrypted_password == password_code and stored_site == site:
                            removed = True  # Set flag to True if match found
                        else:
                            f.write(line)  # Write back the line if it does not match


            if removed:
                print("\nThe username, password, and log-in were removed.\n")
            else:
                print("\nNo matching record found to remove.\n")
    except Exception as e:
        print(f"\nError. Unable to remove the inputs: {e}.\n")


def master_code(): #Function that defines the entry of the user based on the master password.
   t = 60
   time_adder = 1
 
   try:
       with open("master_password.txt", "r") as f:
           master_password = f.readline().strip()
   except FileNotFoundError:
       print("The master password file was not found!")
       return False
 
   for i in range(3):
       for j in range(3):
           tm = t / 60
           master_attempt = input("Enter the master password: ")
           if master_attempt == master_password:
               return True
           else:
               print(f"Incorrect password. {2 - j} attempts left.")


       print(f"\nToo many failed attempts. Try again in {int(tm)} minutes...\n")
     
       time.sleep(t)
       time_adder += 0.5
       t =  pow(t, time_adder)
 
   print("Access denied!")
   return False


def get_filename(): #Function that allows the selection of the name of an existing or new file.
   gfn = True
   while gfn == True:
       filename = input("\nEnter the name of the file (e.g.: data.txt or just data) or type '\\h' for help: ")
     
       match filename:
           case "\\h":
             print("\nThe username, cryptographed password and place of login related in the data must be in a single line separated by '|', with each user on a new line.")
             print("Moreover, each user password must have a respective encryption. Otherwise, the program shall fail.\n")
     
           case "":
             print("Error. Add a name of a file...\n")
         
           case _:
               if '.txt' not in filename:
                   filename = filename + ".txt"
         
               gfn = False
 
   return filename


try: #Code's flow order.
   load_key()
except FileNotFoundError:
   print("Key was not found! Generating a new key...")
   generate_key()


key = load_key()
fer = Fernet(key)


if not master_code():
   exit()


filename = get_filename()
if filename is None:
   exit()


while True:
   print("\nSelect your action:\n")
   action = input("\n'add' => add a new user;\n'view' => view all users;\n'search' => search for an username, password or log-in;\n'remove' => remove an user;\n'return' => return to the file selection;\n'quit' => exit the application.\n")


   action = action.capitalize()


   match action:
       case "Return":
           print("\nReturning to the file selection...\n")
           get_filename()
       case "Quit":
           print("\nEnding process...")
           break
       case "Add":
           add(filename, fer)
       case "View":
           view(filename, fer)
       case "Search":
           search(filename, fer)
       case "Remove":
           remove(filename, fer)
       case _:
           print("Invalid entry. Choose 'add', 'view', 'search', 'return' or 'quit'.")
