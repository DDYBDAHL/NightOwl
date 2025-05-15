import email
from email import policy
# import genericpath # Replaced with os.path
import sys
import os
import re
# from typing import Final # Unused import removed
import colorama
import extract_msg
from colorama import Fore
colorama.init(autoreset=True)

# global count # Unused global declaration

# Ensure exactly one argument (the email file) is provided
if len(sys.argv) != 2:
    print(Fore.RED + "Usage: python NightOwl.py <email_file.msg or email_file.eml>")
    sys.exit(1)

emailFName = sys.argv[1]
emailFNameF = "Attachments"
c_path = os.getcwd()
exportedPath = os.path.join(c_path, emailFNameF)

# Create Attachments directory
if os.path.exists(exportedPath):
    print(Fore.YELLOW + f"Output directory '{exportedPath}' already exists. Files will be saved there.")
    # If you want to exit if it exists, uncomment the lines below and comment out the print above
    # print(Fore.RED + f"Error: Output directory '{exportedPath}' already exists. Please remove or rename it.")
    # sys.exit(1)
else:
    try:
        os.mkdir(exportedPath)
        print(Fore.GREEN + f"Created output directory: {exportedPath}")
    except OSError as e:
        print(Fore.RED + f"Error creating directory {exportedPath}: {e}")
        sys.exit(1)


def fileChecker():
    if emailFName.endswith('.msg'):
        msgGrabber(emailFName)
    elif emailFName.endswith('.eml'):
        baseGrabber()
    else:
        print(Fore.RED + f"The file is in an unsupported format ({emailFName.split('.')[-1]}): {emailFName}")
        print(Fore.YELLOW + "Please provide a .msg or .eml file.")

def msgGrabber(file):
    try:
        print(Fore.CYAN + f"[+] File Name: {file}\n")
        with extract_msg.openMsg(file) as messageFile:
            print(Fore.GREEN + "[+] From: " + Fore.RESET + str(messageFile.sender))
            print(Fore.GREEN + "[+] To: " + Fore.RESET + str(messageFile.to))
            print(Fore.GREEN + "[+] Subject: " + Fore.RESET  + str(messageFile.subject))
            print(Fore.GREEN + "[+] CC: " + Fore.RESET  + str(messageFile.cc))
            print(Fore.GREEN + "[+] BCC: " + Fore.RESET  + str(messageFile.bcc))
            print(Fore.GREEN + "[+] Email Time: " + Fore.RESET  + str(messageFile.receivedTime))
            if len(messageFile.attachments) > 0:
                print(Fore.GREEN + "[+] Attachment Found - Saving in Attachments!\n\n")
                for attachment in messageFile.attachments:
                     attachmentName = attachment.getFilename()
                     print(Fore.CYAN + attachmentName + "\n")
                     attachment.save(customPath=exportedPath) # Ensure exportedPath is defined globally or passed
            else:
                print(Fore.GREEN + "[+] No Attachments Observed")
            
            messageBody = str(messageFile.body)
            trucatedBody = messageBody.replace('\r', ' ')
            print(Fore.GREEN + "[+] Email Body\n\n" + Fore.YELLOW + trucatedBody)
            
            msgIPGrabber(trucatedBody)
            msgEmailGrabber(trucatedBody)
            msgURLGrabber(trucatedBody)
            # messageFile.close() # Not needed with 'with' statement
    except Exception as e:
        print(Fore.RED + f"Something Went Wrong In msgGrabber: {e}")

def msgIPGrabber(bodyWell):
    IP = [] 
    IP_COUNT = 0
    # Regex for IPv4 addresses
    regex = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', bodyWell)
    
    try:
        if regex: # Check if regex is not empty or None
            print(Fore.GREEN + "\n[+] IP Addresses Observed In MSG Body:")
            for match in regex:
                if match not in IP:
                    IP.append(match)
                    IP_COUNT += 1
                    print(f"{IP_COUNT}. {Fore.CYAN}{match}")
        else:
            print(Fore.YELLOW + "\n[-] No IP Addresses found in MSG body.")
    except Exception as e:
        print(Fore.RED + f"Something Goes Wrong In Grabbing MSG IPs: {e}")

def msgEmailGrabber(emailBody):
    EMAIL = [] 
    # Regex for email addresses
    regex = re.findall(r'[\w\.-]+@[\w\.-]+', emailBody)
    
    try:
        if regex:
            print(Fore.GREEN + "\n[+] Emails Observed In MSG Body:")
            for match in regex:
                if match not in EMAIL:
                    EMAIL.append(match)
                    print(Fore.CYAN + match)
            print("\n")
        else:
            print(Fore.YELLOW + "\n[-] No Emails found in MSG body.")
    except Exception as e:
        print(Fore.RED + f"Something Goes Wrong In Grabbing MSG Emails: {e}")

def msgURLGrabber(urlFileContent):
    try:
        print(Fore.GREEN + "\n[+] URLs Observed in MSG Body:")
        URL = [] 
        # More robust regex for domain-like patterns, might need refinement for full URLs
        regex = re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}', urlFileContent)
        # If you need to find full http/https URLs:
        # regex_full_url = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', urlFileContent)
        
        if regex:
            for match in regex:
                urlFound = str(match).strip()
                # Basic cleaning, might need to be more robust depending on expected garbage
                urlFound = re.sub(r"[<>()'\[\]]", "", urlFound) 
                if urlFound and urlFound not in URL:
                    URL.append(urlFound)
                    print(Fore.CYAN + urlFound)
        else:
            print(Fore.YELLOW + "[-] No URLs found in MSG body.")
        print("\n")
    except Exception as e:
        print(Fore.RED + f"Something Goes Wrong In MSG URL Grabber: {e}")

def baseGrabber():
    try: 
        print(Fore.BLUE + "-"*50)
        print(Fore.BLUE + "Printing Details You Should Care About (.eml)!")
        print(Fore.BLUE + "-"*50 + "\n")
        hop_count = 0 # Local variable for hops
        with open(emailFName, "r", encoding="utf-8", errors="ignore") as sample:
            for line in sample:
                line = line.strip() # Remove leading/trailing whitespace
                if line.startswith("From: "):
                    print(Fore.RED + line)
                elif line.startswith("To: "):
                    print(Fore.YELLOW + line)   
                elif line.startswith("Subject: "):
                    print(Fore.GREEN + line)
                elif line.startswith("Date: "):
                    print(Fore.RED + line) 
                elif line.startswith("Message-ID: "):
                    print(Fore.GREEN + line)
                elif line.startswith("Return-Path:"):
                    print(Fore.YELLOW + line)
                # elif line.startswith("Return-To:"): # Often same as Return-Path or not present
                #     print(Fore.GREEN + line)
                elif line.startswith("List-Unsubscribe:"):
                    print(Fore.YELLOW + line)
                # "Message Body: " is not a standard header. Body parsing is complex.
                # if line.startswith("Message Body: "): 
                #     print(Fore.GREEN + line)
                elif line.startswith("Received: "):
                    hop_count += 1
                    print(Fore.CYAN + line) # Print received lines for context

        print(f"\n{Fore.BLUE}+> Total HOPS Count: {hop_count}\n")
        
    except FileNotFoundError:
        print(Fore.RED + f"Error: File not found - {emailFName}")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"Something Went Wrong in Base Grabber: {e}")
        sys.exit(1)
    finally: # Ensure these run even if baseGrabber has issues, if file was opened
        emailGrabber() # Processes the whole .eml file for emails

def emailGrabber():
    print(Fore.BLUE + "-"*50)
    print(Fore.BLUE + "Butchering Emails from .eml file!")
    print(Fore.BLUE + "-"*50)

    try:
        with open(emailFName,'r', encoding='utf-8', errors="ignore") as fileOpen:
            readText = fileOpen.read()
        
        EMAIL = [] 
        regex = re.findall(r'[\w\.-]+@[\w\.-]+', readText)
        if regex:
            for match in regex:
                if match not in EMAIL:
                    EMAIL.append(match)
                    print(Fore.YELLOW + match)
            print("\n")
        else:
            print(Fore.YELLOW + "[-] No email addresses found in the .eml file body/headers via regex.\n")
            
    except FileNotFoundError:
        print(Fore.RED + f"Error: File not found for email grabbing - {emailFName}")
    except Exception as e:
        print(Fore.RED + f"Something Went Wrong in Email Grabber: {e}")
    finally:
        ipGrabber()

def ipGrabber():
    print(Fore.BLUE + "-"*50)
    print(Fore.BLUE + "Printing The Unique IP Addresses Only from .eml file!")
    print(Fore.BLUE + "-"*50)
    
    try:
        with open(emailFName,'r', encoding='utf-8', errors="ignore") as fileOpen:
            readText = fileOpen.read()

        IP = [] 
        IP_COUNT = 0
        regex = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', readText)
        if regex:
            print(Fore.GREEN + "\n[+] IP Addresses Observed:")
            for match in regex:
                if match not in IP:
                    IP.append(match)
                    IP_COUNT += 1
                    print(f"{IP_COUNT}. {Fore.YELLOW}{match}")
            print("\n")
        else:
            print(Fore.YELLOW + "[-] No IP addresses found in the .eml file via regex.\n")
    
    except FileNotFoundError:
        print(Fore.RED + f"Error: File not found for IP grabbing - {emailFName}")
    except Exception as e:
        print(Fore.RED + f"Something Went Wrong IP Grabber: {e}")
    finally:
        urlGrabber()


def urlGrabber():
    print("\n")
    print(Fore.BLUE + "-"*50)
    print(Fore.BLUE + "Butchering All The URLs from .eml file!")
    print(Fore.BLUE + "-"*50 + "\n")
    
    try:
        with open(emailFName,'r', encoding='utf-8', errors="ignore") as fileOpen:
            readText = fileOpen.read()
        
        # Attempt to find full URLs first
        found_urls_specific = []
        specific_url_regex = re.search(r"(?P<url>https?://[^\s\"'<>()]+)", readText)
        if specific_url_regex:
            found_urls_specific.append(specific_url_regex.group("url"))
            print(Fore.GREEN + "Specific HTTP(S) URL found: " + Fore.CYAN + specific_url_regex.group("url"))

        print(Fore.GREEN + "\n[+] Domain-like patterns observed:")
        URL = [] 
        # Regex for domain-like patterns
        domain_regex = re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}', readText)
        
        combined_urls = set(found_urls_specific) # Use a set for uniqueness

        if domain_regex:
            for match in domain_regex:
                cleaned_match = str(match).strip()
                # Further clean common surrounding characters if necessary
                cleaned_match = re.sub(r"[\"<>()']", "", cleaned_match)
                if cleaned_match:
                     combined_urls.add(cleaned_match)
        
        if combined_urls:
            for u in sorted(list(combined_urls)): # Print sorted unique URLs/domains
                 print(Fore.CYAN + u)
        else:
            print(Fore.YELLOW + "[-] There were no URLs or domain-like patterns found via regex!")
        print("\n")

    except FileNotFoundError:
        print(Fore.RED + f"Error: File not found for URL grabbing - {emailFName}")
    except Exception as e:
        print(Fore.RED + f"Something Went Wrong In URL Grabber: {e}")
    finally:
        xHunter()
    
def xHunter():
    print("\n")
    print(Fore.BLUE + "-"*50)
    print(Fore.BLUE + "Printing All The X-Headers from .eml file")
    print(Fore.BLUE + "-"*50 + "\n")

    try:
        with open(emailFName,'r', encoding='utf-8', errors="ignore") as sample:
            found_x_header = False
            for line in sample:
                if line.startswith("X-"):
                    print(Fore.YELLOW + line.strip())
                    found_x_header = True
            if not found_x_header:
                print(Fore.YELLOW + "[-] No X-Headers Observed")
    except FileNotFoundError:
        print(Fore.RED + f"Error: File not found for X-Header hunting - {emailFName}")
    except Exception as e:
        print(Fore.RED + f"No X Headers Observed or error: {e}")
    finally:
        embedAttachments() # For .eml files
        
def embedAttachments():
    print(Fore.BLUE + "-"*50)
    print(Fore.BLUE + "Checking If There Are Any Attachments in .eml file")
    print(Fore.BLUE + "-"*50)

    try:
        with open(emailFName, "rb") as f: # Open .eml in binary mode for email parser
            attachFile = email.message_from_binary_file(f, policy=policy.default)
            
            attachments_found = False
            for attachment in attachFile.iter_attachments():
                attName = attachment.get_filename()
                if attName: # Only proceed if there's a filename
                    attachments_found = True
                    print(Fore.GREEN + f"\n[+] Attachment Found: {Fore.RESET}{attName}")
                    attachment_path = os.path.join(exportedPath, attName)
                    try:
                        with open(attachment_path, "wb") as fileWrite:
                            fileWrite.write(attachment.get_payload(decode=True))
                        print(Fore.GREEN + f"    Saved to: {attachment_path}")
                    except Exception as e_write:
                        print(Fore.RED + f"    Error saving attachment {attName}: {e_write}")
                else: # Handle cases where filename might be missing (e.g. inline images not treated as typical attachments)
                    content_type = attachment.get_content_type()
                    if attachment.is_attachment(): # Could be an inline attachment without a name
                         print(Fore.YELLOW + f"[!] Found an inline attachment part of type '{content_type}', but no filename. Skipping save for now.")

            if not attachments_found:
                print(Fore.YELLOW + "[-] No extractable attachments found in the .eml file.")

    except FileNotFoundError:
        print(Fore.RED + f"Error: File not found for attachment extraction - {emailFName}")
    except Exception as e:
        print(Fore.RED + f"Something Went Wrong In Embed Attachments: {e}")


def banner():
    # Banner content remains the same
    banner_text = """
    
██████   █████  ███           █████       █████          ███████                    ████ 
░░██████ ░░███  ░░░           ░░███       ░░███         ███░░░░░███                 ░░███ 
 ░███░███ ░███  ████   ███████ ░███████   ███████      ███     ░░███ █████ ███ █████ ░███ 
 ░███░░███░███ ░░███  ███░░███ ░███░░███ ░░░███░      ░███      ░███░░███ ░███░░███  ░███ 
 ░███ ░░██████  ░███ ░███ ░███ ░███ ░███   ░███       ░███      ░███ ░███ ░███ ░███  ░███ 
 ░███  ░░█████  ░███ ░███ ░███ ░███ ░███   ░███ ███   ░░███     ███  ░░███████████   ░███ 
 █████  ░░█████ █████░░███████ ████ █████  ░░█████     ░░░███████░    ░░████░████    █████
░░░░░    ░░░░░ ░░░░░  ░░░░░███░░░░ ░░░░░    ░░░░░        ░░░░░░░       ░░░░ ░░░░    ░░░░░ 
                      ███ ░███                                                            
                     ░░██████                                                             
                      ░░░░░░                                                              


    OFFLINE PHISHING EMAIL BUTCHER
    Coded by Kamran Saifullah - Frog Man v1.0
    -----------------------------------------
    Usage: python NightOwl.py <email_file.msg or email_file.eml>
    -----------------------------------------
    LinkedIn: https://www.linkedin.com/in/kamransaifullah/
    GitHub: https://github.com/deFr0ggy
    Twitter: https://twitter.com/deFr0ggy
    """
    print(Fore.GREEN + banner_text + "\n")

def main():
    banner()
    # Argument check is now at the beginning of the script
    fileChecker()

if __name__ == "__main__":
    main()
