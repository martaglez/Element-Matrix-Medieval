import asyncio
import logging
import os
import json
import sys
from urllib.parse import urlparse
from nio import AsyncClient, MatrixRoom, RoomMessageText, LoginResponse, JoinResponse, RoomCreateResponse
from nio.exceptions import OlmUnverifiedDeviceError

# Configure logging for the application
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables used throughout the program
client = None
config_file = "matrix_config.json"
user_keys = {}  # Now stores passphrases, not keys
current_room_id = None

# === MEDIEVAL CIPHER IMPLEMENTATION ===

def normalize_ij(text):
    return text.replace('J', 'I').replace('j', 'i')

def atbash(text):
    text = text.upper()
    return ''.join(chr(90 - (ord(c) - 65)) if c.isalpha() else c for c in text)

def vigenere_encr(plaintext, key):
    plaintext = plaintext.upper()
    key = key.upper()
    ciphertext = ""
    key_len = len(key)
    for i, char in enumerate(plaintext):
        if char.isalpha():
            p = ord(char) - 65
            k = ord(key[i % key_len]) - 65
            c = (p + k) % 26
            ciphertext += chr(c + 65)
        else:
            ciphertext += char
    return ciphertext

def vigenere_decr(ciphertext, key):
    ciphertext = ciphertext.upper()
    key = key.upper()
    plaintext = ""
    key_len = len(key)
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            c = ord(char) - 65
            k = ord(key[i % key_len]) - 65
            p = (c - k + 26) % 26
            plaintext += chr(p + 65)
        else:
            plaintext += char
    return plaintext

def medieval_cipher_encr(plaintext, passphrase):
    # STEP 1: Normalize I/J to I
    plaintext = normalize_ij(plaintext)
    normalized = ''.join(c for c in plaintext.upper() if c.isalpha())
    round1 = atbash(normalized)
    key = atbash(''.join(c for c in passphrase.upper() if c.isalpha()))
    ciphertext = vigenere_encr(round1, key)
    return ciphertext

def medieval_cipher_decr(ciphertext, passphrase):
    key = atbash(''.join(c for c in passphrase.upper() if c.isalpha()))
    round1 = vigenere_decr(ciphertext, key)
    plaintext = atbash(round1)
    return plaintext

# === END MEDIEVAL CIPHER ===

# Function to validate URL
def is_valid_url(url):
    try:
        result = urlparse(url)
        return result.scheme in ('http', 'https') and result.netloc
    except:
        return False

# Functions for managing configuration
def load_config():
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except:
            pass
    
    return {
        "homeserver": "https://matrix.org",
        "user_id": "@atlantic_pacific:matrix.org",
        "device_id": "",
        "access_token": "",
        "room_id": ""
    }

def save_config(config):
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)

async def setup_client():
    global client, current_room_id
    
    config = load_config()
    
    print("Matrix Client Setup")
    print("===================")
    
    homeserver = config.get('homeserver', 'https://matrix.org')
    
    if config.get('user_id') and config.get('access_token'):
        use_existing = input("Found existing credentials. Use them? (y/n): ").strip().lower()
        if use_existing == 'y':
            homeserver = config['homeserver']
            if not is_valid_url(homeserver):
                print("Saved homeserver URL is invalid. Please provide a valid one.")
                homeserver = input("Enter Matrix homeserver URL: ").strip()
                while not is_valid_url(homeserver):
                    print("Invalid homeserver URL. It must be a valid URL like https://matrix.org")
                    homeserver = input("Enter Matrix homeserver URL: ").strip()
                config['homeserver'] = homeserver
                save_config(config)
            
            user_id = config['user_id']
            client = AsyncClient(homeserver, user_id)
            client.device_id = config['device_id']
            client.access_token = config['access_token']
            client.user_id = user_id
            
            if config.get('room_id'):
                current_room_id = config['room_id']
                print(f"Using existing room: {current_room_id}")
                return True
            else:
                print("No room configured. You'll need to join or create one.")
                return True
    
    homeserver_input = input(f"Enter Matrix homeserver URL [{homeserver}]: ").strip()
    if homeserver_input:
        homeserver = homeserver_input
    while not is_valid_url(homeserver):
        print("Invalid homeserver URL. It must be a valid URL like https://matrix.org")
        homeserver = input("Enter Matrix homeserver URL: ").strip()
    
    user_id = input("Matrix User ID (e.g., @username:matrix.org): ").strip()
    if not user_id:
        user_id = config.get('user_id', "@atlantic_pacific:matrix.org")
    
    client = AsyncClient(homeserver, user_id)
    
    password = input("Password: ").strip()
    
    try:
        device_name = "MedievalCipherDevice"
        resp = await client.login(password=password, device_name=device_name)
        
        if isinstance(resp, LoginResponse):
            print("Login successful!")
            
            config['homeserver'] = homeserver
            config['user_id'] = resp.user_id or user_id
            config['device_id'] = resp.device_id
            config['access_token'] = resp.access_token
            save_config(config)
            
            client.user_id = config['user_id']
            
            await setup_room(config)
            return True
        else:
            print(f"Login failed: {resp}")
            return False
    except Exception as e:
        print(f"Login error: {e}")
        import traceback
        traceback.print_exc()
        return False

async def setup_room(config):
    global current_room_id
    
    print("\nRoom Setup")
    print("==========")
    
    room_option = input("Join existing room (j) or create new room (c)? [j/c]: ").strip().lower()
    
    if room_option == 'c':
        room_name = input("Room name: ").strip()
        try:
            resp = await client.room_create(name=room_name)
            if isinstance(resp, RoomCreateResponse):
                current_room_id = resp.room_id
                config['room_id'] = current_room_id
                save_config(config)
                print(f"Created room: {current_room_id}")
            else:
                print(f"Failed to create room: {resp}")
        except Exception as e:
            print(f"Error creating room: {e}")
    else:
        room_id_or_alias = input("Room ID or alias (e.g., #room:matrix.org): ").strip()
        try:
            resp = await client.join(room_id_or_alias)
            if isinstance(resp, JoinResponse):
                current_room_id = resp.room_id
                config['room_id'] = current_room_id
                save_config(config)
                print(f"Joined room: {current_room_id}")
            else:
                print(f"Failed to join room: {resp}")
        except Exception as e:
            print(f"Error joining room: {e}")

async def view_room_messages():
    global current_room_id
    
    if not current_room_id:
        print("No room configured. Please set up a room first.")
        return
    
    try:
        messages_response = await client.room_messages(
            current_room_id,
            limit=20
        )
        
        if not hasattr(messages_response, 'chunk'):
            print("Failed to retrieve messages from the room.")
            return
        
        chunk = messages_response.chunk
        if not chunk:
            print("No recent messages in the room.")
            return
        
        print(f"\nRecent messages in room {current_room_id}:")
        print("=" * 60)
        
        for event in reversed(chunk):
            if (hasattr(event, 'content') and 
                hasattr(event.content, 'body') and 
                hasattr(event, 'sender')):
                
                if hasattr(event, 'type') and event.type == 'm.room.message':
                    timestamp = getattr(event, 'origin_server_ts', 0)
                    if timestamp:
                        from datetime import datetime
                        dt = datetime.fromtimestamp(timestamp / 1000)
                        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        time_str = "Unknown time"
                    
                    body = event.content.body
                    if body.startswith("ENC:"):
                        ciphertext = body[4:]
                        passphrase = user_keys.get(event.sender)
                        if passphrase:
                            try:
                                decrypted = medieval_cipher_decr(ciphertext, passphrase)
                                print(f"[{time_str}] {event.sender}: {decrypted} (decrypted)")
                            except Exception as e:
                                print(f"[{time_str}] {event.sender}: {body} (decryption failed: {e})")
                        else:
                            print(f"[{time_str}] {event.sender}: {body} (encrypted, no passphrase available)")
                    else:
                        print(f"[{time_str}] {event.sender}: {body}")
        
        print("=" * 60)
            
    except Exception as e:
        print(f"Error viewing room messages: {e}")
        import traceback
        traceback.print_exc()

async def decrypt_room_messages():
    global current_room_id
    
    if not current_room_id:
        print("No room configured. Please set up a room first.")
        return
    
    try:
        messages_response = await client.room_messages(
            current_room_id,
            limit=20
        )
        
        if not hasattr(messages_response, 'chunk'):
            print("Failed to retrieve messages from the room.")
            return
        
        chunk = messages_response.chunk
        if not chunk:
            print("No recent messages in the room.")
            return
        
        print(f"\nRecent messages in room {current_room_id} (with decryption):")
        print("=" * 60)
        
        processed_senders = set()
        
        for event in reversed(chunk):
            if (hasattr(event, 'content') and 
                hasattr(event.content, 'body') and 
                hasattr(event, 'sender')):
                
                if hasattr(event, 'type') and event.type == 'm.room.message':
                    timestamp = getattr(event, 'origin_server_ts', 0)
                    if timestamp:
                        from datetime import datetime
                        dt = datetime.fromtimestamp(timestamp / 1000)
                        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        time_str = "Unknown time"
                    
                    body = event.content.body
                    if body.startswith("ENC:"):
                        ciphertext = body[4:]
                        sender = event.sender
                        
                        if sender not in user_keys and sender not in processed_senders:
                            print(f"Encrypted message from {sender}: {body}")
                            passphrase = input(f"Enter passphrase for {sender} (or press Enter to skip): ").strip()
                            if passphrase:
                                user_keys[sender] = passphrase
                            processed_senders.add(sender)
                        
                        passphrase = user_keys.get(sender)
                        if passphrase:
                            try:
                                decrypted = medieval_cipher_decr(ciphertext, passphrase)
                                print(f"[{time_str}] {sender}: {decrypted} (decrypted)")
                            except Exception as e:
                                print(f"[{time_str}] {sender}: {body} (decryption failed: {e})")
                        else:
                            print(f"[{time_str}] {sender}: {body} (encrypted, no passphrase available)")
                    else:
                        print(f"[{time_str}] {event.sender}: {body}")
        
        print("=" * 60)
            
    except Exception as e:
        print(f"Error decrypting room messages: {e}")
        import traceback
        traceback.print_exc()

async def message_callback(room: MatrixRoom, event: RoomMessageText):
    """Handle incoming messages in real-time"""
    try:
        if event.body.startswith("ENC:"):
            ciphertext = event.body[4:]
            user_id = event.sender
            
            if user_id in user_keys:
                passphrase = user_keys[user_id]
                try:
                    decrypted = medieval_cipher_decr(ciphertext, passphrase)
                    print(f"\n🔓 Decrypted message from {user_id}: {decrypted}")
                except Exception as e:
                    print(f"\n⚠️  Failed to decrypt message from {user_id}: {e}")
            else:
                print(f"\n⚠️  Received encrypted message from {user_id}, but no passphrase available")
                print(f"Encrypted: {ciphertext}")
        else:
            print(f"\n📨 Message from {event.sender}: {event.body}")
    except Exception as e:
        logger.error(f"Error processing message: {e}")

async def start_sync():
    """Start syncing with the Matrix server"""
    if client:
        client.add_event_callback(message_callback, RoomMessageText)
        try:
            while True:
                await client.sync(timeout=30000, full_state=False)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"Sync error: {e}")

async def send_encrypted_message(message, passphrase):
    """Encrypt and send a message using Medieval Cipher"""
    global current_room_id
    
    if not current_room_id:
        print("No room configured. Please set up a room first.")
        return False
    
    try:
        encrypted = medieval_cipher_encr(message, passphrase)
        resp = await client.room_send(
            room_id=current_room_id,
            message_type="m.room.message",
            content={
                "msgtype": "m.text",
                "body": f"ENC:{encrypted}"
            }
        )
        if hasattr(resp, 'event_id') and resp.event_id:
            print("✅ Encrypted message sent successfully")
            return True
        else:
            print(f"Send failed: {resp}")
            return False
    except Exception as e:
        logger.error(f"Failed to send message: {e}")
        return False

async def main_loop():
    global current_room_id
    
    if not await setup_client():
        print("Failed to set up client. Exiting.")
        return
    
    config = load_config()
    if not current_room_id and config.get('room_id'):
        current_room_id = config['room_id']
    
    asyncio.create_task(start_sync())
    
    await client.sync(full_state=True)
    
    while True:
        print("\n" + "="*50)
        print("Medieval Cipher Encrypted Matrix Messenger")
        print("="*50)
        print(f"User: {client.user_id if client and client.user_id else 'Not set'}")
        print(f"Room: {current_room_id or 'Not set'}")
        print("="*50)
        print("Options:")
        print("1. Set passphrase for a user")
        print("2. Send encrypted message")
        print("3. Change room")
        print("4. Reconfigure client")
        print("5. View room messages")
        print("6. Decrypt messages from room")
        print("7. Exit")
        
        try:
            choice = input("Choose an option: ").strip()
            
            if choice == "1":
                user_id = input("Enter user ID (e.g., @user:matrix.org): ").strip()
                passphrase = input("Enter passphrase: ").strip()
                if user_id and passphrase:
                    user_keys[user_id] = passphrase
                    print(f"Passphrase set for {user_id}")
                else:
                    print("User ID and passphrase cannot be empty.")
                    
            elif choice == "2":
                if not user_keys:
                    print("No passphrases set. Please set a passphrase first.")
                    continue
                    
                if not current_room_id:
                    print("No room configured. Please set up a room first.")
                    continue
                
                print("Available users:")
                for i, uid in enumerate(user_keys.keys(), 1):
                    print(f"{i}. {uid}")
                try:
                    sel = int(input("Select user to send to (number): ")) - 1
                    users_list = list(user_keys.items())
                    if 0 <= sel < len(users_list):
                        selected_user_id, passphrase = users_list[sel]
                        message = input("Enter message to encrypt and send: ").strip()
                        if message:
                            await send_encrypted_message(message, passphrase)
                            print(f"Encrypted and sent using passphrase for {selected_user_id}.")
                        else:
                            print("Message cannot be empty.")
                    else:
                        print("Invalid selection.")
                except ValueError:
                    print("Invalid input. Please enter a number.")
                
            elif choice == "3":
                await setup_room(load_config())
                
            elif choice == "4":
                if await setup_client():
                    config = load_config()
                    if config.get('room_id'):
                        current_room_id = config['room_id']
                    asyncio.create_task(start_sync())
            
            elif choice == "5":
                await view_room_messages()
            
            elif choice == "6":
                await decrypt_room_messages()
                
            elif choice == "7":
                print("Exiting...")
                if client:
                    await client.close()
                break
                
            else:
                print("Invalid option. Please choose 1-7.")
                
        except KeyboardInterrupt:
            print("\nExiting...")
            if client:
                await client.close()
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        if client:
            asyncio.run(client.close())