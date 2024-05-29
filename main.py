import json
import datetime
import requests
from fastapi import FastAPI, Request, HTTPException
import hashlib
import hmac
from time import time

import uvicorn
import os
import jwt
from fastapi.responses import HTMLResponse, RedirectResponse

from dotenv import load_dotenv

load_dotenv()

import mysql.connector
from mysql.connector import Error

db_password = os.environ.get("DB_PASSWORD")
db_name = os.environ.get("DB_NAME")

app = FastAPI(debug=True, trust_env=True)

# class SignatureVerifier:
#     def __init__(self, signing_key: str, max_delay: int = 60 * 5, secret_version: str = "s0="):
#         self.signing_key = signing_key.encode()
#         self.max_delay = max_delay
#         self.secret_version = secret_version
#
#     def is_valid(self, body: str, timestamp: str | None, signature: str | None) -> bool:
#         if None in [timestamp, signature]:
#             return False
#
#         if self._is_timestamp_valid(timestamp):
#             calculated_signature: str = self._generate_signature(body, timestamp)
#             return hmac.compare_digest(calculated_signature, signature)
#         return False
#
#     def _is_timestamp_valid(self, timestamp: str) -> bool:
#         return abs(time() - int(timestamp)) <= self.max_delay
#
#     def _generate_signature(self, body: str, timestamp: str) -> str:
#         base_string = f"swit:{timestamp}:{body}"
#         signature = hmac.new(self.signing_key, base_string.encode(), hashlib.sha256)
#         return self.secret_version + signature.hexdigest()
#
# signing_key = os.environ.get("SWIT_SIGNING_KEY")
# signature_verifier = SignatureVerifier(signing_key)

signing_key = os.environ.get("SWIT_SIGNING_KEY").encode()
max_delay = 60 * 5  # 5 minutes
secret_version = "s0="


def is_valid(body: str, timestamp: str | None, signature: str | None) -> bool:
    if None in [timestamp, signature]:
        return False

    if _is_timestamp_valid(timestamp):
        calculated_signature: str = _generate_signature(body, timestamp)
        return hmac.compare_digest(calculated_signature, signature)
    return False


def _is_timestamp_valid(timestamp: str) -> bool:
    return abs(time() - int(timestamp)) <= max_delay


def _generate_signature(body: str, timestamp: str) -> str:
    base_string = f"swit:{timestamp}:{body}"
    signature = hmac.new(signing_key, base_string.encode(), hashlib.sha256)
    return secret_version + signature.hexdigest()


def create_db_connection():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password=db_password,
            database=db_name
        )
        return connection
    except Error as e:
        print(f"The error '{e}' occurred")
        return None


def create_table():
    connection = None
    try:
        connection = create_db_connection()
        if connection is not None:
            with connection.cursor() as cursor:
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS userdata (
                    id INT AUTO_INCREMENT PRIMARY KEY, 
                    swit_id VARCHAR(255), 
                    asana_id VARCHAR(255), 
                    asana_token TEXT, 
                    asana_refresh_token VARCHAR(255),
                    swit_token TEXT,
                    swit_refresh_token VARCHAR(255)
                )""")
            connection.commit()
    except Exception as e:
        print(f"Failed to create table: {e}")
    finally:
        if connection and connection.is_connected():
            connection.close()


def fetch_asana_token_from_db(user_id):
    db_connection = create_db_connection()
    if db_connection is None:
        print("Database connection error")
        return None

    try:
        with db_connection.cursor(buffered=True) as cursor:
            cursor.execute("SELECT asana_token FROM userdata WHERE swit_id = %s", (user_id,))
            result = cursor.fetchone()
            return result[0] if result else None
    except Error as e:
        print(f"Database query error: {e}")
        return None
    finally:
        if db_connection.is_connected():
            db_connection.close()


def fetch_swit_token_from_db(user_id):
    db_connection = create_db_connection()
    if db_connection is None:
        print("Database connection error")
        return None

    try:
        with db_connection.cursor(buffered=True) as cursor:
            cursor.execute("SELECT swit_token FROM userdata WHERE swit_id = %s", (user_id,))
            result = cursor.fetchone()
            return result[0] if result else None
    except Error as e:
        print(f"Database query error: {e}")
        return None
    finally:
        if db_connection.is_connected():
            db_connection.close()


swit_app_id = os.environ.get("SWIT_APP_ID")
swit_client_id = os.environ.get("SWIT_CLIENT_ID")
swit_client_secret = os.environ.get("SWIT_CLIENT_SECRET")
redirect_uri = os.environ.get("SWIT_REDIRECT_URI")
asana_redirect_uri = os.environ.get("ASANA_REDIRECT_URI")
asana_client_id = os.environ.get("ASANA_CLIENT_ID")
asana_client_secret = os.environ.get("ASANA_CLIENT_SECRET")
swit_api_url = os.environ.get("SWIT_API_URL")


@app.get("/")
async def root():
    return "API is running"


@app.get("/app_install")
async def app_install(app_name):
    if app_name == "asana_sarah":
        state = "hello"
        scope = "app:install+channel:write+channel:read+message:read+message:write+message:read+project:read+project:write+task:read+task:write"
        swit_authorize_url = swit_api_url + "oauth/authorize"
        install_url = f"{swit_authorize_url}?client_id={swit_client_id}&redirect_uri={redirect_uri}&response_type=code&state={state}&scope={scope}"
        return RedirectResponse(url=install_url)


def initiate_oauth_flow(user_id: str, action: str, user_language: str, channel_id: str):
    state = f"{user_id}:{action}:{user_language}:{channel_id}"
    scope = "app:install+channel:write+channel:read+message:read+message:write+message:read+project:read+project:write+task:read+task:write"
    swit_authorize_url = swit_api_url + "oauth/authorize"
    oauth_url = f"{swit_authorize_url}?client_id={swit_client_id}&redirect_uri={redirect_uri}&response_type=code&state={state}&scope={scope}"
    # oauth_url = "https://urt.swit.fun/sarah/app_install?app_name=asana_sarah&user_id=" + user_id
    return {
        "callback_type": "views.open",
        "new_view": {
            "view_id": "builder_test",
            "state": action + ":" + channel_id,
            "header": {
                "title": "Connect to Asana",
                "buttons": [
                    {
                        "type": "button",
                        "icon": {
                            "type": "image",
                            "image_url": "./assets/builder_logo.png",
                            "alt": "Header button icon"
                        },
                        "static_action": {
                            "action_type": "open_link",
                            "link_url": "https://swit.io"
                        }
                    }
                ]
            },
            "body": {
                "elements": [
                    {
                        "type": "sign_in_page",
                        "title": "Try Asana for Swit",
                        "description": "Sign in to start using Asana in Swit.",
                        "button": {
                            "type": "button",
                            "label": "Sign in",
                            "action_id": "asana_oauth_button",
                            "static_action": {
                                "action_type": "open_oauth_popup",
                                "link_url": oauth_url
                            }
                        },
                        "integrated_service": {
                            "icon": {
                                "type": "image",
                                "image_url": "https://files.swit.io/data/assets/apps/23092108333670VJ6MRS/23103004371942AFKL5P.jpg"
                            }
                        }
                    }
                ]
            }
        }
    }


# def get_token_from_file(token_lifetime_in_seconds=0, token_type="swit_token"):
#     file_path = "token.json"
#
#     if not os.path.exists(file_path):
#         # If the token file does not exist, return None
#         return None
#     with open(file_path, "r") as f:
#         token_data = json.load(f)
#
#     swit_token = token_data['access_token']
#
#     return swit_token
#
#
#
#     # Examines the expiration time of the access token
#     access_token_parsed = jwt.decode(token, options={"verify_signature": False})
#     exp = access_token_parsed['exp']
#     if is_timestamp_earlier_than_future(exp, token_lifetime_in_seconds):
#         return token + "invalid"
#     else:
#         return token
#
#
# def is_timestamp_earlier_than_future(timestamp, token_lifetime_in_seconds):
#     # Convert the provided timestamp to a datetime object
#     provided_time = datetime.datetime.fromtimestamp(int(timestamp))
#     future_time = datetime.datetime.now() + datetime.timedelta(days=7, seconds=(token_lifetime_in_seconds * -1))
#
#     # Check if the provided time is earlier than the future time
#     return provided_time < future_time


@app.get("/oauth")
async def oauth(code, state):
    swit_code = code
    swit_token_url = swit_api_url + "oauth/token"
    swit_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    swit_payload = {
        "grant_type": "authorization_code",
        "client_id": swit_client_id,
        "client_secret": swit_client_secret,
        "redirect_uri": redirect_uri,
        "code": swit_code
    }
    swit_response = requests.post(swit_token_url, headers=swit_headers, data=swit_payload)

    if not swit_response.ok:
        print("Failed to obtain access token. Status code:", swit_response.status_code)
        print("Response:", swit_response.text)
        return {"error": "Failed to obtain access token"}

    if state == "hello":
        html_content = """
                                   <html>
                                       <body>
                                           <script>
                                               window.close();
                                           </script>
                                       </body>
                                   </html>
                                   """
        return HTMLResponse(content=html_content)

    try:
        user_id, action, user_language, channel_id = state.split(":")
        response_json = swit_response.json()
        swit_token = response_json['access_token']
        swit_refresh_token = response_json.get('refresh_token', '')

        # Store swit_token in the database
        db_connection = create_db_connection()
        if db_connection is None:
            return {"error": "Database connection error"}

        try:
            query = """
                                INSERT INTO userdata (swit_id, swit_token, swit_refresh_token) 
                                VALUES (%s, %s, %s) 
                                ON DUPLICATE KEY UPDATE 
                                swit_token = VALUES(swit_token), 
                                swit_refresh_token = VALUES(swit_refresh_token)
                            """
            values = (user_id, swit_token, swit_refresh_token)

            with db_connection.cursor() as cursor:
                cursor.execute(query, values)
                db_connection.commit()
        except Error as e:
            print(f"Database error: {e}")
            return {"error": "Database operation failed"}
        finally:
            if db_connection and db_connection.is_connected():
                db_connection.close()

            asana_authorize_url = "https://app.asana.com/-/oauth_authorize"
            asana_oauth_url = f"{asana_authorize_url}?client_id={asana_client_id}&redirect_uri={asana_redirect_uri}&response_type=code&state={state}&scope=default"
            return RedirectResponse(url=asana_oauth_url)
    except Exception as e:
        print(f"General error: {e}")
        return {"error": "General error"}


@app.get("/asana_oauth")
async def asana_oauth(code, state):
    user_id, action, user_language, channel_id = state.split(":")
    asana_token_url = "https://app.asana.com/-/oauth_token"
    asana_payload = {
        "grant_type": "authorization_code",
        "client_id": asana_client_id,
        "client_secret": asana_client_secret,
        "redirect_uri": asana_redirect_uri,
        "code": code
    }
    asana_response = requests.post(asana_token_url, data=asana_payload)

    if asana_response.ok:
        asana_token_data = asana_response.json()
        asana_token = asana_token_data['access_token']
        asana_refresh_token = asana_token_data['refresh_token']
        asana_id = asana_token_data['data']['gid']

        db_connection = create_db_connection()
        if db_connection is None:
            return {"error": "Database connection error"}

        try:
            query = """
                               UPDATE userdata SET
                               asana_id = %s, 
                               asana_token = %s, 
                               asana_refresh_token = %s
                               WHERE swit_id = %s
                           """
            values = (asana_id, asana_token, asana_refresh_token, user_id)
            with db_connection.cursor() as cursor:
                cursor.execute(query, values)
                db_connection.commit()

        except Error as e:
            print(f"Database error: {e}")
            return {"error": "Database operation failed"}

        finally:
            if db_connection and db_connection.is_connected():
                db_connection.close()

        swit_token = fetch_swit_token_from_db(user_id)

        if action == 'asana_help':
            await help_message(user_id, user_language, channel_id, swit_token)
            html_content = """
                           <html>
                               <body>
                                   <script>
                                       window.close();
                                   </script>
                               </body>
                           </html>
                           """
            return HTMLResponse(content=html_content)
        elif action == 'asana_create':
            await create_task(user_id, channel_id, asana_token, pre_filled_message=None)
            html_content = """
                            <html>
                                <body>
                                    <script>
                                        window.close();
                                    </script>
                                </body>
                            </html>
                            """
            return HTMLResponse(content=html_content)
    else:
        print("Failed to obtain Asana token. Status code:", asana_response.status_code)
        print("Response:", asana_response.text)
        return {"error": "Failed to obtain Asana token"}


async def refresh_swit_token(user_id):
    db_connection = None
    try:
        db_connection = create_db_connection()
        if db_connection is None:
            raise Exception("Database connection could not be established")

        with db_connection.cursor() as cursor:
            cursor.execute("SELECT swit_refresh_token FROM userdata WHERE swit_id = %s", (user_id,))
            result = cursor.fetchone()
            if not result:
                raise Exception(f"No Swit refresh token found for user: {user_id}")
            swit_refresh_token = result[0]

            token_url = swit_api_url + "oauth/token"
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            payload = {
                "grant_type": "refresh_token",
                "client_id": swit_client_id,
                "client_secret": swit_client_secret,
                "refresh_token": swit_refresh_token
            }

            response = requests.post(token_url, headers=headers, data=payload)

            if response.ok:
                new_token_info = response.json()
                new_swit_token = new_token_info['access_token']
                new_swit_refresh_token = new_token_info['refresh_token']

                update_query = """
                                UPDATE userdata SET
                                swit_token = %s, 
                                swit_refresh_token = %s
                                WHERE swit_id = %s
                            """
                update_values = (new_swit_token, new_swit_refresh_token, user_id)
                cursor.execute(update_query, update_values)
                db_connection.commit()
                print("Token refreshed successfully")
                return new_swit_token
            else:
                print("Failed to refresh token. Status code:", response.status_code)
                return False
    except mysql.connector.Error as e:
        print(f"Database error: {e}")
        return False
    except Exception as e:
        print(f"General error: {e}")
        return False
    finally:
        if isinstance(db_connection, mysql.connector.connection.MySQLConnection):
            if db_connection.is_connected():
                db_connection.close()


async def refresh_asana_token(user_id):
    db_connection = None
    try:
        db_connection = create_db_connection()
        if db_connection is None:
            raise Exception("Database connection could not be established")

        with db_connection.cursor() as cursor:
            cursor.execute("SELECT asana_refresh_token FROM userdata WHERE swit_id = %s", (user_id,))
            result = cursor.fetchone()
            if not result:
                raise Exception(f"No Asana refresh token found for user: {user_id}")
            asana_refresh_token = result[0]

            token_url = "https://app.asana.com/-/oauth_token"
            payload = {
                "grant_type": "refresh_token",
                "client_id": asana_client_id,
                "client_secret": asana_client_secret,
                "refresh_token": asana_refresh_token
            }

            response = requests.post(token_url, data=payload)

            if response.ok:
                new_token_info = response.json()
                new_asana_token = new_token_info['access_token']
                new_asana_refresh_token = new_token_info.get('refresh_token', asana_refresh_token)

                update_query = """
                                UPDATE userdata SET
                                asana_token = %s, 
                                asana_refresh_token = %s
                                WHERE swit_id = %s
                            """
                update_values = (new_asana_token, new_asana_refresh_token, user_id)
                cursor.execute(update_query, update_values)
                db_connection.commit()
                return new_asana_token
            else:
                print("Failed to refresh Asana token. Status code:", response.status_code)
                return False
    except mysql.connector.Error as e:
        print(f"Database error: {e}")
        return False
    except Exception as e:
        print(f"General error: {e}")
        return False
    finally:
        if isinstance(db_connection, mysql.connector.connection.MySQLConnection):
            if db_connection.is_connected():
                db_connection.close()


async def help_message(user_id, user_language, channel_id, swit_token):
    help_content = ""
    if user_language == 'ko':
        help_content = "{\"type\":\"rich_text\",\"elements\":[{\"type\":\"rt_section\",\"elements\":[{\"type\":\"rt_mention\",\"user_id\":\"" + user_id + "\"},{\"type\":\"rt_text\",\"content\":\" 안녕하세요. Swit에서 Asana앱을 사용하여 업무를 관리해 보세요.\\n\"},{\"type\":\"rt_text\",\"content\":\"사용 가능한 커맨드\",\"styles\":{\"bold\":true}}]},{\"type\":\"rt_blockquote\",\"elements\":[{\"type\":\"rt_text\",\"content\":\"/asana_create\",\"styles\":{\"code\":true}},{\"type\":\"rt_text\",\"content\":\" 새 업무 생성.\\n\"},{\"type\":\"rt_text\",\"content\":\"/asana_link\",\"styles\":{\"code\":true}},{\"type\":\"rt_text\",\"content\":\" 아사나 링크.\\n\"},{\"type\":\"rt_text\",\"content\":\"/asana_settings\",\"styles\":{\"code\":true}},{\"type\":\"rt_text\",\"content\":\" 설정 보기.\\n\"},{\"type\":\"rt_text\",\"content\":\"/asana_help\",\"styles\":{\"code\":true}},{\"type\":\"rt_text\",\"content\":\" 도움말.\"}]},{\"type\":\"rt_section\",\"elements\":[{\"type\":\"rt_text\",\"content\":\"문의\",\"styles\":{\"bold\":true}}]},{\"type\":\"rt_blockquote\",\"elements\":[{\"type\":\"rt_link\",\"content\":\"문의 링크\",\"url\":\"https://help.swit.io/?support=true\"}]}]}"
    elif user_language == 'en':
        help_content = "{\"type\":\"rich_text\",\"elements\":[{\"type\":\"rt_section\",\"elements\":[{\"type\":\"rt_text\",\"content\":\"Hello \"},{\"type\":\"rt_mention\",\"user_id\":\"" + user_id + "\"},{\"type\":\"rt_text\",\"content\":\", here are some ways you can use Asana for Swit to manage your work.\\n\"},{\"type\":\"rt_text\",\"content\":\"Available commands\",\"styles\":{\"bold\":true}}]},{\"type\":\"rt_blockquote\",\"elements\":[{\"type\":\"rt_text\",\"content\":\"Use \"},{\"type\":\"rt_text\",\"content\":\"/asana_create\",\"styles\":{\"code\":true}},{\"type\":\"rt_text\",\"content\":\" to create a new task. You can add text after the command to pre-fill the task name.\\nUse \"},{\"type\":\"rt_text\",\"content\":\"/asana_link\",\"styles\":{\"code\":true}},{\"type\":\"rt_text\",\"content\":\" in a channel to manage the channel’s linked project notifications or to link a new project.\\nUse \"},{\"type\":\"rt_text\",\"content\":\"/asana_settings\",\"styles\":{\"code\":true}},{\"type\":\"rt_text\",\"content\":\" to manage your personal notifications settings and default Asana domain.\\nUse \"},{\"type\":\"rt_text\",\"content\":\"/asana_help\",\"styles\":{\"code\":true}},{\"type\":\"rt_text\",\"content\":\" to see this message again.\"}]},{\"type\":\"rt_section\",\"elements\":[{\"type\":\"rt_text\",\"content\":\"Support\",\"styles\":{\"bold\":true}}]},{\"type\":\"rt_blockquote\",\"elements\":[{\"type\":\"rt_link\",\"content\":\"Contact us\",\"url\":\"https://help.swit.io/?support=true\"},{\"type\":\"rt_text\",\"content\":\".\"}]}]}"

    url = swit_api_url + "v1/api/message.create"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {swit_token}"
    }
    body = {
        "channel_id": channel_id,
        "content": help_content,
        "body_type": "json_string"
    }

    response = requests.post(url=url, headers=headers, json=body)
    print(response.text)
    # if response.status_code == 401:
    #     # Token refresh
    #     swit_new_token = await refresh_swit_token(user_id)
    #     if swit_new_token:
    #         await help_message(user_id, user_language, channel_id, swit_new_token)
    #     else:
    #         return initiate_oauth_flow(user_id, "asana_help", user_language, channel_id)
    #
    # else:
    #     return {
    #         "callback_type": "views.close"
    #     }


async def create_task(user_id, channel_id, asana_token, pre_filled_message):
    if not asana_token:
        print("No Asana token found for the user.")
        return None

    # Get project list
    url = "https://app.asana.com/api/1.0/projects"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": f"Bearer {asana_token}"
    }
    response = requests.get(url=url, headers=headers)

    if response.status_code == 401:
        # Token refresh
        asana_new_token = await refresh_asana_token(user_id)
        if asana_new_token:
            return await create_task(user_id, channel_id, asana_new_token, pre_filled_message)
        else:
            return initiate_oauth_flow(user_id, "asana_create", "ko", channel_id)

    projects = response.json()['data']
    print(json.dumps(projects, indent=2))

    # sarah_test = [
    #     {
    #         "label": project['name'],
    #         "action_id": project['gid']
    #     } for project in projects
    # ]

    sarah_test = []
    for project in projects:
        project_dict = {
            "label": project['name'],
            "action_id": project['gid']
        }
        sarah_test.append(project_dict)

    ## Get workspace member list
    workspace_url = "https://app.asana.com/api/1.0/users/me/workspace_memberships"

    workspace_headers = {
        "accept": "application/json",
        "authorization": f"Bearer {asana_token}"
    }

    response = requests.get(url=workspace_url, headers=workspace_headers)
    workspaces = response.json()['data']
    print(json.dumps(workspaces, indent=2))

    workspace_id = workspaces[0]['workspace']['gid']
    user_url = f"https://app.asana.com/api/1.0/workspaces/{workspace_id}/workspace_memberships"

    user_headers = {
        "accept": "application/json",
        "authorization": f"Bearer {asana_token}"
    }
    response = requests.get(url=user_url, headers=user_headers)

    members = response.json()['data']
    print(json.dumps(members, indent=2))

    assignee_test = [
        {
            "label": member['user']['name'],
            "action_id": member['user']['gid']
        } for member in members
    ]

    unassigned_option = {"label": "Unassigned", "value": "unassigned"}
    assignee_test.insert(0, unassigned_option)

    create_modal = {
        "callback_type": "views.open",
        "new_view": {
            "view_id": "asana_create_view",
            "state": channel_id,
            "header": {
                "title": "Create a new task",
                "subtitle": "in Asana",
                "buttons": [
                    {
                        "type": "button",
                        "icon": {
                            "type": "image",
                            "image_url": "./assets/builder_logo.png",
                            "alt": "Header button icon"
                        },
                        "static_action": {
                            "action_type": "open_link",
                            "link_url": "https://swit.io"
                        }
                    }
                ]
            },
            "body": {
                "elements": [
                    {
                        "type": "text",
                        "markdown": True,
                        "content": "**Task name**"
                    },
                    {
                        "type": "text_input",
                        "action_id": "asana_task_name",
                        "placeholder": "Write a task name",
                        "trigger_on_input": False
                    },
                    {
                        "type": "text",
                        "markdown": True,
                        "content": "**Task description**"
                    },
                    {
                        "type": "textarea",
                        "action_id": "task_description",
                        "placeholder": "Write a task description",
                        "value": pre_filled_message if pre_filled_message else None,
                        "height": "small",
                        "disabled": False
                    },
                    {
                        "type": "text",
                        "markdown": True,
                        "content": "**Assignee**"
                    },
                    {
                        "type": "select",
                        "options": assignee_test,
                        "placeholder": "Select an assignee",
                        "multiselect": False,
                        "trigger_on_input": False,
                        "query": {
                            "query_server": True,
                            "disabled": True,
                            "placeholder": "Search by member name",
                            "value": None,
                            "action_id": "asana_assignee_select"
                        },
                        "style": {
                            "variant": "outlined"
                        }
                    },
                    {
                        "type": "text",
                        "markdown": True,
                        "content": "**Project**"
                    },
                    {
                        "type": "select",
                        "placeholder": "Select a project",
                        "multiselect": False,
                        "trigger_on_input": False,
                        "options": sarah_test,
                        "style": {
                            "variant": "outlined"
                        }
                    },
                    {
                        "type": "text",
                        "markdown": True,
                        "content": "**Due date**"
                    },
                    {
                        "type": "datepicker",
                        "placeholder": "YYYY-MM-DD",
                        "action_id": "a60389c6-2517-4388-8f56-da1aaf9c7b28"
                    },
                    {
                        "type": "button",
                        "label": "Create",
                        "action_id": "asana_create_button",
                        "style": "primary_filled"
                    }
                ]
            }
        }
    }
    return create_modal


async def task_message(channel_id: str, asana_task_name: str, selected_project_id: str, selected_assignee_id: str,
                       due_date: str, user_id: str, swit_token: str, asana_token: str, task_description: str):
    if not asana_token:
        print("No Asana token found for the user.")
        return None
    asana_url = "https://app.asana.com/api/1.0/tasks"
    asana_headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": f"Bearer {asana_token}"
    }
    asana_body = {
        "data": {
            "projects": [selected_project_id] if selected_project_id else [],
            "name": asana_task_name,
            "assignee": selected_assignee_id if selected_assignee_id else None,
            "due_on": due_date if due_date else None,
            "notes": task_description if task_description else None
        }
    }

    create_response = requests.post(asana_url, json=asana_body, headers=asana_headers)

    bb = create_response.json()['data']
    print(json.dumps(bb, indent=2))

    if create_response.ok:

        task_id = bb['gid']
        task_url = f"https://app.asana.com/0/{selected_project_id}/{task_id}"
        selected_project_name = bb['projects'][0]['name']
        selected_assignee_name = bb['assignee']['name'] if bb['assignee'] else None
        result_content = {
            "type": "rich_text",
            "elements": [
                {
                    "type": "rt_section",
                    "elements": [
                        {"type": "rt_mention", "user_id": user_id},
                        {"type": "rt_text", "content": " You have successfully created a task in Asana!"},
                        {"type": "rt_emoji", "name": ":clap:"}
                    ]
                },
                {
                    "type": "rt_blockquote",
                    "elements": [
                        {"type": "rt_link", "url": task_url, "content": "View Task"},
                        {"type": "rt_text",
                         "content": f"\nTask name: {asana_task_name} \nProject: {selected_project_name} \nTask description: {task_description}"},
                        {"type": "rt_text",
                         "content": f"\nAssignee: {selected_assignee_name}" if selected_assignee_id else "\nAssignee: No assignee"},
                        {"type": "rt_text",
                         "content": f"\nDue date: {due_date}" if due_date else "\nDue date: No due date"}

                    ]
                }
            ]
        }
    else:
        result_content = {
            "type": "rich_text",
            "elements": [
                {
                    "type": "rt_section",
                    "elements": [
                        {"type": "rt_text", "content": "Failed to create task: "},
                        {"type": "rt_text", "content": " " + asana_task_name}
                    ]
                }
            ]
        }
    message_url = swit_api_url + "v1/api/message.create"
    message_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {swit_token}"
    }

    message_body = {
        "channel_id": channel_id,
        "content": json.dumps(result_content),
        "body_type": "json_string"
    }

    message_response = requests.post(url=message_url, headers=message_headers, json=message_body)
    cc = message_response.json()
    print(json.dumps(cc, indent=2))

    if message_response.status_code == 401:
        # Token refresh
        swit_new_token = await refresh_swit_token(user_id)
        if swit_new_token:
            return await task_message(channel_id, asana_task_name, selected_project_id, selected_assignee_id, due_date,
                                      user_id, swit_new_token)
        else:
            return initiate_oauth_flow(user_id, "asana_create", "ko", channel_id)
    else:
        return message_response.json()


async def new_task():
    newtask_modal = {
        "attachments": [
            {
                "body": {
                    "elements": [
                        {
                            "action_id": "sarahtest",
                            "items": [
                                {
                                    "label": "새로운 업무",
                                    "text": {
                                        "content": "**새 업무에 첨부**",
                                        "markdown": True,
                                        "type": "text"
                                    }
                                }
                            ],
                            "type": "info_card"
                        }
                    ]
                },
                "header": {
                    "app_id": swit_app_id,
                    "title": "새로운 태스크를 생성하고, Attachment를 추가합니다."
                },
                "state": "test state"
            }
        ],
        "destination_hint": {
            "workspace_id": "24012409543257ODXSGR",
            "project_id": "24012901343960R33NR9",
            "task_id": "24020106575334Q2G9UD"
        },
        "callback_type": "attachments.share.new_task"
    }

    return newtask_modal


async def existing_task():
    existingtask_modal = {
        "attachments": [
            {
                "body": {
                    "elements": [
                        {
                            "action_id": "sarahtest",
                            "items": [
                                {
                                    "label": "기존 업무",
                                    "text": {
                                        "content": "기존 업무에 첨부",
                                        "style": {},
                                        "type": "text"
                                    }
                                }
                            ],
                            "type": "info_card"
                        }
                    ]
                },
                "header": {
                    "app_id": swit_app_id,
                    "title": "기존 태스크에 Attachment를 추가합니다."
                },
                "state": "test state"
            }
        ],
        "destination_hint": {
            "workspace_id": "24012409543257ODXSGR",
            "project_id": "24012901343960R33NR9",
            "task_id": "24020106575334Q2G9UD"
        },
        "callback_type": "attachments.share.existing_task"
    }

    return existingtask_modal


@app.post("/app/asana22")
async def app_asana(asdf: Request):
    timestamp = asdf.headers.get("x-swit-request-timestamp")
    signature = asdf.headers.get("x-swit-signature")
    request_body = await asdf.body()
    request_body = request_body.decode()

    # if signature_verifier.is_valid(request_body, timestamp, signature):
    #     print("Valid signature")
    #
    # if not signature_verifier.is_valid(request_body, timestamp, signature):
    #     raise HTTPException(status_code=400, detail="Invalid signature")

    if is_valid(request_body, timestamp, signature):
        print("Valid signature")
    else:
        raise HTTPException(status_code=400, detail="Invalid signature")

    aaaa = await asdf.json()
    print(json.dumps(aaaa, indent=2))
    user_action_id = aaaa['user_action']['id']
    channel_id = aaaa['context']['channel_id']
    user_language = aaaa['user_preferences']['language']
    user_id = aaaa['user_info']['user_id']
    swit_token = fetch_swit_token_from_db(user_id)
    asana_token = fetch_asana_token_from_db(user_id)
    user_action_type = aaaa['user_action']['type']
    pre_filled_message = aaaa['user_action']['resource'][
        'content'] if user_action_type == "user_commands.context_menus:message" else None

    if not swit_token:
        return_value = initiate_oauth_flow(user_id, user_action_id, user_language, channel_id)
        print(return_value)
        return return_value
    else:
        if user_action_id == "asana_help":
            callback = await help_message(user_id, user_language, channel_id, swit_token)
            return callback
        elif user_action_id == "asana_create":
            callback = await create_task(user_id, channel_id, asana_token, pre_filled_message)
            return callback

        elif user_action_id == "new_task":
            callback = await new_task()
            return callback

        elif user_action_id == "existing_task":
            callback = await existing_task()
            return callback

        elif user_action_id == "asana_oauth_button":
            first_user_action, channel_id = aaaa['current_view']['state'].split(":")
            if first_user_action == 'asana_help':
                return await help_message(user_id, user_language, channel_id, swit_token)
            elif first_user_action == 'asana_create':
                return await create_task(user_id, channel_id, asana_token, pre_filled_message)

        elif user_action_id == "asana_create_button":
            asana_task_name = aaaa['current_view']['body']['elements'][1]['value']
            channel_id = aaaa['current_view']['state']
            selected_project_list = aaaa['current_view']['body']['elements'][7]['value']
            selected_project_id = selected_project_list[0] if selected_project_list else None
            selected_assignee_list = aaaa['current_view']['body']['elements'][5]['value']
            selected_assignee_id = selected_assignee_list[0] if selected_assignee_list else None
            due_date = aaaa['current_view']['body']['elements'][9]['value']
            task_description = aaaa['current_view']['body']['elements'][3]['value']

            await task_message(channel_id, asana_task_name, selected_project_id, selected_assignee_id, due_date,
                               user_id, swit_token, asana_token, task_description)

        return {
            "callback_type": "views.close"
        }


if __name__ == "__main__":
    create_table()
    uvicorn.run("main:app", host="localhost", port=8282, reload=True)
