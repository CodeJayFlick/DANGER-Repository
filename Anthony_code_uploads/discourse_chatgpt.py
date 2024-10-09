import requests

# Function to create a post (topic)
def create_post(api_key, api_username, base_url, title, raw_content, category_id):
    url = f'{base_url}/posts.json'
    
    headers = {
        'Api-Key': api_key,
        'Api-Username': api_username
    }
    
    data = {
        'title': title,
        'raw': raw_content,
        'category': category_id
    }
    
    response = requests.post(url, headers=headers, data=data)
    
    if response.status_code == 200:
        return response.json()
    else:
        return response.status_code, response.text

# Function to lock a topic
def lock_topic(api_key, api_username, base_url, topic_id):
    url = f'{base_url}/t/{topic_id}/status'
    
    headers = {
        'Api-Key': api_key,
        'Api-Username': api_username
    }
    
    data = {
        'status': 'closed',
        'enabled': True
    }
    
    response = requests.put(url, headers=headers, json=data)
    
    if response.status_code == 200:
        return response.json()
    else:
        return response.status_code, response.text

# Function to unlock a topic
def unlock_topic(api_key, api_username, base_url, topic_id):
    url = f'{base_url}/t/{topic_id}/status'
    
    headers = {
        'Api-Key': api_key,
        'Api-Username': api_username
    }
    
    data = {
        'status': 'closed',
        'enabled': False
    }
    
    response = requests.put(url, headers=headers, json=data)
    
    if response.status_code == 200:
        return response.json()
    else:
        return response.status_code, response.text

# Function to pin a topic
def pin_topic(api_key, api_username, base_url, topic_id):
    url = f'{base_url}/t/{topic_id}/pin'
    
    headers = {
        'Api-Key': api_key,
        'Api-Username': api_username
    }
    
    data = {
        'status': 'pinned',
        'enabled': True
    }
    
    response = requests.put(url, headers=headers, json=data)
    
    if response.status_code == 200:
        return response.json()
    else:
        return response.status_code, response.text

# Function to unpin a topic
def unpin_topic(api_key, api_username, base_url, topic_id):
    url = f'{base_url}/t/{topic_id}/pin'
    
    headers = {
        'Api-Key': api_key,
        'Api-Username': api_username
    }
    
    data = {
        'status': 'pinned',
        'enabled': False
    }
    
    response = requests.put(url, headers=headers, json=data)
    
    if response.status_code == 200:
        return response.json()
    else:
        return response.status_code, response.text

# Function to delete a post
def delete_post(api_key, api_username, base_url, post_id):
    url = f'{base_url}/posts/{post_id}.json'
    
    headers = {
        'Api-Key': api_key,
        'Api-Username': api_username
    }
    
    response = requests.delete(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        return response.status_code, response.text

