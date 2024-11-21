import os
import requests

def get_file(url_str, user_agent):
    try:
        response = requests.get(url_str, headers={'User-Agent': user_agent})
        if response.status_code == 200:
            with open('write.pdb.deleteme', 'wb') as f:
                f.write(response.content)
            print("getFile completed: write.pdb.deleteme")
    except Exception as e:
        print(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    url_str = "http://msdl.microsoft.com/download/symbols/write.pdb/4FD8CA6696F445A7B969AB9BBD76E4591/write.pd_"
    user_agent = "Microsoft-Symbol-Server/6.3.9600.17298"

    home_dir = os.path.expanduser("~")
    file_path = f"{home_dir}/Downloads/write.pdb.deleteme"

    get_file(url_str, user_agent)
