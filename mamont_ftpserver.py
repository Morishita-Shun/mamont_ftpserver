import sys
import os
import socket
import urllib.request
import requests
from bs4 import BeautifulSoup
import datetime
import ipaddress

DATA_PATH = "/Users/user/Desktop/"
URL = "http://www.mmnt.net/"
INDEX_NUM = 49  # until /index.NUM.html
HEADERS = {
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0",
        }

MINIMUM_FILE_NUM = 100  
# If a server don't have many uploaded files,
# we don't count the server as a ftp server.

def foward_lookup(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return False

def is_ipaddress(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def main():
    today = str(datetime.date.today())
    save_path = DATA_PATH + today + "/"
    if not os.path.exists(save_path):
        os.mkdir(save_path)
    else:
        print(save_path + " : Already exist.")
        sys.exit()
    host_list = save_path + "host-list.txt"  # maybe include Dionaea honeypot
    ftpserver_list = save_path + "ftpserver-list.txt"
    total_file_list = save_path + "total-file-list.txt"
    ip_ftpserver_list = save_path + "ip-ftpserver-list.txt"
    lookup_list = save_path + "lookup-list.txt"
    ip_uniq_ftpserver_list = save_path + "ip-uniq-ftpserver-list.txt"

    # get host_list
    for index in range(INDEX_NUM + 1):
        index_url = ""
        if index == 0:
            index_url = URL
        else:
            index_url = URL + "index." + str(index) + ".html"
        
        print("get host_list: " + index_url)
        try:
            request = urllib.request.Request(index_url, headers=HEADERS)
            html = urllib.request.urlopen(request).read()

            soup = BeautifulSoup(html, "lxml")
            a_tags = soup.find_all("a")
            for a_tag in a_tags:
                host = a_tag.get("href")
                if "db/0/0/" in host:
                    host = host.replace("/db/0/0/", "")
                    with open(host_list, "a") as f:
                        f.write(host + "\n")
        except:
            print("Error: " + index_url)

    # extract ftpserver_list
    hosts = []
    with open(host_list, "r") as f:
        hosts = f.readlines()
    for host in hosts:
        host = host.strip()
        host_url = URL + "db/0/0/" + host
        
        print("extract ftpserver_list: " + host_url)
        try:
            request = urllib.request.Request(host_url, headers=HEADERS)
            html = urllib.request.urlopen(request).read()

            soup = BeautifulSoup(html, "lxml")
            pre_tag = soup.find("pre")
            lines = str(pre_tag).split("\n")
            total_file = 0
            for line in lines:
                if "Total files found:" in line:
                    total_file = int(line.strip().split(": ")[1].replace(",", ""))
                    break

            if total_file >= MINIMUM_FILE_NUM:
                with open(ftpserver_list, "a") as f:
                    f.write(host + "\n")
            with open(total_file_list, "a") as f:
                f.write(str(total_file) + ", " + host + "\n")
        except:
            print("Error: " + host_url)

    # resolve ip_ftpserver_list
    hosts = []
    with open(ftpserver_list, "r") as f:
        hosts = f.readlines()
    for host in hosts:
        host = host.strip()
        ip = ""
        if is_ipaddress(host):
            ip = host
        else:
            print("resolve ip_ftpserver_list: " + host)
            ip = foward_lookup(host)
            with open(lookup_list, "a") as f:
                f.write(str(ip) + ", " + host)
            if ip == False:
                continue
        with open(ip_ftpserver_list, "a") as f:
            f.write(ip + "\n")

    # create ip_uniq_ftpserver_list
    command = "awk '!a[$0]++' " + ip_ftpserver_list + " > " + ip_uniq_ftpserver_list
    os.system(command)            


if __name__ == "__main__":
    main()
