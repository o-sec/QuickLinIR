#!/usr/bin/env python3

from bs4 import BeautifulSoup
from os import path, listdir
import importlib.metadata
import subprocess
import requests
import argparse
import psutil
import json
import pwd
import re 

# import configurations
try:
    from config import VIRUS_TOTAL_API_KEY
except ImportError:
    VIRUS_TOTAL_API_KEY = None



# colors
Y = "\033[93m"
R = "\033[91m"
W = "\033[97m"
G = "\033[32m"
B = "\033[96m"
P = "\033[7m"
Res = "\033[0m"



# startup scripts locations
SYSTEM_WIDE_STARTUP_LOCATIONS = [
"/etc/rc.local",
"/etc/init.d/",
"/etc/rc0.d/",
"/etc/rc1.d/",
"/etc/rc2.d/",
"/etc/rc3.d/",
"/etc/rc4.d/",
"/etc/rc5.d/",
"/etc/rc6.d/",
"/etc/systemd/system/",
"/run/systemd/system/",
"/usr/lib/systemd/system/",
"/lib/systemd/system/"
]
            
USER_SPECIFIC_STARTUP_SCRIPTS = [
".bashrc",
".profile",
".bash_profile",
".config/autostart/",
".zshrc"
]  


# network connections analyzer 
class NetworkAnalyzer():
    
    # list all listening ports 
    def getListeningServices(self) -> None:
        try:
            connections = psutil.net_connections(kind='inet')
            if not connections:
                return
                
            tcp = [connection for connection in connections if connection.type == 1 and connection.status == psutil.CONN_LISTEN]
            udp = [connection for connection in connections if  connection.type == 2 and connection.status == psutil.CONN_NONE]
            
            print(f"\n{P}{' ' * 40}Listening Services:{' ' * 40}{Res}\n")    
            
            if not tcp and not udp:
                print(f"{W}No Listening Services{Res}")
                return
            
            
            
            print(f"{'PROTOCOL':<10} {'LOCAL ADDRESS':<20} {'PID':<10} {'EXE':<25} {'USER'}")
            print("-" * 110)
            
            if tcp:
                for tcp_conn in tcp:
                    local_address = ':'.join(map(str,tcp_conn.laddr))
                    process_id = tcp_conn.pid
                    process_name = psutil.Process(tcp_conn.pid).name()
                    process_username = psutil.Process(tcp_conn.pid).username()
                       
                    print(f"{'TCP':<10} {local_address:<20} {process_id if process_id else 'N/A':<10} {process_name if process_name else 'N/A':<25} {process_username if process_username else 'N/A'}")
            if udp:        
                for udp_conn in udp:
                    local_address = ':'.join(map(str,udp_conn.laddr))
                    process_id = udp_conn.pid
                    process_name = psutil.Process(udp_conn.pid).name()
                    process_username = psutil.Process(udp_conn.pid).username()
                        
                    print(f"{'UDP':<10} {local_address:<20} {process_id if process_id else 'N/A':<10} {process_name if process_name else 'N/A':<25} {process_username if process_username else 'N/A'}")
              
                    
        

            
        except KeyboardInterrupt:
            print(f"{R}KeyboardInterrupt !{Res}")
            exit(1)

        except Exception as e:
            print(f"{R}An unexpected error occurred at function {B}getListeningServices(){Res}:\n {e}")
            return 
         
    
    # Retrieve ip information from https://bgp.he.net/ 
    def getIPInfo(self, ip: str) -> dict:
        try:
            ip_info = {}
            
            url = f"https://bgp.he.net/ip/{ip}"             
            response = requests.get(url)
        
        except requests.exceptions.Timeout:
            print(f"{R}Request timed out !{Res}")
            return
        except requests.exceptions.ConnectionError:
            print(f"{R}Could not connect to bgp.he.net{Res}")
            return
        except requests.exceptions.HTTPError as HTTPError:
            print(f"{R}HTTP Error: {str(HTTPError)}{Res}")
            return
            
        try:
            soup = BeautifulSoup(response.text,'html.parser')
            
            table_rows = soup.find('tbody').find_all('tr')
            
            counter = 0
            for row in table_rows:
                ip_info[f"row{counter}"] = {
                "ASN" : row.find('a').text , 
                "CIDR" : row.find('a', href=re.compile(r'^/net/')).text , 
                "DESCREPTION" : re.search(r'<td>[^<].*</td>', str(row)).group().replace('<td>','').replace('</td>','')
                }
                
                counter += 1
                  
            return ip_info
        
        except AttributeError:
            return

        except KeyboardInterrupt:
            print(f"{R}KeyboardInterrupt !{Res}")
            exit(1)
        
        except Exception as e:
            print(f"{R}An unexpected error occurred at function {B}getIPInfo(){Res}:\n {e}")
            return 
            
            
    # a fallback function in case  https://bgp.he.net/ is unavailable  
    def getIPInfoFallback(self,ip: str) -> dict:
        try:           
            ip_info = {}
            
            url = f"https://api.bgpkit.com/v3/utils/ip?ip={ip}"
            response = requests.get(url).json()
        
        except requests.exceptions.Timeout:
            print(f"{R}Request timed out !{Res}")
            return
        except requests.exceptions.ConnectionError:
            print(f"{R}Could not connect to bgp.he.net{Res}")
            return
        except requests.exceptions.HTTPError as HTTPError:
            print(f"{R}HTTP Error: {str(HTTPError)}{Res}")
            return
            
        try:
        
            ip_info['row1'] = {
            "ASN" : response['asn']['asn'],
            "CIDR" : response['asn']['prefix'],
            "DESCREPTION" :  response['asn']['name']
            }
         
            return ip_info
            
            
        except KeyboardInterrupt:
            print(f"{R}KeyboardInterrupt !{Res}")
            exit(1)
        except Exception as e:
            print(f"{R}An unexpected error occurred at function {B}getIPInfoFallback(){Res}:\n {e}")
            return
    
    
    # Scan ip address with virustotal  ( api key is required ) 
    def vtScan(self, ip: str) -> tuple:
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {
            "accept": "application/json",
            "X-Apikey": VIRUS_TOTAL_API_KEY
            }

            response = requests.get(url, headers=headers)
            if response.status_code == 401:
                print(f"{R}  Unable to Authenicate to www.virustotal.com ! Please verify your API Key{Res}")
                return
            
        except requests.exceptions.Timeout:
            print(f"{R}Request timed out !{Res}")
            return
        except requests.exceptions.ConnectionError:
            print(f"{R}Could not connect to www.virustotal.com{Res}")
            return
        except requests.exceptions.HTTPError as HTTPError:
            print(f"{R}HTTP Error: {str(HTTPError)}{Res}")
            return
            
        try:
            malicious = response.json()['data']['attributes']['last_analysis_stats']['malicious']
            suspicious = response.json()['data']['attributes']['last_analysis_stats']['suspicious']
    
            return (malicious,suspicious)
        
        except KeyboardInterrupt:
            print(f"{R}KeyboardInterrupt !{Res}")    
            exit(1)
        
        except Exception as e:
            print(f"{R}An unexpected error occurred at function {B}vtScan(){Res}:\n {e}")
            return
        
         
        
    def auditConnections(self) -> None:
        try:
            self.getListeningServices()
            
            established_connections = [conn for conn in psutil.net_connections(kind='inet') if conn.status == 'ESTABLISHED']
            if established_connections:
                print(f"\n\n{P}{' ' * 40}Established Connections:{' ' * 40}{Res}\n")
                for connection in established_connections:
                    local_address, local_port = connection.laddr
                    remote_address, remote_port = connection.raddr
                    process_id = connection.pid
                    process_name = psutil.Process(process_id).name()
                    process_username = psutil.Process(process_id).username()
                  
                    print(f"\n\n{W}{local_address}:{local_port}{Res} <---> {B}{remote_address}:{remote_port}{Res}  PID: {Y}{process_id}{Res}  EXE: {Y}{process_name}{Res}  USER: {Y}{process_username}{Res}")
                    
                    ip_info = self.getIPInfo(remote_address)
                    ip_info = ip_info if ip_info else self.getIPInfoFallback(remote_address)
                    
                    if ip_info:
                        print(f"About {B}{remote_address}{Res}:")
                        if VIRUS_TOTAL_API_KEY:
                            try:
                                malicious, suspicious = self.vtScan(remote_address)
                                print(f"   malicious: {R if malicious else G}{bool(malicious)}{Res}")
                                print(f"   suspicious: {R if suspicious else G}{bool(suspicious)}{Res}")
                            
                                if malicious or suspicious:
                                    print(f"   For more details: {R}https://www.virustotal.com/gui/ip-address/{remote_address}{Res}")
                            
                            except TypeError:
                                pass
                            
                        try:
                            for row in ip_info:
                                print('')
                                for key , value in ip_info[row].items():
                                    print(f"   {W}{key}{Res}: {Y}{value}{Res}")
                        except  (TypeError, AttributeError, KeyError) as e:
                            print("   Unable to get ip information !")
                            continue
          
        except KeyboardInterrupt:
            print(f"{R}KeyboardInterrupt !{Res}")
            exit(1)

        except Exception as e:
            print(f"{R}An unexpected error occurred at function {B}auditConnections(){Res}:\n {e}")
            return





class ServicesAnalyzer():
    def listAllServices(self) -> None:
        print(f"\n\n{P}{' ' * 40}Services:{' ' * 40}{Res}\n")
        try:
            cmd = ["systemctl", "list-units", "--type=service", "--all", "--output=json"]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
           
            if result.returncode != 0:
                print(f"{R}systemctl returned an error :{Res}{result.stderr}")
                return
               
            services = json.loads(result.stdout)
            
        except json.JSONDecodeError:
            print(f"{R}Failed to parse json !{Res}")
            return
        
        except TypeError:
            print(f"{R}Invalid data type passed to json.loads() !{Res}")
            return
        
        except Exception as e:
            print(f"{R}An unexpected error occurred at function {B}listAllServices(){Res}:\n {e}")
            return
        
        
        if not services:
            return
            
        print(f"{'Service Name':<50} {'Load State':<12} {'Active State':<17} {'Sub State':<12} {'Bin Path'}")
        print("-" * 110)
                           
        for service in services:
            try:
                output = subprocess.run(["systemctl", "show", service['unit'], "-p", "ExecStart"], capture_output=True, text=True, check=True).stdout.strip()
                command = output.split('argv[]=')[1].split(';')[0].strip()  
            except Exception:
                command = None
            
            print(f"{service['unit']:<50} {service['load']:<12} {G if service['active'] == 'active' else Y}{service['active']:<17}{Res} {G if service['sub'] == 'running' else R}{service['sub']:<12} {command if command else 'N/A'}{Res}")
        



class ProcessAnalyzer():
    def analyzeProcesses(self) -> None:
            print(f"\n\n{P}{' ' * 40}Running Processes:{' ' * 40}{Res}\n")
            attrs = ['pid', 'name', 'username', 'status', 'exe']
            print(f"{'PID':<7} {'Status':<10} {'User':<12} {'Name':<50} {'Executable Path'}")
            print("-" * 110)
            try:
                for proc in psutil.process_iter(attrs):
                    try:
                        proc_info = proc.info
                        exe_path = proc_info['exe'] if proc_info['exe'] else 'N/A'
                        print(f"{proc_info['pid']:<7} {proc_info['status']:<10} {R if proc_info['username'] == 'root' else W}{proc_info['username']:<12}{Res}{proc_info['name']:<50} {exe_path}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
            except KeyboardInterrupt:
                print(f"{R}KeyboardInterrupt !{Res}")
                exit(1)
        
            except Exception as e:
                print(f"{R}An unexpected error occurred at function {B}analyzeProcesses(){Res}:\n {e}")
                return 
    # list files opened by process 
    def listOpeneFiles(self) -> None:
        print(f"\n{P}{' ' * 40}Open Files:{' ' * 40}{Res}\n")       
        attrs = ['pid', 'name'] 
        print(f"{'PID':<7} {'Name'}")
        print("-" * 110) 
        try:
            for proc in psutil.process_iter(attrs):
                try:
                    proc_info = proc.info
                    print(f"{proc_info['pid']:<7} {proc_info['name']}")
                    open_files = proc.open_files()
                    if open_files:
                        for file in open_files:
                            print(f"  {G}└─> File{Res}: {file.path}{Res}")
                                          
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        
        except KeyboardInterrupt:
            print(f"{R}KeyboardInterrupt !{Res}")
            exit(1)
        
        except Exception as e:
             print(f"{R}An unexpected error occurred at function {B}listOpeneFiles(){Res}:\n {e}")  


#
class EnvironmentExplorer():
    
    # enumerate all users on the system 
    def enumerateUsers(self) -> None:
        try:
           print(f"\n\n{P}{' ' * 40}All users:{' ' * 40}{Res}\n")
           print(f"{'User Name':<25} {'UID':<6} {'GID':<6} {'Home Directory':<30} {'Login Shell':<12}")
           print("-" * 110)
           for user in pwd.getpwall():
               print(f"{user.pw_name:<25} {R if user.pw_uid == 0 else W} {user.pw_uid:<6} {Res} {R if user.pw_gid == 0 else W}{user.pw_gid:<6} {Res} {user.pw_dir if user.pw_dir else 'N/A':<30} {W if user.pw_shell.endswith('nologin') or user.pw_shell.endswith('false') else G} {user.pw_shell if user.pw_shell else 'N/A'}{Res}")
        
        except PermissionError:
            print("Unable to read /etc/passwd. Permission Denied !")
        
        except KeyError:
            print("Unable to read /etc/passwd. Corrupted or Unreadable !")
        
        except KeyboardInterrupt:
            print(f"{R}KeyboardInterrupt !{Res}")
            exit(1)
        except Exception as e:
             print(f"{R}An unexpected error occurred at function {B}enumerateUsers(){Res}:\n {e}")
        
    
    # list currently loggedin users
    def listLoggedinUsers(self) -> None:
        try:
            users = psutil.users()
            if users:
                print(f"\n\n{P}{' ' * 40}Currently logged-in users:{' ' * 40}{Res}\n")
                print(f"{'User':<20} {'Terminal':<10} {'Host':<25} {'Started'}")
                print("-" * 110)
                for user in users:
                    print(f"{user.name:<20} {user.terminal:<10} {user.host:<25} {user.started}")
                    
        except AttributeError:
            print('attr err')	
            return
        
        except KeyboardInterrupt:
            print(f"{R}KeyboardInterrupt !{Res}")
            exit(1)
        
        except Exception as e:
            print(f"{R}An unexpected error occurred at function {B}listLoggedinUsers(){Res}:\n {e}")
            return
                  


# look for any signs of persistance mechanisms 
class PersistenceThreatsFinder():
    
    # list all users cronjobs     
    def listCronJobs(self) -> None:
        try:
            users = [user.pw_name for user in pwd.getpwall()]
            print(f"\n\n{P}{' ' * 40}Cron jobs:{' ' * 40}{Res}\n")
            
            for user in users:
                try:
                    result = subprocess.run(['crontab', '-l', '-u', user], capture_output=True, text=True, check=True)
                    if result.returncode == 0:
                        pattern = r'^(?!\s*#)(?!\s*$).+'
                        cronjobs = re.findall(pattern, result.stdout, flags=re.MULTILINE)
                        
                        if cronjobs:
                            print(f"Cron jobs for user: {Y}{user}{Res}")
                            for cronjob in cronjobs:
                                print(f"   {G}{cronjob}{Res}")

                except subprocess.CalledProcessError:
                    continue
        
        
        except KeyboardInterrupt:
            print(f"{R}KeyboardInterrupt !{Res}")
            exit(1)
        
        except Exception as e:
            print(f"{R}An unexpected error occurred at function {B}listCronJobs(){Res}:\n {e}")
            return      
    
    # list startup scripts that may start at boot / loging 
    def listStartupScripts(self) -> None:
        try:
            print(f"\n\n{P}{' ' * 40}Startup scripts:{' ' * 40}{Res}\n")
                      
            print(f"System wide startup scripts:\n")
            for file_path in SYSTEM_WIDE_STARTUP_LOCATIONS:
                try:
                    if path.isdir(file_path):
                        print(f"\n   Startup scripts in: {Y}{file_path}{Res}\n")
                        for file in listdir(file_path):
                            print(f"    {G}└─> {W}{path.join(file_path,file)}{Res}")
                
                except PermissionError:
                    continue
            
        except KeyboardInterrupt:
             print(f"{R}KeyboardInterrupt !{Res}")
             exit(1)
        except Exception as e:
             print(f"{R}An unexpected error occurred at function {B}listStartupScripts(){Res}:\n {e}")
             return      
            
    # list user specific startup scripts / shell profiles    
    def listUserStartupScripts(self) -> None:
        try:
            print(f"\n\nConsider checking this files manually as it could be used for persistance:{Res}\n")
            for user in pwd.getpwall():
                for file_path in USER_SPECIFIC_STARTUP_SCRIPTS:
                    absolute_path = path.join(user.pw_dir, file_path)
                    if path.isfile(absolute_path):
                        print(f"    {G}{absolute_path}{Res}")
                    elif path.isdir(absolute_path):
                        try:
                            for file in listdir(absolute_path):
                                print(f"    {G}{path.join(absolute_path,file)}{Res}")
                        except PermissionError:
                            continue         
                
        
        except KeyboardInterrupt:
             print(f"{R}KeyboardInterrupt !{Res}")
             exit(1)
        except Exception as e:
             print(f"{R}An unexpected error occurred at function {B}listUserStartupScripts(){Res}:\n {e}")
             return    
    
    # list all users with UID = 0 or GID  = 0 ( root accounts ) 
    def listRootAccounts(self) -> None:
        try:
            print(f"\n\n{P}{' ' * 40}root Accounts:{' ' * 40}{Res}\n")
            print(f"{'User Name':<25} {'UID':<6} {'GID'}")
            print("-" * 110)
            for user in pwd.getpwall():
                if user.pw_uid == 0 or user.pw_gid == 0:
                    print(f"{user.pw_name:<25} {R}{user.pw_uid:<6}{Res} {R}{user.pw_gid}{Res}")
            
        
        except KeyboardInterrupt:
            print(f"{R}KeyboardInterrupt !{Res}")
            exit(1)
        except Exception as e:
            print(f"{R}An unexpected error occurred at function {B}listRootAccounts(){Res}:\n {e}")
            return
            
            
            
    # list users ssh authorized_keys 
    def listSSHAuthorizedKeys(self) -> None:
        try:
            print(f"\n\n{P}{' ' * 40}Authorized ssh keys:{' ' * 40}{Res}\n")
                        
            for user in pwd.getpwall():
                if not user.pw_shell.endswith('nologin') or not user.pw_shell.endswith('false'):
                    try:
                        keys = open(path.join(user.pw_dir,".ssh/authorized_keys")).read().split('\n')
                        print(f"\nAuthorized keys for user: {Y}{user.pw_name}{Res}\n")
                        for key in keys:
                            print(f"  {key}")
                            
                    except PermissionError:
                        continue
                    except FileNotFoundError:
                        continue                    
        
        except KeyboardInterrupt:
            print(f"{R}KeyboardInterrupt !{Res}")
            exit(1)
        
        except Exception as e:
            print(f"{R}An unexpected error occurred at function {B}listSSHAuthorizedKeys(){Res}:\n {e}")
            return
    
    
    
    # list loaded kernel modules 
    def listLoadedKernelModules(self) -> None:
        try:
            print(f"\n\n{P}{' ' * 40}Loaded kernel modules:{' ' * 40}{Res}\n")
            
            modules = []
            print(f"{'Module Name':<30} {'Reference Count':<20} {'Load State':<15} {'Memory Address':<20} {'Author':<50} {'Description'}")
            print("-" * 150)
            try:
                with open("/proc/modules", "r") as file:
                    for line in file.read().split('\n'):
                        if line:
                            modules.append(line)
                        
            except FileNotFoundError:
                print("Error: /proc/modules not found.")
                return
            except PermissionError:
                print("Error: Insufficient permissions to read /proc/modules.")
                return
            
            
            for module in modules:
                if module:
                    module_name = module.split()[0]
                    reference_count = module.split()[2]
                    load_state = module.split()[4]
                    memory_address = module.split()[5]
                    
                    try:
                        result = subprocess.run(["modinfo", module_name], capture_output=True, text=True, check=True)
                        description = re.search(r"^description:\s*(.*?)\s*$", result.stdout, re.MULTILINE).group(1)
                        author_name = re.search(r"^author:\s*(.*?)\s*$", result.stdout, re.MULTILINE).group(1)  
                    
                    except Exception:
                        description = author_name = None
                        
                           
                    print(f"{module_name:<30} {reference_count:<20} {G if load_state == 'Live' else R}{load_state:<15}{Res} {memory_address:20} {author_name if author_name else 'N/A':<50} {description if description else 'N/A'}")
                      
                                
        
        except KeyboardInterrupt:
            print(f"{R}KeyboardInterrupt !{Res}")
            exit(1)
        
        except Exception as e:
            print(f"{R}An unexpected error occurred at function {B}listLoadedKernelModules(){Res}:\n {e}")
            return

    
    # identify mallicious / vulnerable python libraries installed on the system 
    def scanPythonLibs(self) -> None:
        try:
            url = "https://api.osv.dev/v1/querybatch"
            dists = importlib.metadata.distributions()
            if not dists:
                return
            
            packages = list({dist.metadata['Name']: dist.version for dist in dists}.items())
            
            print(f"\n\n{P}{' ' * 40}Scanning installed Python libs:{' ' * 40}{Res}\n")
            chunk_size = 100
            for i in range(0, len(packages), chunk_size):
                chunk = packages[i:i + chunk_size]
                
                payload = {
                    "queries": [
                    {
                        "package": {"name": package[0], "ecosystem": "PyPI"},
                        "version": package[1]
                    } for package in chunk
                    ]
                }
                
                try:
                    response = requests.post(url, json=payload)
                    results = response.json().get("results", [])

                except requests.exceptions.Timeout:
                    print(f"{R}Request timed out !{Res}")
                    return
                except requests.exceptions.ConnectionError:
                    print(f"{R}Could not connect to api.osv.dev{Res}")
                    return
                except requests.exceptions.HTTPError as HTTPError:
                    print(f"{R}HTTP Error: {str(HTTPError)}{Res}")
                    continue
                except requests.exceptions.JSONDecodeError:
                    print("{R}Failed to decode JSON.{Res} ")
                    return
                
                for result in enumerate(results):
                    if result[1]:
                        threats = result[1]
                        package_name , package_version = chunk[result[0]]
                        print(f"\n{B}PythonLib{Res}: {W}{package_name}{Res} {G}{package_version}{Res}")
                        for vuln in threats['vulns']:
                            print(f"   Threat ID: {R if vuln['id'].startswith('MAL-') else Y}{vuln['id']}{Res}")
                
                i += chunk_size
                
        except KeyboardInterrupt:
            print(f"{R}KeyboardInterrupt !{Res}")
            exit(1)
        
        except Exception as e:
            print(f"{R}An unexpected error occurred at function {B}scanPythonLibs(){Res}:\n {e}")
            return
    
    # identify mallicious / vulnerable Ruby Gems installed on the system 
    def scanRubyGems(self) -> None:
        try:
            url = "https://api.osv.dev/v1/querybatch"
            try:
                result = subprocess.run(["gem", "list", "--local"], capture_output=True, text=True, check=True).stdout.split('\n')[:-1]
            
            except subprocess.CalledProcessError:
                return
            print(f"\n\n{P}{' ' * 40}Scanning installed Ruby Gems:{' ' * 40}{Res}\n")
            packages = []
            for package in result:
                name = package.split()[0]
                versions = re.search(r"\(([^()]+)\)", package).group()
                version = re.search(r"[\d.]+", versions.split('default:')[1]).group() if 'default:' in versions else re.search(r"[\d.]+", versions).group()
                packages.append((name, version))
            

            chunk_size = 100
            for i in range(0, len(packages), chunk_size):
                chunk = packages[i:i + chunk_size]
                
                payload = {
                    "queries": [
                    {
                        "package": {"name": package[0], "ecosystem": "RubyGems"},
                        "version": package[1]
                    } for package in chunk
                    ]
                }
                
                try:
                    response = requests.post(url, json=payload)
                    results = response.json().get("results", [])

                except requests.exceptions.Timeout:
                    print(f"{R}Request timed out !{Res}")
                    return
                except requests.exceptions.ConnectionError:
                    print(f"{R}Could not connect to api.osv.dev{Res}")
                    return
                except requests.exceptions.HTTPError as HTTPError:
                    print(f"{R}HTTP Error: {str(HTTPError)}{Res}")
                    continue
                except requests.exceptions.JSONDecodeError:
                    print("{R}Failed to decode JSON.{Res} ")
                    return
                
                for result in enumerate(results):
                    if result[1]:
                        threats = result[1]
                        package_name , package_version = chunk[result[0]]
                        print(f"\n{R}RubyGem{Res}: {W}{package_name}{Res} {G}{package_version}{Res}")
                        for vuln in threats['vulns']:
                            print(f"   Threat ID: {R if vuln['id'].startswith('MAL-') else Y}{vuln['id']}{Res}")
                
                i += chunk_size
                
        except KeyboardInterrupt:
            print(f"{R}KeyboardInterrupt !{Res}")
            exit(1)
        
        except Exception as e:
            print(f"{R}An unexpected error occurred at function {B}scanRubyGems(){Res}:\n {e}")
            return




class Main(NetworkAnalyzer, ProcessAnalyzer, ServicesAnalyzer, EnvironmentExplorer, PersistenceThreatsFinder):
    
    def __init__(self) -> None:       
        self.parser = argparse.ArgumentParser(prog='quicklinir.py', description="Quick Linux Initial Incident Response.")
        self.parser.add_argument('-a', '--all' , action='store_true', default=True, help='audit everything ( default )')
        self.parser.add_argument('-n', '--network' , action='store_true', help='audit network connections')
        self.parser.add_argument('-p', '--processes' , action='store_true', help='audit processes')
        self.parser.add_argument('-e', '--environment' , action='store_true', help='audit the environment')
        self.parser.add_argument('-s', '--services' , action='store_true', help='audit services')
        self.parser.add_argument('-c', '--cronjobs', action='store_true', help='list all users cronjobs')
        self.parser.add_argument('-u', '--startup', action='store_true', help='list startup scripts')
        self.parser.add_argument('-r', '--roots', action='store_true', help='list all root accounts')
        self.parser.add_argument('-t', '--trustedsshkeys', action='store_true', help='list all users ssh authorized keys')
        self.parser.add_argument('-k', '--kernelmodules', action='store_true', help='list loaded kernel modules')
        self.parser.add_argument('-l', '--scanlibs', action='store_true', help='scan installed libraries (PyPI Libs/ RubyGems)')
        
        #parse arguments
        self.args = self.parser.parse_args()
        
    
        
    def main(self) -> None:
        try:
            options = [var for var , value in vars(self.args).items() if value and var != 'all']
            
            actions = {
            'network' : [self.auditConnections],
            'services' : [self.listAllServices],
            'processes' : [self.analyzeProcesses, self.listOpeneFiles],
            'environment' : [self.enumerateUsers, self.listLoggedinUsers],
            'cronjobs' : [self.listCronJobs],
            'startup' : [self.listStartupScripts, self.listUserStartupScripts],
            'roots' : [self.listRootAccounts],
            'trustedsshkeys' : [self.listSSHAuthorizedKeys],
            'kernelmodules' : [self.listLoadedKernelModules],
            'scanlibs' : [self.scanPythonLibs, self.scanRubyGems]
            }
            
        
            if not options:
                self.auditConnections()
                self.listAllServices()
                self.analyzeProcesses()
                self.listOpeneFiles()
                self.enumerateUsers()
                self.listLoggedinUsers()
                self.listCronJobs()
                self.listStartupScripts()
                self.listUserStartupScripts()
                self.listRootAccounts()
                self.listSSHAuthorizedKeys()
                self.listLoadedKernelModules()
                self.scanPythonLibs()
                self.scanRubyGems()
            
            for option in options:
                for action in actions[option]:
                    action()
                
                
        except KeyboardInterrupt:
            print(f"{R}KeyboardInterrupt !{Res}")
            exit(1)
        
        except Exception as e:
            print(f"{R}An unexpected error occurred at function {B}main(){Res}:\n {e}")
            return       
            
if __name__ == "__main__":
    Main = Main()
    Main.main()     

