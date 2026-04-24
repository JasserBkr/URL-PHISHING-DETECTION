from urllib.parse import urlparse
import dns.resolver
import socket
import re
import tldextract
import requests


abuseIpDB_url="https://api.abuseipdb.com/api/v2/check"
api_key="6a4f6785b482e33389d586e54ca5f7f87ea28af25a329d5a931064137827ad4483b5e0944222e73a"
category={
    1:"DNS Compromise",
    2:"DNS Poisoning",
    3:"Fraud Orders",
    4:"DDoS Attack",
    5:"FTP Brute-Force",
    6:"Ping of Death",
    7:"Phishing",
    8:"Fraud VoIP",
    9:"	Open Proxy",
    10:"Web Spam",
    11:"Email Spam",
    12:"Blog Spam",
    13:"VPN IP",
    14:"Port Scan",
    15:"Hacking",
    16:"SQL Injection",
    17:"Spoofing",
    18:"Brute-Force",
    19:"Bad Web Bot",
    20:"Exploited Host",
    21:"Web App Attack",
    22:"SSH",
    23:"IoT Targeted"
}



def check_db(ip,api_key,abuseIpDB_url):
    
    parms={
        "ipAddress":ip,
        "maxAgeInDays":364,
        "verbose":True
    }
    headers={
        "Accept":"application/json",
        "Key":api_key
    }
    r=requests.get(abuseIpDB_url,headers=headers,params=parms)
    data=r.json()["data"]
    return(data)

def ret_id_reports(data):
    if data["reports"]:
        list_of_id=data["reports"][0]["categories"]
        list_of_cat=[]
        for id in list_of_id:
            list_of_cat.append(category[id])
        return list_of_cat
    else:
        return None
    
def get_info(data):
    isp=data.get("isp","unknown")
    country=data.get("countryCode","unknown")
    usage=data.get("usageType","unknown")
    return(isp,country,usage)

def get_mx_rec(domain):
    mx_list=[]
    try:
        an=dns.resolver.resolve(domain,"MX")
        for i in an:
            mx_list.append(str(i.exchange))
        return mx_list
    except:
        return ["has no mx record"]

def get_spf_record(domain):
    try:
        an=dns.resolver.resolve(domain,"TXT")
        for i in an:
            spf=b"".join(i.strings).decode()    
            if spf.startswith("v=spf1"):
                return(spf)
        return "has no spf"
    except:
        return "unkown"

def get_ns_record(domain):
    ns_list=[]
    try:
        an=dns.resolver.resolve(domain,"NS")
        for i in an:
            ns_list.append(str(i.target).lower())
        return ns_list
    except:
        return ["has no ns record"]

def get_soa_record(domain):
    try:
        soa_record=dns.resolver.resolve(domain,"SOA")[0]
        name=soa_record.rname.to_text()
        name=name.replace(".","@",1)
        return name
    except:
        return "unknown"

def dns_rec(url):
    threat_map={}
    host=urlparse(url).hostname
    ip_pattern=r"^\d+\.\d+\.\d+\.\d+$"

    if re.match(ip_pattern,host):
        data=check_db(host,api_key,abuseIpDB_url)
        reports=ret_id_reports(data)
        isp,country,usage=get_info(data)
        try:
            domain=socket.gethostbyaddr(host)[0]
            mx_rec_list=get_mx_rec(domain)
            spf_record=get_spf_record(domain)
            ns_record=get_ns_record(domain)
            soa_record=get_soa_record(domain)
            threat_map[host]=[reports,isp,country,usage]
            threat_map["MX_record"]=mx_rec_list
            threat_map["spf_record"]=spf_record
            threat_map["ns_record"]=ns_record
            threat_map["soa_record"]=soa_record
        except:
            threat_map[host]=[reports,isp,country,usage]
            threat_map["MX_record"]=["has no mx records"]
            threat_map["spf_record"]="has no spf records"
            threat_map["ns_record"]=["has no ns record"]
            threat_map["soa_record"]="unkown"
    else:
        ext=tldextract.extract(host)
        domain=ext.domain+"."+ext.suffix
        mx_rec_list=get_mx_rec(domain)
        spf_record=get_spf_record(domain)
        ns_record=get_ns_record(domain)
        soa_record=get_soa_record(domain)
        try:
            info=socket.getaddrinfo(host,None)
            ips=[]
            for res in info:
                if res[0]==socket.AF_INET:
                    ips.append(res[4][0])

            for ip in ips:
                data=check_db(ip,api_key,abuseIpDB_url)
                reports=ret_id_reports(data)
                isp,country,usage=get_info(data)
                threat_map[ip]=[reports,isp,country,usage]
            threat_map["MX_record"]=mx_rec_list
            threat_map["spf_record"]=spf_record
            threat_map["ns_record"]=ns_record
            threat_map["soa_record"]=soa_record
        except:
            print("the ip is blocked")
            return({"ip","the ip is blocked"})
    return(threat_map)

