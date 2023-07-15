import os
import subprocess
from urllib.parse import urlparse


def scan_whois(x) :

    parsed_url = urlparse(x)

     # Exemple d'utilisation
    nom_domaine = parsed_url.netloc

    try:
        var = subprocess.check_output(["whois", nom_domaine])
        print(var)
        var_result = var.decode("utf8")
        tab = var_result.split('\n')
        print(tab)
        return tab
    except subprocess.CalledProcessError as e:
        error=f"Il n'y a pas d'informations sur ce nom de domaine disponible"
        return  error
    



#scan_whois("http://192.168.1.1")