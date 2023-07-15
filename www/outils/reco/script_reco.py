import os
import sys
import json

# Chemin avec la notation tilde (~)
chemin_src = "~/website_audit/www/outils/reco/sources"

# Expansion du chemin avec le répertoire de l'utilisateur
chemin_absolu = os.path.expanduser(chemin_src)

# Ajout du chemin absolu au chemin de recherche des modules
sys.path.append(chemin_absolu)

from scan_whois import scan_whois
from scan_nslookup import *
from scan_nmap import *
from scan_cmseek import *
from scan_gobuster import *


def main_reco(url,mode):
       
       #url = input("Entrez l'URL à tester : ")
       #mode = input("Entrez le mode souhaité (lent ou rapide) : ")
       print("")
       print("")

       chemin_reco = "~/website_audit/www/static/rapport"
       chemin_absolu_reco = os.path.expanduser(chemin_reco)
       
       x=url
       y=mode

       #tab = [scan_nslookup(url),scan_whois(url),scan_nmap(url),scan_gobuster(url)]


       scan_cmseek(x)

       ############################################################################################################
       ############################################################################################################
       ############################################################################################################

       def nslookup_json(x) :
       
              lst = scan_nslookup(x)
              ip_nslookup = ""

              if isinstance(lst, list) :

                     for i in  range (len(lst)):
                            
                                   ip_nslookup += lst[i]

                                   if (i + 1) < len(lst):
                                          ip_nslookup += ","
              else : 
                     ip_nslookup = lst


              return ip_nslookup

       

       

       ############################################################################################################
       ############################################################################################################
       ############################################################################################################



       def whois_json(x) :
              
              whois = scan_whois(x)
              #var =""

              #for i in range(len(lst)) :
               #      var += lst[i] + "<&>"

              #return var

              donnees = {}
              lst_lignes =  []
              cpt = 1

              for i in range(len(whois)):
          
                     lst_lignes.append("ligne" + str(cpt))
                     cpt += 1

              for i in range(len(whois)):
          
                     donnees[lst_lignes[i]] = whois[i]
              return donnees

       ############################################################################################################
       ############################################################################################################
       ############################################################################################################

              
       nmap_ports,nmap_mac,nmap_os,cpt_nmap = scan_nmap(x)
              
              
                     
       ############################################################################################################
       ############################################################################################################
       ############################################################################################################             

       gobuster_pages,gobuster_sde,cpt_gobuster = scan_gobuster(x,y)

       ############################################################################################################
       ############################################################################################################
       ############################################################################################################  

       donnees = {
              "Adresses_IP" : nslookup_json(x),
              "whois" : whois_json(x),
              "nmap_ports" : nmap_ports,
              "nmap_mac" : nmap_mac,
              "nmap_os" : nmap_os,
              "gobuster_pages" : gobuster_pages,
              "gobuster_sde" : gobuster_sde


       }

       donnees_json = json.dumps(donnees)



       

       with open(f"{chemin_absolu_reco}/reco.json", "w") as f:

              f.write(donnees_json)

       cpt_total = cpt_nmap + 2 + cpt_gobuster

       return cpt_total

       
#print(main_reco("https://192.168.1.1","rapide"))