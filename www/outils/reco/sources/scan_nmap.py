import os
from subprocess import check_output
from urllib.parse import urlparse


def scan_nmap(x) :



     # Fonction pour extraire le nom de domaine
     parsed_url = urlparse(x)

     # Exemple d'utilisation
     nom_domaine = parsed_url.netloc

     var = check_output(["sudo","nmap","-O","-sV","-sS",nom_domaine])
     var_result = var.decode("utf8")
     tab = var_result.split('\n')

     port = []
     mac = []
     ostab = []


     for i in range(len(tab)) :                                      #on parcourt la sortie nmap

               tab2 = tab[i].split(" ")                                #on split la ligne qu'on lit par des espace

               if tab2[0] == "PORT" :                                  #detection de la sortie concernant les ports 
                    
                    for y in range((i+1),len(tab)) :                    # on parcours à partir de la ligne du premier port
                         
                         port.append(tab[y])                            #ajout de la ligne du port à la list port 
                         tab2 = tab[y].split(" ")                       #on split pour faire le test if par la suite
                    
                         if tab2[0] == "MAC" :                          #test pour stoper la list du port et incrémenter la list mac

                              mac.append(tab2[2])
                              tab2 = tab[y].split("(")
                              tab2[1] = tab2[1].replace(")","")         
                              mac.append(tab2[1])
                              port.pop()
                              break

                         
                         if not tab2[0][0].isdigit():
                              break
               
               if tab2[0] == "OS" and tab2[1] == "details:" :          #test si OS détecté
                    
                    ostab =tab[i].split("OS details: ")                #enlève les info inutiles
                    ostab[0] = ostab[1]                                #incrémente la variable qui récupère l'OS
                    ostab.pop()  
                    ostab = ostab[0]                                      #supprime le doublons

               elif tab2[0] == "No" and tab2[1] == "exact" :           #test si OS pas détecté
                    ostab.append("No OS detected")
                    ostab = ostab[0]

     donnees = {}
     lst_port =  []
     cpt = 1

     for i in range(len(port)):
          
          lst_port.append("port" + str(cpt))
          cpt += 1

     for i in range(len(port)):
          
          donnees[lst_port[i]] = port[i]



     mac_char = ""

     if len(mac) == 0 :
          mac_char = "None Physical Addresse detected"
     else :

          for i in range(len(mac)) :
          
               mac_char += mac[i]

               if i != (len(mac) - 1) :
                    mac_char += " - "
   

     cpt_info = len(port) + 2

     return donnees,mac_char,ostab,cpt_info
    

#print(scan_nmap('http://192.168.1.135'))