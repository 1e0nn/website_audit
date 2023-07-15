import os
import subprocess
from subprocess import check_output
from urllib.parse import urlparse


def scan_gobuster(x,y) :
    try:
        if y == "rapide" :

            var = check_output(["gobuster","dir","-u",x,"-w","/usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt"])

        elif y == "lent" :

            var = check_output(["gobuster","dir","-u",x,"-w","/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"])

    

        var_result = var.decode("utf8")
        tab = var_result.split('\n')

        dir = []
    

        for i in range(14, len(tab)):

            tab2 = tab[i].split("\r\x1b[2K")
            tab2.pop(0)

            if tab2 != [] :
                
                var2 = tab2[0]
                var2 = var2.split(" ")
                
                

                lien = var2[len(var2) - 1]
                lien = lien[:-1]

                dir.append(lien)

        


        # Fonction pour extraire le nom de domaine
        parsed_url = urlparse(x)

        # Exemple d'utilisation
        nom_domaine = parsed_url.netloc

        if y == "rapide" :

            var = check_output(["gobuster","dns","-d",nom_domaine,"-w","/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt"])

        elif y == "lent" :

            var = check_output(["gobuster","dns","-d",nom_domaine,"-w","/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt"])

        var_result = var.decode("utf8")
        tab = var_result.split('\n')
        tab2= []

        for i in range (len(tab)):
        
            a = tab[i].split(" ")
        
            if a[0] == "\r\x1b[2KFound:":

                b = a[1] + "/" + a[2]

                tab2.append(b) 

        if len(tab2) == 0:
            
            tab2 = "Aucun Sous-Domaine détécté"
            #tab2.append('Aucun Sous-Domaine détécté')


        donnees = {}
        lst_dir =  []
        cpt = 1

        for i in range(len(dir)):
            
            lst_dir.append("page" + str(cpt))
            cpt += 1

        for i in range(len(dir)):
            
            donnees[lst_dir[i]] = dir[i]

        cpt_gobuster = len(dir) + 1

        return donnees,tab2,cpt_gobuster

    except subprocess.CalledProcessError as e:
        error1=f"Enumeration de pages Web indisponible pour ce site"
        error2=f"Enumeration de domaine indisponible pour ce site"
        cpt_error = 0
        return  error1,error2,cpt_error

    


#print(scan_gobuster("http://localhost/mutillidae","rapide"))

