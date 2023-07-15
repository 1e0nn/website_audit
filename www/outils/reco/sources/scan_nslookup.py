import os
import ipaddress
import subprocess
from urllib.parse import urlparse



def scan_nslookup(x) :

    # Le but de cette fonction est de renvoyer seulement les addresses IP trouvées à partir de la commande nslookup
    
    #extraction du nom de domaine depuis l'url rentré:


     # Fonction pour extraire le nom de domaine
    parsed_url = urlparse(x)

     # Exemple d'utilisation
    nom_domaine = parsed_url.netloc


    #Execution de la commande et récupération de la sortie:
    try:
        var = subprocess.check_output(["nslookup", nom_domaine])
        print(var)

        #Décodage du résultat de la commande
        var_result = var.decode("utf8")

        #Transformation du résultat en liste avec comme séparature les lignes
        tab = var_result.split('\n')


        tab2 = []


        #On parcours la liste à partir de la ligne qui nous intéresse
        for i in range(5,len(tab)) :
        
            tab3 = tab[i].split(":")

            if tab3[0] == "Address" :

                if len(tab3) > 2 :

                    #Détecte si c'est une addresse IPv6 et si c'est le cas split d'une autre manière

                    tab4 = tab[i].split(" ")
                    tab2.append(tab4[1])

                else :

                    tab2.append(tab3[1])
            
        if tab2 == [] :

            tab2.append("No Adress found")
        
        return tab2

        
    except subprocess.CalledProcessError as e:
        error=f"No Adress found"
        return  error


#print(scan_nslookup("https://localhost"))