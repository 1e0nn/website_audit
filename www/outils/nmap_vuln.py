from subprocess import check_output
import re
from urllib.parse import urlparse


def nmap_vuln(url):


    # Fonction pour extraire le nom de domaine
    parsed_url = urlparse(url)

     # Exemple d'utilisation
    nom_domaine = parsed_url.netloc

    #execute la commande nmap avec la url et store dans une variable
    test_nmap_vuln = check_output(["nmap","-sV","--script","vuln",nom_domaine])

    #decode le résultat de la commande
    result_decoded_vuln = test_nmap_vuln.decode("utf8")
    
    #mettre la sortie de la commande dans une liste (chaque ligne = un élément dans la liste)
    result_nmap=result_decoded_vuln.split('\n')

    #test affichage
    print(result_decoded_vuln)

    #vérifier chaques lignes pour voir si c'est une ligne de début ou de fin avec regex puis sauvegarder ses index dans la liste index
    index=[]

    for idx, i in enumerate(result_nmap):   

        if re.match("\|_\w",i):
            pass
        elif re.match("\| \w",i):
            if re.match("\| \w",i) and re.match("\| \w",result_nmap[idx-1]):
                pass
            else:
                index.append(idx+1)
                #test affichage
                print(idx+1," debut", i)
        elif re.match("\|_\s",i):
            index.append(idx+1)
            #test affichage
            print(idx+1," fin", i)
        else:
            pass    



   #vérifie si la liste est paire (si pas paire la liste est érroné)
    nb_resu=len(index)
    if nb_resu%2==0: 

        #variables qui vont donner les résultats      
        dico_cve_per_group_vuln={}
        dico_results_per_group_vuln={}
        dico_type_per_group_vuln={}

        dico_results_full_list_vuln={"result_list":[]}
        dico_cve_full_list_vuln={"cve_list":[]}
        

        #boucle qui s'éffectuer le nombre de fois qu'il y a une paire d'index existente (chaques groupe de paire représente un groupe de vulnw)
        for i in range(0,int(nb_resu/2)):

            #crée un dic avec pour x groupe ses sorties associées  ex: {"result_groupe 2":["folder admin found","vuln sql"...]}
            dico_results_per_group_vuln["result_groupe {0}".format(i)]=result_nmap[index[i*2]:index[i*2+1]]

            #crée un dic avec pour chaques groupe leurs types type de service et port
            dico_type_per_group_vuln["type_groupe {0}".format(i)]=result_nmap[index[i*2]-1]

            numb_cve=i
            dico_cve_per_group_vuln[f"cve_groupe {numb_cve}"] = []

            #boucle qui retourne  dans i chaques groupes de vuln ex ["deb","vuln1","vuln2","vuln3","fin"]
            for i in result_nmap[index[i*2]:index[i*2+1]]:

                #crée une liste complète de tout les résulats et évite les doublons
                if i in dico_results_full_list_vuln["result_list"]:
                    pass
                else:
                    dico_results_full_list_vuln["result_list"].append(i)

                cve_regex="(CVE-(1999|2\d{3})-(0\d{2}[1-9]|[1-9]\d{3,}))"

            #pour chaques groupe, verif des cve présent et ajout dans 2 dico, cve par groupe et un avec toutes les cve
                if re.search(cve_regex,i):
                    
                    #vérifie qu'il n'y a pas de doublon de cve dans les listes cve groupe et cve full list
                    if re.search(cve_regex,i).group() in dico_cve_full_list_vuln["cve_list"]:

                        dico_cve_per_group_vuln[f"cve_groupe {numb_cve}"].append(re.search(cve_regex,i).group())
                        pass
                    
                    else:

                        dico_cve_full_list_vuln["cve_list"].append(re.search(cve_regex,i).group())

                        dico_cve_per_group_vuln[f"cve_groupe {numb_cve}"].append(re.search(cve_regex,i).group())
            
           
        return(dico_type_per_group_vuln,dico_results_per_group_vuln,dico_cve_full_list_vuln,dico_cve_per_group_vuln)
        #print(dico_results_per_group_vuln)
        #print(dico_cve_per_group_vuln)
        #print(dico_type_per_group_vuln)
        #print(dico_cve_full_list_vuln)
        #print(dico_results_full_list_vuln)


    else:
        
        #test affichage
        print("erreur, la liste index n'est pas paire")


#nmap_vuln("http://localhost/mutillidae")