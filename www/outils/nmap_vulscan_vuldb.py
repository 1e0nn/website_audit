
from subprocess import check_output
import re
from urllib.parse import urlparse


def nmap_vulscan_vuldb(url):

    # Fonction pour extraire le nom de domaine
    parsed_url = urlparse(url)

     # Exemple d'utilisation
    nom_domaine = parsed_url.netloc

    #execute la commande nmap avec la url et store dans une variable
    command_nmap_vulscan = check_output(["nmap","-sV","--script=vulscan/vulscan.nse","--script-args", "vulscandb=scipvuldb.csv", nom_domaine])  
    #nmap -sV --script=vulscan/vulscan.nse --script-args vulscandb=cve.csv 192.168.1.175
         


    #decode le résultat de la commande
    result_decoded_vulscan = command_nmap_vulscan.decode("utf8")
    
    #mettre la sortie de la commande dans une liste (chaque ligne = un élément dans la liste)
    result_vulscan=result_decoded_vulscan.split('\n')

    #test affichage
    print(result_decoded_vulscan)
    #print(result_vulscan)

    #vérifier chaques lignes pour voir si c'est une ligne de début ou de fin avec regex puis sauvegarder ses index dans la liste index
    index=[]

    for idx, i in enumerate(result_vulscan):   

        if re.match("\|_\w",i):
            pass
        elif re.match("[0-9]+/[A-Za-z]+\s+",i):
            #compte pas les ports avec aucune vuln qui bug
            #print(result_vulscan[idx]," test ", result_vulscan[idx+1])
            if re.match("[0-9]+/[A-Za-z]+\s+",result_vulscan[idx]) and re.match("[0-9]+/[A-Za-z]+\s+",result_vulscan[idx+1]):
                pass
            elif re.match("[0-9]+/[A-Za-z]+\s+",result_vulscan[idx]) and len(result_vulscan[idx+1]) == 0 :
                pass
            else:
                index.append(idx+2)
                #test affichage
                print(idx+2," re deb", i)
        elif re.match("\|_$",i):
            index.append(idx-1)
            #test affichage
            print(idx-1," re fin ", i)
        else:
            pass  

   #vérifie si la liste est paire (si pas paire la liste est érroné)
    nb_resu=len(index)
    if nb_resu%2==0: 

        #variables qui vont donner les résultats
        dico_cve_per_group_vuldb={}
        dico_results_per_group_vuldb={}
        dico_type_per_group_vuldb={}
        dico_results_full_list_vuldb={"result_list":[]}
        dico_cve_full_list_vuldb={"vuldb_list":[]}
        a_virer='| vulscan: scipvuldb.csv:'

        #boucle qui s'éffectuer le nombre de fois qu'il y a une paire d'index existente (chaques groupe de paire représente un groupe de vulnw)
        for i in range(0,int(nb_resu/2)):

            #crée un dic avec pour x groupe ses sorties associées  ex: {"result_groupe 2":["folder admin found","vuln sql"...]} et vérifie que ca ne commence pas avec '| vulscan: scipvuldb.csv:' 
            if a_virer in result_vulscan[index[i*2]:index[i*2+1]]:
                dico_results_per_group_vuldb["result_groupe {0}".format(i)]=result_vulscan[index[i*2]+1:index[i*2+1]]
            else:
                dico_results_per_group_vuldb["result_groupe {0}".format(i)]=result_vulscan[index[i*2]:index[i*2+1]]

            
            #crée un dic avec pour chaques groupe leurs types type de service et port
            dico_type_per_group_vuldb["type_groupe {0}".format(i)]=result_vulscan[index[i*2]-2]


            num_groupe=i
            dico_cve_per_group_vuldb[f"cve_groupe {num_groupe}"] = []



            #boucle qui retourne  dans i chaques groupes de vuln ex ["deb","vuln1","vuln2","vuln3","fin"]
            for i in result_vulscan[index[i*2]:index[i*2+1]]:



                #crée une liste complète de tout les résulats et évite les doublons
                if i in dico_results_full_list_vuldb["result_list"]:
                    pass
                else:
                    dico_results_full_list_vuldb["result_list"].append(i)

                vuldb_regex="[[0-9]+\]"

            #pour chaques groupe, verif des cve présent et ajout dans 2 dico, cve par groupe et un avec toutes les cve
                if re.search(vuldb_regex,i):
                    
                    #vérifie qu'il n'y a pas de doublon de cve dans les listes cve groupe et cve full list
                    if re.search(vuldb_regex,i).group() in dico_cve_full_list_vuldb["vuldb_list"]:

                        dico_cve_per_group_vuldb[f"cve_groupe {num_groupe}"].append(re.search(vuldb_regex,i).group())
                        pass
                    
                    else:

                        dico_cve_full_list_vuldb["vuldb_list"].append(re.search(vuldb_regex,i).group())

                        dico_cve_per_group_vuldb[f"cve_groupe {num_groupe}"].append(re.search(vuldb_regex,i).group())
           
        return(dico_type_per_group_vuldb,dico_results_per_group_vuldb,dico_cve_full_list_vuldb,dico_cve_per_group_vuldb)
        #print(dico_results_per_group_vuldb)
        #print(dico_cve_per_group_vuldb)
        #print(dico_type_per_group_vuldb)
        #print(dico_cve_full_list_vuldb)
        #print(dico_results_full_list_vuldb)


    else:
        
        #test affichage
        print("erreur, la liste index n'est pas paire")


#"192.168.1.175"
