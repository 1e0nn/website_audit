
from subprocess import check_output
import subprocess
import re

def nikto(url):

    #execute la commande nmap avec la url et store dans une variable
    #command_nikto = check_output(["nikto","-h",url,"-ask","auto"])
    command_nikto = subprocess.Popen(["nikto","-h",url,"-ask","no"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    output, error = command_nikto.communicate()

    #decode le résultat de la commande
    result_decoded_nikto = output.decode("utf8")
    
    #mettre la sortie de la commande dans une liste (chaque ligne = un élément dans la liste)
    result_nikto=result_decoded_nikto.split('\n')

    #test affichage
    print(result_decoded_nikto)

    #vérifier chaques lignes pour voir si c'est une ligne de début ou de fin avec regex puis sauvegarder ses index dans la liste index
    index=[]

    for idx, i in enumerate(result_nikto):   

        if re.match("\+ Server: [A-Za-z0-9]+",i):
            index.append(idx+1)
            #test affichage
            print(idx+1," debut", i)
        elif re.match("\+ [0-9]+ requests: [0-9]+ error\(s\) and [0-9]+ item\(s\) reported on remote host",i):
            index.append(idx+1)
            #test affichage
            print(idx+1," fin", i)
        else:
            pass    



   #vérifie si la liste est paire (si pas paire la liste est érroné)
    nb_resu=len(index)
    if nb_resu%2==0: 

        #variables qui vont donner les résultats      
        dico_results_full_list_nikto={}
        dico_type_per_vuln_nikto={}

        dico_osvdb_full_list_nikto={"cve_list":[]}
        

        #boucle qui s'éffectuer le nombre de fois qu'il y a une paire d'index existente (chaques groupe de paire représente un groupe de vuln)
        for i in range(0,int(nb_resu/2)):

            #crée un dic avec pour x groupe ses sorties associées  ex: {"result_groupe 2":["folder admin found","vuln sql"...]}
            dico_results_full_list_nikto["result_groupe {0}".format(i)]=result_nikto[index[i*2]:index[i*2+1]]

            #crée un dic avec pour chaques groupe leurs types type de service et port
            dico_type_per_vuln_nikto["type_groupe {0}".format(i)]=result_nikto[index[i*2]-1]

            numb_cve=i
            
            #boucle qui retourne  dans i chaques groupes de vuln ex ["deb","vuln1","vuln2","vuln3","fin"]
            for i in result_nikto[index[i*2]:index[i*2+1]]:


                cve_regex="OSVDB-[0-9]+"

            #pour chaques groupe, verif des cve présent et ajout dans 2 dico, cve par groupe et un avec toutes les cve
                if re.search(cve_regex,i):
                    
                    #vérifie qu'il n'y a pas de doublon de cve dans les listes cve groupe et cve full list
                    if re.search(cve_regex,i).group() in dico_osvdb_full_list_nikto["cve_list"]:

                        pass
                    
                    else:

                        dico_osvdb_full_list_nikto["cve_list"].append(re.search(cve_regex,i).group())

                                   
           
        return(dico_type_per_vuln_nikto,dico_results_full_list_nikto,dico_osvdb_full_list_nikto)
        #print(dico_results_full_list_nikto)
        #print(dico_type_per_vuln_nikto)
        #print(dico_osvdb_full_list_nikto)
        #print()


    else:
        
        #test affichage
        print("erreur, la liste index n'est pas paire")


#nikto("192.168.56.101")