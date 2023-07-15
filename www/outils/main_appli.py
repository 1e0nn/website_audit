import os
import sys
import json
import re
from wapiti import wapiti
from nmap_vulscan_cve import nmap_vulscan_cve
from nmap_vuln import nmap_vuln
from nmap_vulscan_vuldb import nmap_vulscan_vuldb
from nikto import nikto
from script_cve import cvss_main


# Chemin avec la notation tilde (~)
chemin_reco = "~/website_audit/www/outils/reco"

# Expansion du chemin avec le répertoire de l'utilisateur
chemin_absolu = os.path.expanduser(chemin_reco)

# Ajout du chemin absolu au chemin de recherche des modules
sys.path.append(chemin_absolu)


from script_reco import *


#from start_cve import *

def main_appli(url,mode):


    serv_lst=["ftp","smb","SMB"]
    db_lst=["http-sql-injection","mysql","sql","MariaDB", "sqli","SQL Injection"]
    web_lst=["Apache","http ","https ","ssl/http","vulners","ssl-dh-params","http-csrf","crlf","CRLF","injections","csp","http_headers","csrf","cookieflags","exec","brute_login_form","htaccess","shellshock","ssrf","redirect","xss","xxe","permanentxss","methods"]
    convert_service=[]
    cve_service=[]
    cve_web=[]
    cve_db=[]
    convert_web=[]
    convert_db=[]
    service=[]
    web=[]
    db=[]
    nb_db=0
    nb_web=0
    nb_service=0
  
        

    #---------------------------PARTIE RECONNAISANCE --------------------------------------------------------------------------------------------------------------------
    os.system("rm ~/website_audit/www/static/rapport/reco.json")
    os.system("rm ~/website_audit/www/static/rapport/cpts.json")
    #os.system("touch ~/website_audit/www/static/rapport/reco.json")

    cpt_infos_reco = main_reco(url,mode)

    dico_type_per_group_vuln,dico_results_per_group_vuln,dico_cve_full_list_vuln,dico_cve_per_group_vuln = nmap_vuln(url)

    dico_type_per_group_vuldb,dico_results_per_group_vuldb,dico_cve_full_list_vuldb,dico_cve_per_group_vuldb = nmap_vulscan_vuldb(url)
    
    type,group,cve,cve_group = nmap_vulscan_cve(url)

    #final_score,low_vuln_count,mid_vuln_count,high_vuln_count,critical_vuln_count  = cve_concatenate(dico_cve_full_list_vuln,cve)


    if mode == "lent" :

        dico_type_per_vuln_nikto,dico_results_full_list_nikto,dico_osvdb_full_list_nikto = nikto(url)

        print(" --------NIKTO------------- ")

        print(dico_type_per_vuln_nikto,dico_results_full_list_nikto,dico_osvdb_full_list_nikto)


        vl_list=list(dico_type_per_vuln_nikto.values())

        for idx,i in enumerate(vl_list):

            type_gr=i
            
            #web
            for i in web_lst:
                if re.search(i,type_gr):
                    #web.append(idx)
                    #print(re.search(i,type_gr))
                    #for i in dico_osvdb_full_list_nikto[f"cve_list"]:
                    #    cve_web.append(i)
                    for i in dico_results_full_list_nikto[f"result_groupe 0"]:
                        convert_web.append(i)
                        nb_web +=1
                        
                    break

        wapiti_web_lst,wapiti_db,cve_wapiti_web,cve_wapiti_db, wapiti_nb_web,wapiti_nb_db = wapiti(url, mode)

    if mode == "rapide" :

        wapiti_web_lst,wapiti_db,cve_wapiti_web,cve_wapiti_db, wapiti_nb_web, wapiti_nb_db = wapiti(url, mode)
    


    donnees_cpt = {
              "cpt_reco" : cpt_infos_reco,
              #"cpt_low_vuln" : low_vuln_count,
              #"cpt_mid_vuln" : mid_vuln_count,
              #"cpt_high_vuln" : high_vuln_count,
              #"cpt_critical_vuln" : critical_vuln_count,
       }

    donnees_json = json.dumps(donnees_cpt)

    chemin_cpts = "~/website_audit/www/static/rapport"
    chemin_absolu_cpts = os.path.expanduser(chemin_cpts)

    with open(f"{chemin_absolu_cpts}/cpts.json", "a") as f:

              f.write(donnees_json)

    #return final_score,low_vuln_count,mid_vuln_count,high_vuln_count,critical_vuln_count,

    #---------------------------PARTIE DETECTION VULN --------------------------------------------------------------------------------------------------------------------


    print(" ----------WAPITI----------- ")


    print(wapiti_web_lst,wapiti_db,cve_wapiti_web,cve_wapiti_db, wapiti_nb_web, wapiti_nb_db)


    #web
    for i in wapiti_web_lst:
        convert_web.append(i)
    nb_web += wapiti_nb_web

    #db
    for i in wapiti_db:
        convert_db.append(i)
    nb_db += wapiti_nb_db



    print(" ----------VULSCAN CVE----------- ")

    #vulscan cve
    print(type,group,cve,cve_group)

    vl_list=list(type.values())

    for idx,i in enumerate(vl_list):

        type_gr=i

        #web
        for i in web_lst:
            if re.search(i,type_gr):
                #web.append(idx)
                #print(re.search(i,type_gr))
                for i in cve_group[f"cve_groupe {idx}"]:
                    cve_web.append(i)
                for i in group[f"result_groupe {idx}"]:
                    convert_web.append(i)
                    nb_web +=1
                break
        #db
        for i in db_lst:
            if re.search(i,type_gr):
                #db.append(idx)
                #print(re.search(i,type_gr))
                for i in cve_group[f"cve_groupe {idx}"]:
                    cve_db.append(i)
                for i in group[f"result_groupe {idx}"]:
                    convert_db.append(i)
                    nb_db +=1

                break
        #service
        for i in serv_lst:
            if re.search(i,type_gr):
                #service.append(idx)
                #print(re.search(i,type_gr))
                for i in cve_group[f"cve_groupe {idx}"]:
                    cve_service.append(i)
                for i in group[f"result_groupe {idx}"]:
                    convert_service.append(i)
                    nb_service +=1
                break


    print(" ----------VULSCAN VULDB----------- ")

    #vulscan vuldb
    print(dico_type_per_group_vuldb,dico_results_per_group_vuldb,dico_cve_full_list_vuldb,dico_cve_per_group_vuldb)


    vl_list=list(dico_type_per_group_vuldb.values())

    for idx,i in enumerate(vl_list):

        type_gr=i
        
        #web
        for i in web_lst:
            if re.search(i,type_gr):
                #web.append(idx)
                #print(re.search(i,type_gr))
                #for i in dico_cve_per_group_vuldb[f"cve_groupe {idx}"]:
                #    cve_web.append(i)
                for i in dico_results_per_group_vuldb[f"result_groupe {idx}"]:
                    convert_web.append(i)
                    nb_web +=1
                break
        #db
        for i in db_lst:
            if re.search(i,type_gr):
                #db.append(idx)
                #print(re.search(i,type_gr))
                #for i in dico_cve_per_group_vuldb[f"cve_groupe {idx}"]:
                #    cve_db.append(i)
                for i in dico_results_per_group_vuldb[f"result_groupe {idx}"]:
                    convert_db.append(i)
                    nb_db +=1
                break
        #service
        for i in serv_lst:
            if re.search(i,type_gr):
                #service.append(idx)
                #print(re.search(i,type_gr))
                #for i in dico_cve_per_group_vuldb[f"cve_groupe {idx}"]:
                #    cve_service.append(i)
                for i in dico_results_per_group_vuldb[f"result_groupe {idx}"]:
                    convert_service.append(i)
                    nb_service +=1
                break






    print(" --------VULN------------- ")


    print(dico_type_per_group_vuln,dico_results_per_group_vuln,dico_cve_full_list_vuln,dico_cve_per_group_vuln)


    vl_list=list(dico_type_per_group_vuln.values())

    for idx,i in enumerate(vl_list):

        type_gr=i
        
        #web
        for i in web_lst:
            if re.search(i,type_gr):
                #web.append(idx)
                #print(re.search(i,type_gr))
                for i in dico_cve_per_group_vuln[f"cve_groupe {idx}"]:
                    cve_web.append(i)
                for i in dico_results_per_group_vuln[f"result_groupe {idx}"]:
                    convert_web.append(i)
                    nb_web+=1
                break
        #db
        for i in db_lst:
            if re.search(i,type_gr):
                #db.append(idx)
                #print(re.search(i,type_gr))
                for i in dico_cve_per_group_vuln[f"cve_groupe {idx}"]:
                    cve_db.append(i)
                for i in dico_results_per_group_vuln[f"result_groupe {idx}"]:
                    convert_db.append(i)
                    nb_db +=1
                break
        #service
        for i in serv_lst:
            if re.search(i,type_gr):
                #service.append(idx)
                #print(re.search(i,type_gr))
                for i in dico_cve_per_group_vuln[f"cve_groupe {idx}"]:
                    cve_service.append(i)
                for i in dico_results_per_group_vuln[f"result_groupe {idx}"]:
                    convert_service.append(i)
                    nb_service +=1
                break


    
    
    print(web,db,service)
    print(convert_web)
    print(convert_db)
    print(convert_service)


    # Ajout des éléments de la liste dans le dictionnaire

    json_web = {
        "nb_web": nb_web,
        "web": convert_web
    }

    json_db = {
        "nb_db": nb_db,
        "db": convert_db
    }


    json_service = {
        "nb_service": nb_service,
        "service": convert_service
    }

    chemin_vuln = "~/website_audit/www/static/rapport"
    chemin_absolu = os.path.expanduser(chemin_vuln)

    nom_fichier=["json_web","json_db","json_service",json_web,json_db,json_service]

    # Écriture du JSON dans le fichier
    for i in range (3):
        with open(f"{chemin_absolu}/{nom_fichier[i]}.json", "w") as fichier:
            json.dump(nom_fichier[i+3], fichier)

    print("\n cript léo fini")

    cvss_main(cve_web,cve_db,cve_service,cve_wapiti_web,cve_wapiti_db)
    
    return cpt_infos_reco


#main_appli("http://192.168.1.200/mutillidae","rapide")