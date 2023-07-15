#!/usr/bin/env python
import requests
from subprocess import check_output
import json
import os
import sys


def cvss_main(cve_web,cve_db,cve_service,cve_wapiti_web,cve_wapiti_db):

    print("\n script tommy")


    def calculate_cvss_score(cvss):
        if cvss <= 3.9:
            score = "low"
        elif cvss <= 6.9:
            score = "medium"
        elif cvss <= 8.9:
            score = "high"
        else:
            score = "critical"

        return score
    

    def calculate_final_score(cve_list,int_list):



        high_vuln_count = 0
        mid_vuln_count = 0
        low_vuln_count = 0
        critical_vuln_count = 0
        total_vuln_count = 0
        max_vuln_score = None

        for cve in int_list:            
            
            if type(cve) == int:
                
                score = calculate_cvss_score(cve)
                print(f"lvl wapiti: {cve} | Score: {score}")

                if score == "high":
                    high_vuln_count += 1
                elif score == "medium":
                    mid_vuln_count += 1
                elif score == "low":
                    low_vuln_count += 1
                elif score == "critical":
                    critical_vuln_count += 1
                total_vuln_count += 1

                if max_vuln_score is None or cve > max_vuln_score:
                    max_vuln_score = cve
            else:
                print("liste chiffre wap error")

        for cve in cve_list:

            url = f"https://cve.circl.lu/api/cve/{cve}"
            response = requests.get(url)

            if response.status_code == 200:
                try:
                    data = response.json()
                    if data is not None and 'cvss' in data:
                        cvss = data['cvss']
                        if cvss :
                            score = calculate_cvss_score(cvss)
                            print(f"CVE: {cve} | Score: {score}")
            
                            if score == "high":
                                high_vuln_count += 1
                            elif score == "medium":
                                mid_vuln_count += 1
                            elif score == "low":
                                low_vuln_count += 1
                            elif score == "critical":
                                critical_vuln_count += 1
                            total_vuln_count += 1

                            if max_vuln_score is None or cvss > max_vuln_score:
                                max_vuln_score = cvss
                    else:
                        print(f"CVSS score not found for {cve}")
                except ValueError:
                    print(f"Invalid JSON data for {cve}")
            else:
                print(f"Failed to fetch JSON data for {cve}")

        if total_vuln_count == 0:
            final_score = "N/A"
        elif max_vuln_score is not None and max_vuln_score <= 3.9:
            final_score = "low"
        elif high_vuln_count >= 4:
            final_score = "critical"
        elif max_vuln_score is not None and max_vuln_score <= 6.9:
            final_score = "medium"
        elif max_vuln_score is not None and max_vuln_score >= 8.9:
            final_score = "critical"
        else:
            final_score = "high"

        return final_score,low_vuln_count,mid_vuln_count,high_vuln_count,critical_vuln_count 
    
    cve_wapiti_null = []
    cve_web = list(set(cve_web))
    cve_db = list(set(cve_db))
    cve_service = list(set(cve_service))
    
    final_score_web = calculate_final_score(cve_web,cve_wapiti_web)
    final_score_db = calculate_final_score(cve_db,cve_wapiti_db)
    final_score_service = calculate_final_score(cve_service,cve_wapiti_null)




    print(cve_web,cve_db,cve_service)


    final_score_site = ["",0,0,0,0]

    lst_test=[final_score_web ,final_score_db,final_score_service]

    for idx,i in enumerate(lst_test):
        final_score_site[1] += i[1]
        final_score_site[2] += i[2]
        final_score_site[3] += i[3]
        final_score_site[4] += i[4]


    if final_score_site[1] and final_score_site[2] and final_score_site[3] and final_score_site[4] == 0:
        final_score_site[0] = "N/A"
    if final_score_site[1] is not None and final_score_site[1] >= 1:
        final_score_site[0] = "low"
    if final_score_site[2] is not None and final_score_site[2] >= 1:
        final_score_site[0] = "medium"
    if final_score_site[3] is not None and final_score_site[3] <= 3:
        final_score_site[0] = "high"     
    if final_score_site[3] is not None and final_score_site[3] >= 4:
        final_score_site[0] = "critical"  
    if final_score_site[4] >= 1:
        final_score_site[0] = "critical"



    #cve_site.extend(cve_web)
    #cve_site.extend(cve_db)
    #cve_site.extend(cve_service)
    #final_score_site = calculate_final_score(cve_site,cve_wapiti_null)
    
    data_cvss = {
    "score": [
        final_score_site[0],
        final_score_site[1],
        final_score_site[2],
        final_score_site[3],
        final_score_site[4]
    ],
    "web": [
        final_score_web[0],
        final_score_web[1],
        final_score_web[2],
        final_score_web[3],
        final_score_web[4]
    ],
    "db": [
        final_score_db[0],
        final_score_db[1],
        final_score_db[2],
        final_score_db[3],
        final_score_db[4]
    ],
    "service": [
        final_score_service[0],
        final_score_service[1],
        final_score_service[2],
        final_score_service[3],
        final_score_service[4]
    ]
    }

    chemin_reco = "~/website_audit/www/static/rapport"

    # Expansion du chemin avec le répertoire de l'utilisateur
    chemin_absolu = os.path.expanduser(chemin_reco)

    # Ajout du chemin absolu au chemin de recherche des modules
    sys.path.append(chemin_absolu)

    with open(f'{chemin_absolu}/data_cvss.json', 'w', encoding='utf-8') as f:
        json.dump(data_cvss, f, ensure_ascii=False, indent=4)

#cvss_main(cve_web,cve_db,cve_service,cve_wapiti_web,cve_wapiti_db)