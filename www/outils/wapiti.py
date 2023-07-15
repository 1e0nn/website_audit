from subprocess import check_output
import json
import os


def wapiti(url,mode):


    db_lst=["http-sql-injection","mysql","sql","MariaDB", "sqli","SQL Injection"]
    web_lst=["Apache","http ","https ","ssl/http","vulners","ssl-dh-params","http-csrf","crlf","CRLF Injection","csp","http_headers","csrf","cookieflags","exec","brute_login_form","htaccess","shellshock","ssrf","redirect","xss","xxe","permanentxss","methods","Content Security Policy Configuration","Cross Site Request Forgery","Potentially dangerous file","Command execution","Path Traversal","Htaccess Bypass","HTTP Secure Headers","HttpOnly Flag cookie","Open Redirect","Secure Flag cookie","Server Side Request Forgery","XML External Entity","Cross Site Scripting"]

    wapiti_web_lst = []
    wapiti_db = []
    wapiti_nb_web=0
    wapiti_nb_db=0
    cve_wapiti_web=[]
    cve_wapiti_db=[]

    chemin_reco = "~/website_audit/www/outils/wapiti_res.json"

    # Expansion du chemin avec le répertoire de l'utilisateur
    chemin_absolu = os.path.expanduser(chemin_reco)
    if os.path.exists(chemin_absolu):
        os.remove(chemin_absolu)

    if mode == "lent" :
        
        wapiti_web = check_output(["wapiti","-f","json","-o",chemin_absolu,"-u",url,"-m","backup,brute_login_form,cookieflags,crlf,csp,csrf,exec,file,htaccess,http_headers,methods,permanentxss,redirect,shellshock,sql,ssrf,xss,xxe"])

    elif mode == "rapide" :

        wapiti_web = check_output(["wapiti","-f","json","-o",chemin_absolu,"-u",url,"-m","brute_login_form,exec,htaccess,http_headers,redirect,sql,ssrf,xss,xxe"])

    


    with open(chemin_absolu) as json_file:
        data = json.load(json_file)


    value1 = data['vulnerabilities']

    wapiti_web_lst.append("-----------------")

    for i in value1:

        if i in web_lst:

            #print(i)
            if len(data['vulnerabilities'][i]) == 0:
                pass
            else:
                #wapiti_web_lst.append('<br>')
                wapiti_web_lst.append(f"{i}:")

                for item in data['vulnerabilities'][i]:

                    for key, value in item.items():
                        if key in "method":
                            wapiti_web_lst.append("-")
                        if key in "level":
                            cve_wapiti_web.append(value)
                        wapiti_web_lst.append(f"{key}: {value}")
                    wapiti_nb_web +=1

                wapiti_web_lst.append('------------------------------------------')

        elif i in db_lst:


            if len(data['vulnerabilities'][i]) == 0:
                pass
            else:
                #wapiti_db.append('<br>')
                wapiti_db.append(f"{i}: ")

                for item in data['vulnerabilities'][i]:


                    for key, value in item.items():
                        if key in "method":
                            wapiti_db.append("-")
                        if key in "level":
                            cve_wapiti_db.append(value)
                        wapiti_db.append(f"{key}: {value}")
                    wapiti_nb_db +=1
                                
                wapiti_db.append('------------------------------------------')

        else:
            print("error")

    #print(wapiti_web,wapiti_db)
    #for i in wapiti_web:
        #print(i)

    #for i in wapiti_db:
        #print(i)

    print(wapiti_web_lst,wapiti_db,cve_wapiti_web,cve_wapiti_db, wapiti_nb_web,wapiti_nb_db)

    os.remove(chemin_absolu)
    
    return (wapiti_web_lst,wapiti_db,cve_wapiti_web,cve_wapiti_db,wapiti_nb_web,wapiti_nb_db)
    


#wapiti("http://192.168.1.200/mutillidae","rapide")


