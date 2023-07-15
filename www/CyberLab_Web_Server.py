from flask import Flask, jsonify, request, render_template, send_file

app=Flask(__name__)

@app.route('/',methods=['GET'])
def home():

    if request.method == 'GET':

        return render_template('home.html')



@app.route('/loading',methods=['GET'])
def loading():
    
    if request.method == 'GET':

        return render_template('loading.html')

@app.route('/rapport',methods=['GET'])
def rapport():

    if request.method == 'GET':

        return render_template('rapport.html')


@app.route('/verif',methods=['POST'])
def verif_ip():
    #import re
    import validators


    if request.method == 'POST':
 
        dico_requete=request.form.to_dict()
        mode = dico_requete['mode']
        lien = dico_requete['url']
        print("la requete verif fonctionne",lien,mode,)
        validation = validators.url(lien)
        
        if mode in ("rapide","lent") and validation:

            return ('',201)
        else:
            print("l'url rentré n'est pas bon")
            return('',500)


@app.route('/lance_rapport',methods=['POST'])
def lancer_rapport():
    #import time
    import validators
    import sys
    import os
    from urllib.parse import urlparse
    import datetime
    import shutil

    chemin_reco = "~/website_audit/www/outils"
    # Expansion du chemin avec le répertoire de l'utilisateur
    chemin_absolu = os.path.expanduser(chemin_reco)
    # Ajout du chemin absolu au chemin de recherche des modules
    sys.path.append(chemin_absolu)

    from main_appli import main_appli


    if request.method == 'POST':

        dico_requete=request.form.to_dict()
        mode = dico_requete['mode']
        lien = dico_requete['url']
        print("la requete verif fonctionne",lien,mode,)
        validation = validators.url(lien)


        if mode in ("rapide","lent") and validation:


            parsed_url = urlparse(lien)
            doss_rapport = parsed_url.netloc

            doss_rapport = f'{doss_rapport}-{mode}-{str(datetime.date.today())}'
            chemin = "~/website_audit/www/static/rapport/"
            chemin_absolu = os.path.expanduser(chemin)

            path = os.path.join(chemin_absolu, doss_rapport)

            if os.path.isdir(path):
                shutil.rmtree(path)

            os.mkdir(path)

            main_appli(lien,mode)

            lst_json=["cms.json","cpts.json","data_cvss.json","json_web.json","json_db.json","json_service.json","reco.json"]

            for i in lst_json:
                shutil.copy(f"{chemin_absolu}{i}", f"{path}/{i}")

            # *crée le rapport et pépaère la requete json et ses var* #
            print("la requete lance_rapport fonctionne",lien,mode,)

            # *une fois fini renvoie le lien pour au site pour quitter loading et afficher le rapport final* #
            lien_rapport='/rapport'

            #win32api.MessageBox(0, f'Le mode {mode} a été séléctionné pour le lien: {lien}', 'Python', 0x00001000)
            return jsonify({'rapport': lien_rapport}), 201
    
        else:
            
            print("error pour le lancement du rapport")
            return('',500)
           

@app.route('/all_reports',methods=['POST'])
def all_reports():
    import os
    import shutil


    if request.method == 'POST':

        dico_requete=request.form.to_dict()
        print(dico_requete)
        mode = dico_requete['mode']
        select = dico_requete['select']
        print("la requete all reports fonctionne",mode)

        if mode in ("recup"):

            print("recup fonctionne")

            chemin = "~/website_audit/www/static/rapport/"
            chemin_absolu = os.path.expanduser(chemin)

            noms_dossiers = []
            for nom in os.listdir(chemin_absolu):
                chemin = os.path.join(chemin_absolu, nom)
                if os.path.isdir(chemin):
                    noms_dossiers.append(nom)

            return jsonify({'reports': noms_dossiers}), 201
        elif mode in ("change"):

            chemin = "~/website_audit/www/static/rapport/"
            chemin_absolu = os.path.expanduser(chemin)

            if os.path.isdir(f"{chemin_absolu}{select}"):

                print(f"ce dosssier existe {chemin_absolu}{select}")
                
                lst_json=["cms.json","cpts.json","data_cvss.json","json_web.json","json_db.json","json_service.json","reco.json"]

                for i in lst_json:

                    if os.path.isdir(i):
                        shutil.remove(f"{chemin_absolu}{i}")
                        print(f"{chemin_absolu}{i} supprimé")

                    print(f"{chemin_absolu}{select}/{i} copié vers {chemin_absolu}{i}")
                    shutil.copy(f"{chemin_absolu}{select}/{i}",f"{chemin_absolu}{i}", ) 
                print("change à fonctionne ce dossier à été chargé", select)
                return (''), 201
            else:
                print("dossier à charger pas existant")
                return ('',501)
        else:

            print("error all reports")
            return('',500)


    
@app.route('/fichier.json',methods=['GET'])
def rapport_info_f():

    if request.method == 'GET':

        # Chemin d'accès au fichier JSON
        chemin_fichier = 'static/rapport/data_cvss.json'
        return send_file(chemin_fichier, mimetype='application/json'),200
    

@app.route('/cpts.json',methods=['GET'])
def rapport_info_c():

    if request.method == 'GET':

        # Chemin d'accès au fichier JSON
        chemin_fichier = 'static/rapport/cpts.json'

        return send_file(chemin_fichier, mimetype='application/json'),200

@app.route('/reco.json',methods=['GET'])
def rapport_info_r():

    if request.method == 'GET':

        # Chemin d'accès au fichier JSON
        chemin_fichier = 'static/rapport/reco.json'

        return send_file(chemin_fichier, mimetype='application/json'),200
    

@app.route('/cms.json',methods=['GET'])
def rapport_info_cms():

    if request.method == 'GET':

        # Chemin d'accès au fichier JSON
        chemin_fichier = 'static/rapport/cms.json'

        return send_file(chemin_fichier, mimetype='application/json'),200
    

    
@app.route('/json_db.json',methods=['GET'])
def rapport_info_db():

    if request.method == 'GET':

        # Chemin d'accès au fichier JSON
        chemin_fichier = 'static/rapport/json_db.json'

        return send_file(chemin_fichier, mimetype='application/json'),200
    
    

@app.route('/json_web.json',methods=['GET'])
def rapport_info_web():

    if request.method == 'GET':

        # Chemin d'accès au fichier JSON
        chemin_fichier = 'static/rapport/json_web.json'

        return send_file(chemin_fichier, mimetype='application/json'),200
    

@app.route('/json_service.json',methods=['GET'])
def rapport_info_service():

    if request.method == 'GET':

        # Chemin d'accès au fichier JSON
        chemin_fichier = 'static/rapport/json_service.json'

        return send_file(chemin_fichier, mimetype='application/json'),200




if __name__=="__main__":
    app.run(host='0.0.0.0', port=80, debug=False)