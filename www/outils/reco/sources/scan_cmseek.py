import os
import glob
from subprocess import check_output
import shutil


def scan_cmseek(x) :
    
    chemin_cms = "~/website_audit/www/static/rapport/"
    chemin_absolu = os.path.expanduser(chemin_cms)
    lst_1=["cmseek_rapport.txt","reports.json","Result"]


    #if glob.glob('**/static/rapport/cms.json', recursive=True):
        #print(glob.glob('**/static/rapport/cms.json', recursive=True))
        #os.remove(f'{chemin_absolu}cms.json')

    if os.path.exists(f'{chemin_absolu}cms.json'):
        os.remove(f'{chemin_absolu}cms.json')    

    def del_files(list):

        for i in (list):
            cms_path=(glob.glob(f'**/{i}', recursive=True))
            for i in range (len(cms_path)):
                try:
                    os.remove(cms_path[i])
                except:
                    shutil.rmtree(cms_path[i])
    del_files(lst_1)

    os.system("cmseek -u" + x + " > cmseek_rapport.txt")



    cms_path=glob.glob('**/Result/**/cms.json', recursive=True)
    shutil.move(cms_path[0], chemin_absolu)

    del_files(lst_1)

    return 

#scan_cmseek("http://10.6.1.27/mutillidae")