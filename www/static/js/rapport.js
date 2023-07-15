// declar var

var coll = document.getElementsByClassName("collapsible");
var i;
const btn = document.getElementById("dl");
const gaugeElement = document.querySelector(".gauge");
let content = '';
let ninfos=0;
let vuln_total=0;
let nb_tot_cve=0;
let score=""
let cve_web=""
let cve_db=""
let cve_service= ""
let all_reports =''



function setGaugeValue(gauge, value) {
  if (value < 0 || value > 1) {
    return;
  }

  gauge.querySelector(".gauge__fill").style.transform = `rotate(${
    value / 2
  }turn)`;
  if (value <= 0.39){
    gauge.querySelector(".gauge__fill").style.background = `green`;
  };
  if (value > 0.39 &&  value <= 0.69 ){
    gauge.querySelector(".gauge__fill").style.background = `yellow`;
  }
  if (value > 0.68 &&  value <= 0.89 ){
    gauge.querySelector(".gauge__fill").style.background = `orange`;
  }
  if (value > 0.89 &&  value <= 1 ){
    gauge.querySelector(".gauge__fill").style.background = `red`;
  }
  //gauge.querySelector(".gauge__cover").textContent = `${Math.round(
  //  value * 100
  //)}%`;

}

function toggleText(buttonId) {
  var element = document.getElementById('expanded-text' + buttonId);
  var button = document.getElementById('colaps'+ buttonId);

  if (buttonId === buttonId) {
    // Action à effectuer si la variable est égale à elle-même
    element.style.display = "flex";
    button.setAttribute("style", "text-decoration: underline;");

    // Vérification si la variable moins 1 est impaire
    if ((buttonId - 1) % 2 !== 0) {
      // Action à effectuer si la variable moins 1 est impaire
      var previousElement = document.getElementById('expanded-text' + (buttonId - 1));
      var previousButton = document.getElementById('colaps'+ (buttonId - 1));
      previousElement.style.display = "none";
      previousButton.removeAttribute("style");
    }
  
    // Vérification si la variable plus 1 est paire
    if ((buttonId + 1) % 2 === 0) {
      // Action à effectuer si la variable plus 1 est paire
      var nextElement = document.getElementById('expanded-text' + (buttonId + 1));
      var nextButton = document.getElementById('colaps'+ (buttonId + 1));
      nextElement.style.display = "none";
      nextButton.removeAttribute("style");
    }
  }
  
}


function def_dyn(score_f,totvuln){

  const def_vuln1 = document.querySelector('#def_vuln1');
  const jauge = document.querySelector('#gauge_id');  
  const expanded_text3 = document.querySelector('#expanded-text3');  
  const expanded_text5 = document.querySelector('#expanded-text5');  
  const expanded_text7 = document.querySelector('#expanded-text7'); 
  const def_det = document.querySelector('#def_det'); 
  const lvl_web = document.querySelector('#lvl_web');  
  const lvl_db = document.querySelector('#lvl_db');  
  const lvl_service = document.querySelector('#lvl_service'); 
  const lvl_web2 = document.querySelector('#lvl_web2');  
  const lvl_db2 = document.querySelector('#lvl_db2');  
  const lvl_service2 = document.querySelector('#lvl_service2'); 

  const lst_quer_sel=[expanded_text3,expanded_text5,expanded_text7,lvl_web,lvl_db,lvl_service,lvl_web2,lvl_db2,lvl_service2];
  
  const lst_web=["Les vulnérabilités de niveau faible spécifiques au Web peuvent inclure des problèmes tels que les avertissements de sécurité mineurs, les informations de débogage exposées, les erreurs de configuration mineures ou les faibles exigences de mot de passe. Bien que ces vulnérabilités puissent avoir un impact limité, elles nécessitent néanmoins une attention pour maintenir un niveau de sécurité élevé.",
  "Les vulnérabilités de niveau moyen spécifiques au Web peuvent inclure des problèmes tels que les fuites d'informations sensibles, les vulnérabilités de sécurité du contenu, les problèmes de gestion des erreurs ou les faiblesses dans les mécanismes d'authentification. Ces vulnérabilités peuvent présenter des risques limités, mais nécessitent une attention pour éviter les exploitations potentielles.",
  "Les vulnérabilités web peuvent inclure des failles de sécurité telles que les injection de code malveillant, fichiers malveillants... Ainsi que des failles de sécurité liées à la gestion des sessions. Ces vulnérabilités peuvent permettre à un attaquant d'accéder à des informations sensibles, de prendre le contrôle du site Web ou de compromettre la sécurité des utilisateurs."];

  const lst_db=["Les vulnérabilités de niveau faible spécifiques aux bases de données peuvent inclure des problèmes tels que les avertissements de sécurité mineurs, les erreurs de configuration mineures, les recommandations de sécurité non respectées. Bien qu'elles puissent présenter un risque faible, elles nécessitent néanmoins une attention pour éviter tout impact indésirable.",
  "Les vulnérabilités de niveau moyen spécifiques aux bases de données peuvent inclure des problèmes tels que les vulnérabilités des procédures stockées, les erreurs de configuration des paramètres de sécurité, les vulnérabilités des connexions réseau ou les problèmes de gestion des erreurs. Ces vulnérabilités peuvent présenter un risque modéré, nécessitant une attention pour éviter les exploitations potentielles.",
  "Les vulnérabilités spécifiques aux bases de données peuvent inclure des problèmes tels que les injections SQL, les erreurs de configuration des bases de données, les privilèges d'accès excessifs, les failles d'authentification ou les vulnérabilités liées aux mécanismes de chiffrement des données. Ces vulnérabilités peuvent permettre à un attaquant de compromettre la confidentialité, l'intégrité ou la disponibilité des données stockées dans la base de données."];

  const lst_service=["Les vulnérabilités de niveau faible spécifiques aux services peuvent inclure des problèmes tels que les avertissements de sécurité mineurs, les erreurs de configuration mineures ou les faibles exigences de mot de passe pour les services. Bien que ces vulnérabilités puissent avoir un impact limité, elles nécessitent néanmoins une attention pour maintenir un niveau de sécurité optimal.",
  "Les vulnérabilités de niveau moyen spécifiques aux services peuvent inclure des problèmes tels que les vulnérabilités des serveurs web, des serveurs de fichiers, des serveurs VPN. Ces vulnérabilités peuvent présenter des risques limités, mais nécessitent tout de même une attention pour éviter les exploitations potentielles.",
  "Les vulnérabilités spécifiques aux services peuvent inclure des problèmes tels que les failles de sécurité dans les protocoles de communication, les vulnérabilités des services exposés sur le réseau, les erreurs de configuration des services ou les faiblesses dans les mécanismes d'authentification. Ces vulnérabilités peuvent permettre à un attaquant de compromettre la sécurité des services, d'accéder à des informations sensibles ou de perturber leur fonctionnement."];

  const lst_full=[lst_web,lst_db,lst_service];
  const lst_type=[cve_web[0],cve_db[0],cve_service[0]];

  for (var [index, i] of lst_type.entries()){

    //console.log(index + i)
    if (i === "low"){

      lst_quer_sel[index].innerHTML = lst_full[index][0];
      lst_quer_sel[index+3].innerHTML = "Faible";
      lst_quer_sel[index+6].innerHTML = "Faible";
      lst_quer_sel[index + 3].style.color = "green";
      lst_quer_sel[index + 6].style.color = "green";

      
    } else if (i === "medium"){

      lst_quer_sel[index].innerHTML = lst_full[index][1];
      lst_quer_sel[index+3].innerHTML = "Moyen";
      lst_quer_sel[index+6].innerHTML = "Moyen";
      lst_quer_sel[index + 3].style.color = "yellow";
      lst_quer_sel[index + 6].style.color = "yellow";



    } else if (i === "high"){
  
      lst_quer_sel[index].innerHTML = lst_full[index][2];
      lst_quer_sel[index+3].innerHTML = "Élevée";
      lst_quer_sel[index+6].innerHTML = "Élevée";
      lst_quer_sel[index + 3].style.color = "orange";
      lst_quer_sel[index + 6].style.color = "orange";



    } else if (i === "critical"){

      lst_quer_sel[index].innerHTML = lst_full[index][2];
      lst_quer_sel[index+3].innerHTML = "Critique";
      lst_quer_sel[index+6].innerHTML = "Critique";
      lst_quer_sel[index + 3].style.color = "red";
      lst_quer_sel[index + 6].style.color = "red";

    
    }


  };

  if (score_f[0] === "low"){

    setGaugeValue(gaugeElement, 0.25);
    jauge.innerHTML = "Faible";
    def_vuln1.innerHTML = "Niveau de vulnérabilité du site bas, elles peuvent inclure des problèmes mineurs tels que les avertissements de sécurité mineurs, les erreurs de configuration mineures, les recommandations de sécurité non respectées. Bien qu'elles puissent présenter un risque faible, elles nécessitent néanmoins une attention pour éviter tout impact. "+totvuln+" Vulnérabilités au total ont été trouvées sur votre site";
    def_det.innerHTML = "Niveau de vulnérabilité du site bas. "+totvuln+" Vulnérabilités ont été trouvées sur votre site et "+nb_tot_cve+" CVE trouvées.";

  } else if (score_f[0] === "medium"){

    setGaugeValue(gaugeElement, 0.5);
    jauge.innerHTML = "Moyen";
    def_vuln1.innerHTML = "Niveau de vulnérabilité du site moyen, elles peuvent inclure des problèmes tels que les erreurs de configuration mineures, les faiblesses des contrôles d'accès, les vulnérabilités des applications tierces, les vulnérabilités des protocoles réseau, etc. Bien qu'elles ne soient pas aussi critiques que les vulnérabilités de haut niveau, elles nécessitent néanmoins une attention pour éviter toute exploitation potentielle. "+totvuln+" Vulnérabilités ont été trouvées sur votre site";
    def_det.innerHTML = "Niveau de vulnérabilité du site moyen. "+totvuln+" Vulnérabilités ont été trouvées sur votre site et "+nb_tot_cve+" CVE trouvées.";



  } else if (score_f[0] === "high"){

    setGaugeValue(gaugeElement, 0.75);
    jauge.innerHTML = "Élevé";
    def_vuln1.innerHTML = "Niveau de vulnérabilité du site élevé, elles peuvent inclure des problèmes tels que les failles de sécurité majeures, les accès non autorisés, les attaques de déni de service, les fuites de données sensibles, etc. Ces vulnérabilités peuvent entraîner des conséquences graves, compromettant la confidentialité, l'intégrité et la disponibilité des systèmes et des données. "+totvuln+" Vulnérabilités ont été trouvées sur votre site";
    def_det.innerHTML = "Niveau de vulnérabilité du site élevé. "+totvuln+" Vulnérabilités ont été trouvées sur votre site et "+nb_tot_cve+" CVE trouvées.";



  } else if (score_f[0] === "critical"){

    setGaugeValue(gaugeElement, 0.95);
    jauge.innerHTML = "Critique";
    def_vuln1.innerHTML = "Niveau de vulnérabilité du site critique, elles peuvent inclure des problèmes tels que les failles de sécurité majeures, les accès non autorisés, les attaques de déni de service, les fuites de données sensibles, etc. Ces vulnérabilités peuvent entraîner des conséquences graves, compromettant la confidentialité, l'intégrité et la disponibilité des systèmes et des données. "+totvuln+" Vulnérabilités ont été trouvées sur votre site";
    def_det.innerHTML = "Niveau de vulnérabilité du site critique. "+totvuln+" Vulnérabilités ont été trouvées sur votre site dont "+nb_tot_cve+" CVE trouvées.";

  }
};


//mettre las requetes ajax qui recup les infos des fichiers ici

// Charger le fichier JSON avec AJAX et effectué les modifs
const xhr_fi = new XMLHttpRequest();
xhr_fi.open('GET', 'fichier.json', true);
xhr_fi.onreadystatechange = function() {
  if (xhr_fi.readyState === 4 && xhr_fi.status === 200) {
    // Convertir le contenu en objet JavaScript
    const obj = JSON.parse(xhr_fi.responseText);
    score=obj.score;
    cve_web= obj.web
    cve_db= obj.db
    cve_service=  obj.service



    nb_tot_cve = parseInt(score[1]) + parseInt(score[2]) + parseInt(score[3]) + parseInt(score[4])

    const p_cve1 = document.querySelector("#p_cve1");
    const p_cve2 = document.querySelector("#p_cve2");
    const p_cve3 = document.querySelector("#p_cve3");
    const p_cve4 = document.querySelector("#p_cve4");
    const p_cve5 = document.querySelector("#p_cve5");
    const p_cve6 = document.querySelector("#p_cve6");
    const p_cve7 = document.querySelector("#p_cve7");
    const p_cve8 = document.querySelector("#p_cve8");
    const p_cve9 = document.querySelector("#p_cve9");
    const p_cve10 = document.querySelector("#p_cve10");
    const p_cve11 = document.querySelector("#p_cve11");
    const p_cve12 = document.querySelector("#p_cve12");
    const p_cve13 = document.querySelector("#p_cve13");
    const p_cve14 = document.querySelector("#p_cve14");
    const p_cve15 = document.querySelector("#p_cve15");
    const p_cve16 = document.querySelector("#p_cve16");
    const p_cvedet1 = document.querySelector("#p_cve_det1");
    const p_cvedet2 = document.querySelector("#p_cve_det2");
    const p_cvedet3 = document.querySelector("#p_cve_det3");
    const p_cvedet4 = document.querySelector("#p_cve_det4");


    var lst_pcve = [p_cve1, p_cve2, p_cve3, p_cve4, p_cve5, p_cve6, p_cve7, p_cve8, p_cve9, p_cve10, p_cve11, p_cve12, p_cve13,p_cve14, p_cve15, p_cve16];
    var lst_pcve_det = [p_cvedet1, p_cvedet2, p_cvedet3, p_cvedet4]
    var lst_vu= ["🟢 Vulnérabilités faible: ","🟡 Vulnérabilités moyenne: ","🟠 Vulnérabilités élevé: ","🔴 Vulnérabilités critique: "]
    var lst_vu_det= ["🟢 CVE faible: ","🟡 CVE moyen: ","🟠 CVE élevé: ","🔴 CVE critique: "]

    for (var i_i = 0; i_i < 8; i_i++){


      if (i_i < 4 ){

        lst_pcve[i_i].innerHTML=lst_vu[i_i]+score[i_i+1]
        lst_pcve_det[i_i].innerHTML=lst_vu_det[i_i]+score[i_i+1]


      } else if (i_i > 3 ) {

        lst_pcve[i_i].innerHTML=lst_vu_det[i_i-4]+cve_web[(i_i-4)+1]
        lst_pcve[i_i+4].innerHTML=lst_vu_det[i_i-4]+cve_db[(i_i-4)+1]
        lst_pcve[i_i+8].innerHTML=lst_vu_det[i_i-4]+cve_service[(i_i-4)+1]

      }

    }

  }

};
xhr_fi.send();

const xhr_cpts = new XMLHttpRequest();
xhr_cpts.open('GET', 'cpts.json', true);
xhr_cpts.onreadystatechange = function() {
  if (xhr_cpts.readyState === 4 && xhr_cpts.status === 200) {
    // Convertir le contenu en objet JavaScript
    const obj = JSON.parse(xhr_cpts.responseText);

    ninfos=obj.cpt_reco;

  }
  
};
xhr_cpts.send();


const xhr_info = new XMLHttpRequest();
xhr_info.open('GET', 'reco.json', true);
xhr_info.onreadystatechange = function() {
  if (xhr_info.readyState === 4 && xhr_info.status === 200) {
    // Convertir le contenu en objet JavaScript
    const obj = JSON.parse(xhr_info.responseText);
    const ip=obj.Adresses_IP;
    const whois=obj.whois;
    const nmap=obj.nmap_ports;

    const mac=obj.nmap_mac;
    const os=obj.nmap_os;
    const pages=obj.gobuster_pages;
    const sde=obj.gobuster_sde;


    const todelete=["==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============","Aucun Sous-Domaine d\u00e9t\u00e9ct\u00e9","Enumeration de pages Web indisponible pour ce site","Enumeration de domaine indisponible pour ce site"];
    const inf1 = document.querySelector("#inf1");
    const inf2 = document.querySelector("#inf2");
    const inf3 = document.querySelector("#inf3");



    inf1.innerHTML = "Adresse IP: "+ip
    content += `<div style="font-weight: bold;font-size: 1em;">Adresse IP: ${ip}</div>`;
    content += `<div>${ip}</div>`;

    if (os==""){
      inf2.innerHTML = "Système d'exploitation: Inconnu"
      content += `<div style="font-weight: bold;font-size: 1em;>Système d'exploitation: Inconnu</div>`;
      content += `<div>Inconnu</div>`;


    } else {
      inf2.innerHTML = "Système d'exploitation: "+os
      content += `<div style="font-weight: bold;font-size: 1em;">Système d'exploitation: </div>`;
      content += `<div>${os}</div>`;


    }
    inf3.innerHTML = "Adresse MAC: "+mac
    content += `<div style="font-weight: bold;font-size: 1em;">Adresse MAC: </div>`;
    content += `<div>${mac}</div>`;


    content += `<br style="margin-top: 1px;margin-bottom: 1px;"></br>`;
    content += `<div style="font-weight: bold;font-size: 1.2em;">Ports ouverts: </div>`;
    for (var port in nmap) {
      if (todelete.includes(nmap[port])) {
        continue; // Passe à l'itération suivante de la boucle
      }
      content += `<div>${nmap[port]}</div>`;
    }

    if (whois["ligne1"] === "I"){

      content += `<div>Aucune Informations relatifs au domaine trouvé</div>`;


    } else {

      content += `<br></br>`;
      content += `<div style="font-weight: bold;font-size: 1.2em;">Informations relatifs au domaine: </div>`;
      for (var l in whois) {
        content += `<div>${whois[l]}</div>`;
      }

    }

    if (todelete.includes(pages)){

      content += `<div>Aucune page détectée</div>`;

    } else {

      content += `<br></br>`;
      content += `<div style="font-weight: bold;font-size: 1.2em;">Pages trouvées: </div>`;
      for (var p in pages) {
        content += `<div>${pages[p]}</div>`;
      }

    }

    content += `<br></br>`;
    if (todelete.includes(sde)) {
      content += `<div style="font-weight: bold;font-size: 1.2em;">Aucun sous-domaine détecté</div>`;
    } else {
      content += `<div style="font-weight: bold;font-size: 1.2em;">Sous-domaine détectés: </div>`;

      for (var sd in sde) {

        content += `<div>${sde[sd]}</div>`;
      }
    }



  }
};
xhr_info.send();


const xhr_cms = new XMLHttpRequest();
xhr_cms.open('GET', 'cms.json', true);
xhr_cms.onreadystatechange = function() {
  if (xhr_cms.readyState === 4 && xhr_cms.status === 200) {
    // Convertir le contenu en objet JavaScript
    const obj = JSON.parse(xhr_cms.responseText);
    const cms_id=obj.cms_id;
    const cms_name=obj.cms_name;
    const cms_url=obj.cms_url;
    const detection_param=obj.detection_param;


    const lst_cms=["ID du CMS: "+cms_id,"URL du CMS: "+cms_url,"Paramètre de détection du CMS: "+detection_param];

    //déclare var
    const inf4 = document.querySelector("#inf4");
    const f_info = document.querySelector('#text_info');


    //déclare var
    const nb_infos = document.querySelector('#nb_infos');
    const nb_infos2 = document.querySelector('#nb_infos2');



    if ( cms_name === "" && cms_id === ""){

      content += `<br></br>`;
      inf4.innerHTML = "CMS: Non detecté";
      content += `<div style="font-weight: bold;font-size: 1.2em;">CMS: </div>`;
      content += `<div>Non detecté</div>`;

      ninfos +=1

    } else if (cms_id === "wp"){

      const wp_license=obj.wp_license
      const wp_plugins=obj.wp_plugins
      const wp_readme_file=obj.wp_readme_file
      const wp_themes=obj.wp_themes
      const wp_version=obj.wp_version
      ninfos +=9

      content += `<br></br>`;
      content += `<div style="font-weight: bold;font-size: 1.2em;">Nom du CMS: Wordpress</div>`;
      lst_cms.push("License Wordpress: "+wp_license,"Plugins: ",wp_plugins,"Thèmes WP: "+wp_themes,"Version WP: "+wp_version,"Fichier README: "+wp_readme_file)

      inf4.innerHTML ="Nom du CMS: Wordpress";
      for (var j_lst in lst_cms) {
        content += `<div>${lst_cms[j_lst]}</div>`;
      }


    } else if (cms_id === "joom") {

      const joomla_backup_files=obj.joomla_backup_files
      const joomla_config_files=obj.joomla_config_files
      const joomla_debug_mode=obj.joomla_debug_mode
      const joomla_readme_file=obj.joomla_readme_file
      const joomla_version=obj.joomla_version
      ninfos +=9


      inf4.innerHTML ="Nom du CMS: Joomla";
      content += `<br></br>`;
      content += `<div style="font-weight: bold;font-size: 1.2em;">"Nom du CMS: Joomla"</div>`;
      lst_cms.push("Fichier de configuration: ",joomla_config_files,"Debug mode: "+joomla_debug_mode,"Fichier README: "+joomla_readme_file,"Version joomla: "+joomla_version)

      for (var j_lst in lst_cms) {
        content += `<div>${lst_cms[j_lst]}</div>`;
      }
      content += `<div>Fichier de sauvegarde du CMS:</div>`;
      for (var el in joomla_backup_files) {
        content += `<div>${joomla_backup_files[el]}</div>`;
      } 

    } else if (cms_id === "wix") {

      inf4.innerHTML ="Nom du CMS: WIX";
      content += `<br></br>`;
      content += `<div style="font-weight: bold;font-size: 1.2em;">"Nom du CMS: WIX"</div>`;
      for (var j_lst in lst_cms) {
        content += `<div>${lst_cms[j_lst]}</div>`;
      }
      ninfos +=4

    } else if (cms_id === "shopify"){$
    
      inf4.innerHTML ="Nom du CMS: Shopify";
      content += `<br></br>`;
      content += `<div style="font-weight: bold;font-size: 1.2em;">"Nom du CMS: Shopify"</div>`;

      for (var j_lst in lst_cms) {
        content += `<div>${lst_cms[j_lst]}</div>`;
      }
      ninfos +=4
    
    };

    f_info.innerHTML = content;
    //change cpts info
    nb_infos.innerHTML = ninfos;
    nb_infos2.innerHTML = ninfos;
    
  }
  
};
xhr_cms.send();

const xhr_web = new XMLHttpRequest();
xhr_web.open('GET', 'json_web.json', true);
xhr_web.onreadystatechange = function() {
  if (xhr_web.readyState === 4 && xhr_web.status === 200) {
    const obj = JSON.parse(xhr_web.responseText);

    const nbweb = obj.nb_web;
    const fweb = obj.web;
    vuln_total += parseInt(nbweb);
    console.log(nbweb);
    console.log(vuln_total + "prems");

    const nb_web_ndt = document.querySelector('#nb_web');
    const nb_web = document.querySelector('#nb_scve_web');
    const f_web = document.querySelector('#text_web');

    nb_web_ndt.innerHTML = nbweb;
    nb_web.innerHTML = nbweb;

    fweb.forEach(function(item) {
      const line = document.createElement('div');
      line.textContent = item;
      f_web.appendChild(line);
    });

    // Lorsque la première requête est terminée, on exécute la deuxième requête
    executeXhrDb();
  }
};
xhr_web.send();

function executeXhrDb() {
  const xhr_db = new XMLHttpRequest();
  xhr_db.open('GET', 'json_db.json', true);
  xhr_db.onreadystatechange = function() {
    if (xhr_db.readyState === 4 && xhr_db.status === 200) {
      const obj = JSON.parse(xhr_db.responseText);

      const nbdb = obj.nb_db;
      const fsdb = obj.db;
      vuln_total += parseInt(nbdb);
      console.log(nbdb);
      console.log(vuln_total + "dexi");

      const nb_db_ndt = document.querySelector('#nb_db');
      const nb_db = document.querySelector('#nb_scve_db');
      const f_db = document.querySelector('#text_db');

      nb_db_ndt.innerHTML = nbdb;
      nb_db.innerHTML = nbdb;

      fsdb.forEach(function(item) {
        const line = document.createElement('div');
        line.textContent = item;
        f_db.appendChild(line);
      });

      // Lorsque la deuxième requête est terminée, on exécute la troisième requête
      executeXhrService();
    }
  };
  xhr_db.send();
}

function executeXhrService() {
  const xhr_service = new XMLHttpRequest();
  xhr_service.open('GET', 'json_service.json', true);
  xhr_service.onreadystatechange = function() {
    if (xhr_service.readyState === 4 && xhr_service.status === 200) {
      const obj = JSON.parse(xhr_service.responseText);

      const nbservice = obj.nb_service;
      const fservice = obj.service;
      vuln_total += parseInt(nbservice);
      console.log(nbservice);
      console.log(vuln_total + "final");
      def_dyn(score, vuln_total);

      const nb_service_ndt = document.querySelector('#nb_service');
      const nb_service = document.querySelector('#nb_scve_service');
      const f_service = document.querySelector('#text_service');

      nb_service_ndt.innerHTML = nbservice;
      nb_service.innerHTML = nbservice;

      fservice.forEach(function(item) {
        const line = document.createElement('div');
        line.textContent = item;
        f_service.appendChild(line);
      });
    }
  };
  xhr_service.send();
}


// Enregistrement du fichier en PDF

btn.addEventListener("click", function(){
    //window.print();
    coll[0].click();
    toggleText(1)
    toggleText(3)
    toggleText(5)
    toggleText(7)
    html2canvas(document.querySelector('#main')).then((canvas) => {
        let base64image = canvas.toDataURL('image/png');
        //console.log(base64image);
        let pdf = new jsPDF('p', 'px', [1903, 3174.8]);
        pdf.addImage(base64image, 'PNG', 0, 0, 1903, 3174.8);
        pdf.save('webtylepress-two.pdf');
        
    });
    
});

function popup() {
  var popup = document.getElementById("myPopup");
  popup.classList.toggle("show");
}

function selectionne(arg) {
  // Code à exécuter lorsque l'élément <a> est cliqué
  //console.log(arg);
  //console.log(all_reports);

  $.ajax({
    type:"POST",
    url: "/all_reports",
    data: {'mode':"change","select":all_reports[arg]},
    success: function() {

      // La requête AJAX est terminée avec succès
      // Vous pouvez maintenant effectuer la redirection

      location.reload();
      //console.log("ça fonctionne")

    },
    error: function() {
      // Une erreur s'est produite lors de la requête AJAX
      // Gérer l'erreur ici si nécessaire.
      alert("Error server side")
    }
  });
}

var select_rep = document.querySelector('#select_report');
var dropdown = document.querySelector('.dropdown-content');

// Ajouter un écouteur d'événement au bouton
select_rep.addEventListener('click', function() {


  $.ajax({
    type:"POST",
    url: "/all_reports",
    data: {'mode':"recup","select":''},
    success: function(data) {

      // La requête AJAX est terminée avec succès
      // Vous pouvez maintenant effectuer la redirection

      all_reports = data.reports;
      var reports = '';
      //console.log(all_reports)



      for (var i in all_reports){
        
        reports += `<a onclick='selectionne(${i})' class="reports">${all_reports[i]}</a>`;
        reports += `<div class="line"></div>`;

      }

      const select_report = document.querySelector('.dropdown-content');
      select_report.innerHTML = reports;
      dropdown.style.display = dropdown.style.display !== 'flex' ? 'flex' : 'none';


    },
    error: function() {
      // Une erreur s'est produite lors de la requête AJAX
      // Gérer l'erreur ici si nécessaire.
      alert("Error server side")
    }
  });

});


// Bouton rapport détaillé

for (i = 0; i < coll.length; i++) {
    coll[i].addEventListener("click", function() {    
      this.classList.toggle("active");
      var content = this.nextElementSibling;
      if (content.style.maxHeight) {
        content.style.maxHeight = null;
        this.textContent = "Afficher le rapport détaillé"; // Changer le texte lorsqu'il est réduit
    } else {
      content.style.maxHeight = content.scrollHeight + "px";
      this.textContent = "Masquer le rapport détaillé"; // Changer le texte lorsqu'il est déroulé
    }
  });
}


// Lancement des boutons impact et contres mesures pour afficher text

toggleText(1)
toggleText(3)
toggleText(5)
toggleText(7)

