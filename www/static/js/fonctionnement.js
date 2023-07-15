

// Récupérez les ID nécessaires
const modeSelect = document.getElementById("mode_select");
const lentLink = document.getElementById("lent");
const rapideLink = document.getElementById("rapide");
const executeReportInput = document.getElementById("execute_report");
var mainBody = document.getElementById("page_principale");
var loadingBody = document.getElementById("page-de-chargement");

// PARTIE MODE LENT ET RAPIDE -------------------------------

// Ajoutez des écouteurs d'événements click aux liens
lentLink.addEventListener("click", function() {
  modeSelectionne = "lent";
  modeSelect.innerText = `Mode ${modeSelectionne} sélectionné`;
  modeSelect.style.color = "#dc0909";
});

rapideLink.addEventListener("click", function() {
  modeSelectionne = "rapide";
  modeSelect.innerText = `Mode ${modeSelectionne} sélectionné`;
  modeSelect.style.color = "#1c8701";
});

// --------------------------------------------------------------


// PARTIE AFFICHAGE URL ------------------------------------

// Fonction pour gérer le clic sur les boutons
function handleClick() {
  document.getElementById("boutons").style.display = "none"; // Masquer le bouton 2
  document.getElementById("url").classList.remove("hidden"); // Afficher la zone de texte
  document.getElementById("mode_select").classList.remove("hidden"); // Afficher la zone de texte
}

// Ajouter le gestionnaire de clic aux deux boutons
document.getElementById("rapide").addEventListener("click", handleClick);
document.getElementById("lent").addEventListener("click", handleClick);

// --------------------------------------------------------------

// quand le bouton lancer audit est appuyer les données url vont être vérifier si bon  requete retour (code 201,200... )
// la fonction lancer rapport se lance


function myfunction_clickevent(){

  let url = document.getElementById("execute_report").value;
  var audio = document.getElementById("audio");


  $.ajax({
    type:"POST",
    url: "/verif",
    data: {'mode':modeSelectionne,'url':url},
    success: function() {

      // La requête AJAX est terminée avec succès
      // Vous pouvez maintenant effectuer la redirection
      mainBody.style.display = "none";
      loadingBody.style.display = "block";
      audio.play();
      lance_rapport();

    },
    error: function() {
      // Une erreur s'est produite lors de la requête AJAX
      // Gérer l'erreur ici si nécessaire.
      alert("veuillez saisir un URL correct et vérifier que le site est bien accesible")
    }
  });

}

// cette partie permet de lancer le rapport et de récupérer des infos ou la page du rapport

function lance_rapport(){

  let url = document.getElementById("execute_report").value;


  $.ajax({
    type:"POST",
    url: "/lance_rapport",
    data: {'mode':modeSelectionne,'url':url},
    success: function(data) {

      // La requête AJAX est terminée avec succès
      // Vous pouvez maintenant effectuer la redirection
      location.href = data.rapport;

    },
    error: function() {
      // Une erreur s'est produite lors de la requête AJAX
      // Gérer l'erreur ici si nécessaire.
      alert("Error server side")
    }
  });

}

// bouton enter pressé envoie de l'url
//Attachez un gestionnaire d'événements à l'événement "keydown" (appui d'une touche)
executeReportInput.addEventListener("keydown", function(event) {
  // Vérifiez si la touche Entrée est pressée (code 13)
  if (event.keyCode === 13) {
    event.preventDefault(); // Empêche le comportement par défaut de la touche Entrée (soumission du formulaire)

    // Appelez la fonction myfunction_clickevent()
    myfunction_clickevent();
  }
});

