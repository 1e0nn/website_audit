#!/bin/bash

# Fonction pour vérifier et installer un programme
check_and_install() {
    program=$1
    package_name=$2
    echo "Vérification de $program..."
    if ! dpkg-query -W -f='${Status}' "$package_name" 2>/dev/null | grep -q "install ok installed"; then
        echo "$program n'est pas installé. Installation en cours..."
        sudo apt install "$package_name" -y
        if [ $? -eq 0 ]; then
            echo "Installation de $program terminée avec succès."
        else
            echo "Erreur lors de l'installation de $program."
            exit 1
        fi
    else
        echo "$program est déjà installé."
    fi
    echo
}

# Fonction pour vérifier et installer un paquet via pip3
check_and_install_pip3() {
    program=$1
    package_name=$2
    echo "Vérification de $program..."
    if ! pip3 show "$package_name" >/dev/null 2>&1; then
        echo "$program n'est pas installé. Installation en cours..."
        sudo pip3 install "$package_name"
        if [ $? -eq 0 ]; then
            echo "Installation de $program terminée avec succès."
        else
            echo "Erreur lors de l'installation de $program."
            exit 1
        fi
    else
        echo "$program est déjà installé."
    fi
    echo
}


# Fonction pour vérifier et cloner un repository Git
check_and_clone() {
    repo_name=$1
    repo_url=$2
    target_dir=$3
    echo "Vérification de $repo_name..."
    if [ ! -d "$target_dir" ]; then
        echo "$repo_name n'est pas présent. Clonage en cours..."
        git clone $repo_url $target_dir
        if [ $? -eq 0 ]; then
            echo "Clonage de $repo_name terminé avec succès."
        else
            echo "Erreur lors du clonage de $repo_name."
            exit 1
        fi
    else
        echo "$repo_name est déjà présent."
    fi
    echo
}

# Vérification et installation des prérequis
check_and_install "python3" "python3"
check_and_install "pip3" "python3-pip"
pip3_packages=("flask" "validators" "wapiti3")
for package in "${pip3_packages[@]}"; do
    check_and_install_pip3 "$package" "$package"
done


# Vérification et installation des outils
check_and_install "seclists" "seclists"
check_and_install "cmseek" "cmseek"
check_and_install "nikto" "nikto"
check_and_install "nmap" "nmap"
check_and_install "gobuster" "gobuster"
check_and_install "whois" "whois"

# Clonage des repository
check_and_clone "Repository Nmap vulscan" "https://github.com/scipag/vulscan" /usr/share/nmap/scripts/vulscan

echo "Toutes les installations ont été effectuées avec succès."

echo "Veuillez lancer cette commande afin de l'ancer l'application d'audit:  python3 ~/website_audit/www/CyberLab_Web_Server.py"
