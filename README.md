# Website Audit - Security Audit Web Server

## Overview

This project is designed to serve as a web server that conducts security audits and generates detailed reports. The web server is powered by Python and is intended to enhance your ability to assess the security of websites.

## Installation and Setup

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/1e0nn/website_audit.git ~/
    ```

2. **Run Prerequisites Script:**
    - Execute the following command with elevated privileges to set up necessary dependencies:
        ```bash
        sudo ~/website_audit/prerequisites.sh
        ```

3. **Start the Web Server:**
    - Run the web server using the following command:
        ```bash
        python3.9 ~/website_audit/www/CyberLab_Web_Server.py
        ```


 ## Configuration

 - **Adjust Sound File Path:**
   - Modify the `SOUND_FILE` variable to change the sound alert file path.

 - **Set Photo Folder:**
   - Modify the `PHOTO_FOLDER` variable to set the folder for captured photos.

 - **Customize Capture Threshold:**
   - Customize the `CAPTURE_COUNT_THRESHOLD` to determine how many times the keyboard + mouse should be triggered to lock the screen (default = 4).

 - **Set Quit Key:**
   - Modify the `quit_program_key` variable to set the key to quit the program (default = page_up).

 ## Disclaimer

 This script is intended for ethical purposes only. Use it responsibly, and ensure you have permission before auditing others website.

 ## Author

 Leon

Feel free to modify the script and adapt it to your preferences.
