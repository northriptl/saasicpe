#!/bin/bash

#By: Tyler Northrip
#This script configures ubuntu for optimal security for cyber patriots. Run using sudo
#DO NOT RUN AS ROOT!! USE SUDO

Version="v0.4 alpha"
UserName=$(whoami)
LogDay=$(date '+%Y-%m-%d')
LogTime=$(date '+%Y-%m-%d %H:%M:%S')
LogFile=/var/log/saasi_$LogDay.log

#DO NOT TOUCH THIS CODE
#CONTAINS MAGIC
greeter(){  
	read -d '' help <<- EOF
	. _____                    _____ _____ 
	 / ____|  /\\\        /\\\    / ____|_   _|
	 |(___   /  \\\      /  \\\  | (___   | |  
	 \\\___ \\\ / /\\\ \\\    / /\\\ \\\  \\\___ \\\  | |  
	 ____) / ____ \\\  / ____ \\\ ____) |_| |_ 
	|_____/_/    \\\_\\\/_/    \\\_\\\_____/|_____|
	"Script Aimed At Securing Installs"
	"Cyber Patriot Edition"

	Dev: Tyler Northrip
	Version: 0.4                   
	EOF

	echo "$help" 
}

sysctl_fixes(){
    echo "$LogTime uss: [$UserName] 1. Configure sysctl"

	#Kernel network security settings
	mv /etc/sysctl.conf /etc/sysctl.conf.old
	cp ./sysctl.conf /etc/sysctl.conf

	# Run these commands to ensure you receive credit    
	sysctl -p  #Loads all your changes from the file
	sysctl --system  #Load settings from all system configuration files.

	#sh -c 'printf "kernel.kptr_restrict=1\nkernel.yama.ptrace_scope=1\nvm.mmap_min_addr=65536" > /etc/sysctl.conf'
	#sh -c 'printf "net.ipv4.icmp_echo_ignore_broadcasts=1\nnet.ipv4.icmp_ignore_bogus_error_responses=1\nnet.ipv4.icmp_echo_ignore_all=0" > /etc/sysctl.conf'
} #End sysctl

remove_guest(){
    echo "$LogTime uss: [$UserName] 2. Remove guest account" 
	#Remove the guest user by editing lightdm
	sh -c 'printf "[SeatDefaults]\nallow-guest=false\n" > /etc/lightdm/lightdm.conf.d/50-no-guest.conf'
} #End remove_guest


firewall(){
    echo "$LogTime uss: [$UserName] 3. Configure ufw firewall"     
    
	#Reset the ufw config
	ufw --force reset

	ufw status verbose
	
	ufw logging on
	ufw loggin high
	
	ufw default deny incoming
	ufw default allow outgoing
				
	#Reload the firewall
	ufw disable
	ufw enable

} #End Firewall

packages(){
    echo "$LogTime uss: [$UserName] 4. Remove packages"

	apt remove vino yelp gcc g++ cheese thunderbird cups rsync curl libreoffice-common  -y
	apt remove telnet openvpn cups aisleriot gnome-mahjongg gnome-mines gnome-sudoku endless-sky -y
	apt remove netcat-openbsd tcpdump transission-common netcat nc ettercap hunt dsniff -y
	apt remove postgress apache2 xinetd snmp rpcbind nginx mysql bind9 dovecot thunderbird -y
	apt autoremove -y
	apt autoclean -y

} #End packages

secure_fstab(){
	echo "$LogTime uss: [$UserName] Check if shared memory is secured" >> $LogFile          
    # Make sure fstab does not already contain a tmpfs reference
    fstab=$(grep -c "tmpfs" /etc/fstab)
    if [ ! "$fstab" -eq "0" ] 
    	then
        	echo "$LogTime uss: [$UserName] fstab already contains a tmpfs partition." >> $LogFile
        fi
     if [ "$fstab" -eq "0" ]
        then
             echo "$LogTime uss: [$UserName] fstab being updated to secure shared memory" >> $LogFile
             sudo echo "# $TFCName Script Entry - Secure Shared Memory - $LogTime" >> /etc/fstab
             sudo echo "tmpfs     /dev/shm     tmpfs     defaults,noexec,nosuid     0     0" >> /etc/fstab
             echo "$LogTime uss: [$UserName] Shared memory secured. Reboot required" >> $LogFile
     	fi
  		
} #End secure_fstab

audit_logs(){
	apt-get install auditd -y
	auditctl -e 1
	mv /etc/audit/audit.rules  /etc/audit/audit.rules.old
	cp ./audit.rules /etc/audit/audit.rules

} # end auditlogs


ssh_secure(){
	echo "$LogTime uss: [$UserName] Replace old ssh file with configurations" >> $LogFile    
	#backup old file. the config is left aligned incase a tab or something will break the config
	cp /etc/ssh/sshd_config /etc/ssh/sshd_config_old
	
	#add: AllowUsers user1 user2 user3
	#add: AllowGroups group1 group2 group3
	
	cp ./sshd_config /etc/ssh/sshd_config

	service ssh restart
	
} #end ssh config

password_policy(){

	apt-get install libpam-cracklib -y

	echo "difok=5 minlen=14 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minclass=1 maxrepeat=1 maxclassrepeat=1 gecoscheck=1" >> /etc/security/pwquality.conf

	mv /etc/pam.d/common-password /etc/pam.d/common-password-old
	
	cp ./common-password /etc/pam.d/common-password  

} # end password_policy

something(){
	echo something
} #end something


gui_plus(){
    response=$(zenity --list --checklist --title="SAASI $Version" --column=Boxes --column=Selections --text="Select the security fixes you want" --width 480 --height 550 \
    TRUE " 1. Apply sysctl changes" \
    TRUE " 2. Remove guest account" \
    TRUE " 3. UFW firewall config" \
    TRUE " 4. Uninstall packages" \
    TRUE " 5. Secure shared memory" \
    TRUE " 6. Enable auditing" \
    TRUE " 7. Secure SSH" \
    TRUE " 8. Password policy" \
    TRUE " 9. host.conf" \
    TRUE "10. Secure Samba" \
    --separator=':')

    if [ -z "$response" ] ; then
       echo "No selection"
       exit 1
    fi

    if [ ! "$response" = "" ] 
      then
        echo "$LogTime [$UserName] * SAASI $Version - Install Log Started" >> $LogFile
        
        option=$(echo $response | grep -c "1.")
            if [ "$option" -eq "1" ]  
                then
                    sysctl_fixes >> $LogFile
                fi
                        
        option=$(echo $response | grep -c "2.")
            if [ "$option" -eq "1" ]  
                then
                    remove_guest >> $LogFile
                fi
            
        
        option=$(echo $response | grep -c "3.")
            if [ "$option" -eq "1" ]  
                then
                    firewall >> $LogFile
                fi
                    
            
        option=$(echo $response | grep -c "4.")
            if [ "$option" -eq "1" ]  
                then
                    packages >> $LogFile
                fi
            
            
        option=$(echo $response | grep -c "5.")
            if [ "$option" -eq "1" ]  
                then
                    secure_fstab
                fi
            
        
        option=$(echo $response | grep -c "6.")
            if [ "$option" -eq "1" ]  
                then
                    audit_logs >> $LogFile
                fi
            
            
        option=$(echo $response | grep -c "7.")
            if [ "$option" -eq "1" ]  
                then
                    ssh_secure >> $LogFile
                fi
                
        option=$(echo $response | grep -c "8.")
	    	if [ "$option" -eq "1"]
	    		then
		    		password_policy >> $LogFile
            	fi
            	
		option=$(echo $response | grep -c "9.")
            if [ "$option" -eq "1" ]  
                then
                    hosts_secure >> $LogFile
                fi
                
        option=$(echo $response | grep -c "10.")
	    	if [ "$option" -eq "1"]
	    		then
		    		something >> $LogFile
            	fi

        #End option chain    
        fi
      
    echo "$LogTime [$UserName] * SAASI $Version - Install Log Ended" >> $LogFile
} #End gui_plus

# Check for root priviliges
if [[ $EUID -ne 0 ]]; then
   printf "Please run as root:\nsudo bash %s\n" "${0}"
   exit 1
fi

terminal_only(){
	greeter
	
	#Main functions
	printf "\nThe program will now do general security fixes\n"
	printf "Press enter to continue"
	read continue
	echo "$LogTime [$UserName] * SAASI $Version - Install Log Started" >> $LogFile
	sysctl_fixes >> $LogFile
	firewall >> $LogFile
	remove_guest >> $LogFile
	
	printf "\n"
	
	#Ask to do firewall test
	while true 
		do
    		read -p "Do you wish to perform a simple firewall test? y/n: " yn
    		case $yn in
        		[Yy]* ) printf "\n"; firewall_test; break;;
        		[Nn]* ) break;;
        		* ) echo "Please answer yes or no.";;
    		esac
	done
	
	printf "\n"
	#Ask to remove packages
	while true 
		do
    		read -p "Do you wish to remove unneeded/dangerous packages? y/n: " yn
    		case $yn in
        		[Yy]* ) packages >> $LogFile; break;;
        		[Nn]* ) break;;
        		* ) echo "Please answer yes or no.";;
    		esac
	done
	
	printf "\n"
	#Ask to install macchanger
	while true 
		do
    		read -p "Would you like to install macchanger (recommended)? y/n: " yn
    		case $yn in
        		[Yy]* ) printf "\n"; mac_fix >> $LogFile; break;;
        		[Nn]* ) break;;
        		* ) echo "Please answer yes or no.";;
    		esac
	done
	
	printf "\n"
	#Ask to install macchanger
	while true 
		do
    		read -p "Would you like to disable all usb ports (recommended only for VM)? y/n: " yn
    		case $yn in
        		[Yy]* ) printf "\n"; usb_disable >> $LogFile; break;;
        		[Nn]* ) break;;
        		* ) echo "Please answer yes or no.";;
    		esac
	done
	
	printf "\n"
	#Ask to install macchanger
	while true 
		do
    		read -p "Would you like to disable firewire? y/n: " yn
    		case $yn in
        		[Yy]* ) printf "\n"; firewire_disable >> $LogFile; break;;
        		[Nn]* ) break;;
        		* ) echo "Please answer yes or no.";;
    		esac
	done
	
	while true 
		do
    		read -p "Would you like to install rkhunter? y/n: " yn
    		case $yn in
        		[Yy]* ) printf "\n"; install_rkhunter >> $LogFile; break;;
        		[Nn]* ) break;;
        		* ) echo "Please answer yes or no.";;
    		esac
	done
	
	while true 
		do
    		read -p "Would you like to secure shared memory (fstab)? y/n: " yn
    		case $yn in
        		[Yy]* ) printf "\n"; secure_fstab >> $LogFile; break;;
        		[Nn]* ) break;;
        		* ) echo "Please answer yes or no.";;
    		esac
	done
	
	echo "$LogTime [$UserName] * SAASI $Version - Install Log Ended" >> $LogFile
	printf "\nScript exiting\nIt is strongly recommended to reboot after running this script\n"
	
} #End terminal_only



while test $# -gt 0; do
        case "$1" in
                -h|--help)
                        echo "SAASI - Script Aimed At Securing Installs"
                        echo " "
                        echo "usage:"
                        echo "-h, --help                show brief help"
                        echo "-t, --terminal            runs text only"
						echo "-g, --gui                 runs with gui"
                        exit 0
                        ;;
                -t|--terminal)
                        shift
                        terminal_only    
                        shift
                        ;;
                -g|--gui)
                        shift
                        gui_plus   
                        shift
                        ;;
                *)
                        echo "SAASI - Script Aimed At Securing Installs"
                        echo " "
                        echo "usage:"
                        echo "-h, --help                show brief help"
                        echo "-t, --terminal            runs text only"
						echo "-g, --gui                 runs with gui"
                        exit 0
                        ;;
        esac
done

