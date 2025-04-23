$numberOfIPs = Read-Host "Enter the number of IP addresses you want to scan in a batch"

Write-Host "You have chosen to scan $numberOfIPs IP addresses in a batch."

$ipAddresses = @()

for ($i = 1; $i -le $numberOfIPs; $i++) {
    $ipAddress = Read-Host "Enter IP address $i"
    $ipAddresses += $ipAddress
}

if ($ipAddresses.Count -eq $numberOfIPs) {
    Write-Host "You have entered the correct number of IP addresses."
} else {
    Write-Host "The number of IP addresses entered does not match the expected count."
}

Write-Host "The IP addresses you entered are:"
$ipAddresses | ForEach-Object { Write-Host $_ }   
foreach ($ip in $ipAddresses) {
    Write-Host "Starting All ports scan for IP: $ip with the command: 'nmap $ip -sC -sV -v1 -p- -Pn -oN $ip-all-SYN.txt'." -ForegroundColor Green
    Write-Host "`nPlease wait while the scanning is going on!`n" -ForegroundColor Blue
    cmd.exe /c "nmap $ip -sC -sV -v1 -Pn -oA $ip-all-SYN"
    
    $folderName = "$ip-scan-results"
    if (-Not (Test-Path -Path $folderName)) {
        New-Item -ItemType Directory -Path $folderName
    }

    Move-Item -Path "$ip-all-SYN.xml" -Destination "$folderName/$ip-all-SYN.xml"
    Move-Item -Path "$ip-all-SYN.nmap" -Destination "$folderName/$ip-all-SYN.nmap"
    Move-Item -Path "$ip-all-SYN.gnmap" -Destination "$folderName/$ip-all-SYN.gnmap"

    $x = Get-ChildItem -Path "$folderName/$ip-all-SYN.xml"
    $x = [xml]$xml = Get-Content $x
    $x = $x.selectnodes("//host")
    $list = @()
    $x | foreach {$_.address | foreach { if ($_.addrtype -like "ipv4") {$hostip = new-object psobject ;
    $hostip | add-member -membertype NoteProperty -name ip -Value $_.addr }}
    $_.ports | foreach { $_.port | foreach {
        $val = new-object psobject ;
        $val | add-member -membertype NoteProperty -name Host -Value $hostip.ip
        $val | add-member -membertype NoteProperty -name Port -Value $_.portid
        $val | add-member -membertype NoteProperty -name State -Value $_.state.state
        $val | add-member -membertype NoteProperty -name Service -Value $_.service.name
        if ($val.proto -ne "") {$list += $val}
    }}}
    $y = $list | Where-Object {$_.state -ne 'closed' -and $_.state -ne 'filtered'} | Select-Object * -ExcludeProperty 'State'
    $addr = $y.host | Get-Unique

    $sshPorts = $y | Where-Object { $_.Service -like '*ssh*' } | Select-Object -ExpandProperty Port
    if ($sshPorts) {
        Write-Host "`The ports used by SSH are: $sshPorts, starting SSH NSE scan`n" -ForegroundColor Blue
        foreach ($sshPort in $sshPorts) {
            nmap -Pn -v -p $sshPort --script ssh2-enum-algos,ssh-auth-methods $ip -oN "$folderName/$ip-ssh2-enum-$sshPort.txt"
        }
    } else {
        Write-Host "`SSH service not found."
    }
    $HTTPPorts = $y | Where-Object { $_.Service -like '*http*' -or $_.Service -like '*https*' -or $_.Service -like '*ssl*' } | Select-Object -ExpandProperty Port
    if ($HTTPPorts) {
        Write-Host "`The ports used by HTTP/HTTPS are: $HTTPPorts, starting HTTP NSE scan`n" -ForegroundColor Green
        foreach ($HTTPPort in $HTTPPorts) {
            nmap -Pn -v -p $HTTPPort --script ssl-enum-ciphers,ssl-cert $ip -oN "$folderName/$ip-ssl-ciphers-$HTTPPort.txt"
        }
    } else {
        Write-Host "`HTTP service not found."
    }
    $FTPPorts = $y | Where-Object { $_.Service -like '*ftp*' } | Select-Object -ExpandProperty Port
    if ($FTPPorts) {
        Write-Host "`The ports used by FTP are: $FTPPorts, starting FTP NSE scan`n" -ForegroundColor Blue
        foreach ($FTPPort in $FTPPorts) {
            nmap -Pn -v -p $FTPPort -sC -sV --script ftp-anon,ftp-bounce,ftp-syst $ip -oN "$folderName/$ip-ftp-enum-$FTPPort.txt"
        }
    } else {
        Write-Host "`FTP service not found."
    }
    $SMBPorts = $y | Where-Object { $_.Service -like '*smb*' -or $_.Service -like '*msrpc*' -or $_.Service -like "*netbios-ns*" -or $_.Service -like "*netbios-ssn*" -or $_.Service -like "*microsoft-ds*" } | Select-Object -ExpandProperty Port
    if ($SMBPorts) {
        Write-Host "`The ports used by SMB are: $SMBPorts, starting SMB NSE scan`n" -ForegroundColor Blue
        foreach ($SMBPort in $SMBPorts) {
            nmap -Pn -v -p $SMBPort --script 'smb-* and safe' $ip -oN "$folderName/$ip-smb-safe-$SMBPort.txt"
        }
    } else {
        Write-Host "`SMB service not found."
    }
    $RDPPorts = $y | Where-Object { $_.Service -like '*rdp*' -or $_.Service -like '*ms-wbt-server*' } | Select-Object -ExpandProperty Port
    if ($RDPPorts) {
        Write-Host "`The ports used by RDP are: $RDPPorts, starting RDP NSE scan`n" -ForegroundColor Blue
        foreach ($RDPPort in $RDPPorts) {
            nmap -Pn -v -p $RDPPort --script rdp-enum-encryption,rdp-ntlm-info $ip -oN "$folderName/$ip-rdp-enum-$RDPPort.txt"
        }
    } else {
        Write-Host "`RDP service not found."
    }
    $DNSPorts = $y | Where-Object { $_.Service -like '*dns*' } | Select-Object -ExpandProperty Port
    if ($DNSPorts) {
        Write-Host "`The ports used by DNS are: $DNSPorts, starting DNS NSE scan`n" -ForegroundColor Blue
        foreach ($DNSPort in $DNSPorts) {
            nmap -Pn -v -p $DNSPort --script 'dns* and safe' $ip -oN "$folderName/$ip-dns-enum-$DNSPort.txt"
        }
    } else {
        Write-Host "`DNS service not found."
    }
    $SMTPPorts = $y | Where-Object { $_.Service -like '*smtp*' } | Select-Object -ExpandProperty Port
    if ($SMTPPorts) {
        Write-Host "`The ports used by SMTP are: $SMTPPorts, starting SMTP NSE scan`n" -ForegroundColor Blue
        foreach ($SMTPPort in $SMTPPorts) {
            nmap -Pn -v -p $SMTPPort --script 'smtp* and safe' $ip -oN "$folderName/$ip-smtp-enum-$SMTPPort.txt"
        }
    } else {
        Write-Host "`SMTP service not found."
    }
    $NTPPorts = $y | Where-Object { $_.Service -like '*ntp*' } | Select-Object -ExpandProperty Port
    if ($NTPPorts) {
        Write-Host "`The ports used by NTP are: $NTPPorts, starting NTP NSE scan`n" -ForegroundColor Blue
        foreach ($NTPPort in $NTPPorts) {
            nmap -Pn -v -p $NTPPort --script ntp-info,ntp-monlist $ip -oN "$folderName/$ip-ntp-enum-$NTPPort.txt"
        }
    } else {
        Write-Host "`NTP service not found."
    }
    $TELNETPorts = $y | Where-Object { $_.Service -like '*telnet*' } | Select-Object -ExpandProperty Port
    if ($TELNETPorts) {
        Write-Host "`The ports used by Telnet are: $TELNETPorts, starting TELNET NSE scan`n" -ForegroundColor Blue
        foreach ($TELNETPort in $TELNETPorts) {
            nmap -Pn -v -p $TELNETPort --script 'telnet-*' $ip -oN "$folderName/$ip-telnet-enum-$TELNETPort.txt"
        }
    } else {
        Write-Host "`Telnet service not found."
    }
    $SNMPPorts = $y | Where-Object { $_.Service -like '*snmp*' } | Select-Object -ExpandProperty Port
    if ($SNMPPorts) {
        Write-Host "`The ports used by SNMP are: $SNMPPorts, starting SNMP NSE scan`n" -ForegroundColor Blue
        foreach ($SNMPPort in $SNMPPorts) {
            nmap -Pn -v -p $SNMPPort --script 'snmp* and not snmp-brute' $ip -oN "$folderName/$ip-snmp-enum-$SNMPPort.txt"
        }
    } else {
        Write-Host "`SNMP service not found."
    }

    Write-Host "`nScanning completed for IP: $ip" -ForegroundColor Yellow
    Write-Host "----------------------------------------"
}
Write-Host "`nAll IP addresses have been scanned." -ForegroundColor Green