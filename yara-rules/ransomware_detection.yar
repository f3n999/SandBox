/*
    YARA Rules - Détection Ransomware
    Oteria B3 - Défense Anti-Ransomware Santé
    
    Déployées dans CAPE Sandbox pour enrichir l'analyse dynamique.
*/

rule Ransomware_CryptoAPI_Usage {
    meta:
        description = "Détecte l'utilisation de CryptoAPI typique des ransomwares"
        author = "Oteria B3"
        severity = "critical"
        category = "ransomware"
    
    strings:
        $crypto1 = "CryptEncrypt" ascii
        $crypto2 = "CryptGenKey" ascii
        $crypto3 = "CryptDeriveKey" ascii
        $crypto4 = "CryptAcquireContext" ascii
        $bcrypt1 = "BCryptEncrypt" ascii
        $bcrypt2 = "BCryptGenerateSymmetricKey" ascii
        
        $file1 = "CreateFileW" ascii
        $file2 = "WriteFile" ascii
        $file3 = "MoveFileEx" ascii
        
        $ransom1 = "your files" nocase ascii wide
        $ransom2 = "encrypted" nocase ascii wide
        $ransom3 = "bitcoin" nocase ascii wide
        $ransom4 = "decrypt" nocase ascii wide
        $ransom5 = "payment" nocase ascii wide
    
    condition:
        uint16(0) == 0x5A4D and  // PE file
        (2 of ($crypto*) or 1 of ($bcrypt*)) and
        (1 of ($file*)) and
        (1 of ($ransom*))
}

rule Ransomware_Shadow_Copy_Deletion {
    meta:
        description = "Détecte la suppression de shadow copies (comportement ransomware)"
        author = "Oteria B3"
        severity = "critical"
        category = "ransomware"
    
    strings:
        $vss1 = "vssadmin" nocase ascii wide
        $vss2 = "delete shadows" nocase ascii wide
        $vss3 = "wmic shadowcopy delete" nocase ascii wide
        $vss4 = "bcdedit /set" nocase ascii wide
        $vss5 = "recoveryenabled no" nocase ascii wide
        $vss6 = "wbadmin delete catalog" nocase ascii wide
    
    condition:
        2 of them
}

rule Ransomware_File_Encryption_Pattern {
    meta:
        description = "Pattern de renommage/chiffrement de fichiers en masse"
        author = "Oteria B3"
        severity = "high"
        category = "ransomware"
    
    strings:
        $ext1 = ".locked" ascii wide
        $ext2 = ".encrypted" ascii wide
        $ext3 = ".crypt" ascii wide
        $ext4 = ".enc" ascii wide
        $ext5 = ".lockbit" ascii wide
        $ext6 = ".conti" ascii wide
        $ext7 = ".hive" ascii wide
        $ext8 = ".blackcat" ascii wide
        $ext9 = ".royal" ascii wide
        $ext10 = ".play" ascii wide
        
        $note1 = "README" ascii wide
        $note2 = "DECRYPT" ascii wide
        $note3 = "RESTORE" ascii wide
        $note4 = "HOW_TO" ascii wide
        $note5 = "RECOVER" ascii wide
    
    condition:
        (2 of ($ext*)) and (1 of ($note*))
}

rule Ransomware_Process_Injection {
    meta:
        description = "Injection de processus typique des ransomwares avancés"
        author = "Oteria B3"
        severity = "high"
        category = "evasion"
    
    strings:
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtUnmapViewOfSection" ascii
        $api5 = "NtWriteVirtualMemory" ascii
        $api6 = "QueueUserAPC" ascii
    
    condition:
        uint16(0) == 0x5A4D and
        3 of them
}

rule Ransomware_Service_Tampering {
    meta:
        description = "Arrêt de services de sécurité / backup"
        author = "Oteria B3"
        severity = "high"
        category = "ransomware"
    
    strings:
        $svc1 = "net stop" nocase ascii wide
        $svc2 = "sc config" nocase ascii wide
        $svc3 = "taskkill" nocase ascii wide
        
        $target1 = "vss" nocase ascii wide
        $target2 = "sql" nocase ascii wide
        $target3 = "backup" nocase ascii wide
        $target4 = "exchange" nocase ascii wide
        $target5 = "sophos" nocase ascii wide
        $target6 = "symantec" nocase ascii wide
        $target7 = "defender" nocase ascii wide
        $target8 = "malware" nocase ascii wide
    
    condition:
        (1 of ($svc*)) and (2 of ($target*))
}

rule Ransomware_Macro_Dropper {
    meta:
        description = "Document Office avec macro suspecte (dropper potentiel)"
        author = "Oteria B3"
        severity = "medium"
        category = "dropper"
    
    strings:
        $ole1 = {D0 CF 11 E0 A1 B1 1A E1}  // OLE header
        $macro1 = "AutoOpen" ascii
        $macro2 = "Auto_Open" ascii
        $macro3 = "Document_Open" ascii
        $macro4 = "Workbook_Open" ascii
        
        $shell1 = "Shell" ascii
        $shell2 = "WScript" ascii
        $shell3 = "PowerShell" nocase ascii
        $shell4 = "cmd.exe" nocase ascii
        $shell5 = "CreateObject" ascii
        
        $download1 = "URLDownloadToFile" ascii
        $download2 = "XMLHTTP" ascii
        $download3 = "Invoke-WebRequest" nocase ascii
    
    condition:
        $ole1 at 0 and
        (1 of ($macro*)) and
        (1 of ($shell*)) and
        (1 of ($download*))
}

rule Ransomware_LNK_Dropper {
    meta:
        description = "Fichier LNK malveillant (vecteur d'infection courant 2024)"
        author = "Oteria B3"
        severity = "high"
        category = "dropper"
    
    strings:
        $lnk = {4C 00 00 00 01 14 02 00}  // LNK header
        $ps1 = "powershell" nocase ascii wide
        $ps2 = "-enc" nocase ascii wide
        $ps3 = "-nop" nocase ascii wide
        $ps4 = "bypass" nocase ascii wide
        $cmd1 = "cmd /c" nocase ascii wide
        $cmd2 = "mshta" nocase ascii wide
    
    condition:
        $lnk at 0 and
        (2 of ($ps*) or 1 of ($cmd*))
}
