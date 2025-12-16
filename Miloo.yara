rule XWorm_Campaign_Complete {
    meta:
        description = "Detecta SVG malicioso, payloads comprimidos y archivos .olg cifrados de la campana XWorm v7.0 (versión mejorada diciembre 2025)"
        author = "Angel Gil & Jorge Gonzalez + actualización comunitaria"
        date = "2025-12-15"
        campaign = "Suplantacion Fiscalia Colombia"
        malware_family = "XWorm v7.0 + HijackLoader"
        severity = "critical"
    strings:
        $xml_header = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" ascii
        $svg_tag = "<svg" ascii
        $atob = "atob(" ascii
        $createObjectURL = "createObjectURL" ascii
        $new_blob = "new Blob" ascii
        $b64_1 = "fgs7zJIfOUaTNehyRnsKcg==" ascii
        $b64_2 = "CEHTKyf1zkCMbzG1EJHzQw==" ascii
        $joined = "joined" ascii
        $frags = "frags" ascii
        $var_hexbase64 = /var\s+[a-zA-Z0-9]{4,20}\s*=\s*['"][A-Za-z0-9+\/=]{400,}['"]/ ascii
        $sig_prefix = "FISCALIA_JUDICIALPAYLOAD" ascii
        $sig_regex = /FISCALIAJUDICIALPAYLOAD[0-9]{10,13}[0-9a-f]{4,16}/ ascii
        $sig_hex = { 46 49 53 43 41 4C 49 41 5F 4A 55 44 49 43 49 41 4C 5F 50 41 59 4C 4F 41 44 5F }
        $magic_7z = { 37 7A BC AF 27 1C }
        $heur_lh = "-lh0-" ascii
        $png_iend = { 00 00 00 00 49 45 4E 44 AE 42 60 82 }
        $high_entropy_marker1 = { 8E [1-4] 71 [1-4] A0 }
        $high_entropy_marker2 = { A2 [1-4] 8E [1-4] 71 }
        $iend = { 49 45 4E 44 AE 42 60 82 }
        $clsid     = { 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

        $exe_name = {
            30 00 30 00 31 00 5F 00
            44 00 45 00 4D 00 41 00 4E 00 44 00 41 00 20 00
            4A 00 55 00 5A 00 47 00 41 00 44 00 4F 00 20 00
            50 00 45 00 4E 00 41 00 4C 00 20 00
            44 00 45 00 20 00
            42 00 4F 00 47 00 4F 00 54 00 41 00
            2E 00 65 00 78 00 65 00
        }

        $ctx1 = {
            43 00 4F 00 4E 00 54 00 52 00 4F 00 4C 00 20 00
            44 00 45 00 20 00
            47 00 41 00 52 00 41 00 4E 00 54 00 49 00 41 00 53 00
        }

        $ctx2 = {
            45 00 6E 00 76 00 69 00 6F 00 20 00
            64 00 65 00 20 00
            72 00 65 00 73 00 75 00 6D 00 65 00 6E 00 20 00
            64 00 65 00 20 00
            61 00 63 00 74 00 75 00 61 00 63 00 69 00 6F 00 6E 00 65 00 73 00
        }

        $xml  = "<?xml version=" wide
        $task = "<Task version=\"1.1\"" wide
        $ns   = "schemas.microsoft.com/windows/2004/02/mit/task" wide

        $calendar = "<CalendarTrigger>" wide
        $repeat   = "<Repetition>" wide
        $interval = "<Interval>PT" wide
        $minutes  = "M</Interval>" wide

        $exec     = "<Exec>" wide
        $command  = "<Command>" wide

        $runlevel = "<RunLevel>HighestAvailable</RunLevel>" wide

        $com      = "<ComHandler>" wide
        $maint    = "<MaintenanceSettings>" wide

condition:
        (
            filesize > 5000 and filesize < 20000000 and
            $xml_header and $svg_tag and
            $var_hexbase64 and
            ( $atob or $createObjectURL or $new_blob ) and
            ( $joined or $frags or $b64_1 or $b64_2 )
        )
        or
        (
            filesize > 20000 and
            ( $magic_7z at 0 or $heur_lh ) and
            ( $sig_regex or $sig_prefix in (filesize - 32768 .. filesize - 1) or $sig_hex in (filesize - 32768 .. filesize - 1) )
        )
        or
        (
            uint32(0) != 0x474E5089 and uint16(0) != 0x5A4D and
            filesize > 500000 and filesize < 3000000 and
            $png_iend at (filesize - 12) and
            (#high_entropy_marker1 > 100 or #high_entropy_marker2 > 100)
        )
        or
        (
            uint32(0) != 0x474E5089 and uint32(0) != 0x46445025 and
            uint16(0) != 0x5A4D and uint16(0) != 0x4B50 and
            uint32(0) != 0x04034B50 and uint32(0) != 0x21726152 and
            filesize > 500000 and filesize < 5000000 and
            $iend in (filesize - 20 .. filesize)
        )
        or 
        (
        uint32(0) == 0x0000004C and
        filesize < 80KB and
        $clsid and
        $exe_name and
        $ctx1 and
        $ctx2
        )
        or
        (
        uint16(0) == 0xFEFF and
        all of ($xml,$task,$ns) and
        all of ($calendar,$repeat,$interval,$minutes) and
        all of ($exec,$command) and
        $runlevel and
        not any of ($com,$maint)
        )
}






